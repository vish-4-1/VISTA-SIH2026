"""
VISTA SOC & Threat Intelligence Service
Summarizes repository datasets and supplied analysis, with MITRE ATT&CK mappings.

Evidence provenance:
  "Dataset ground-truth label"  — attackType from the repository CSV (not live ML)
  "ML Prediction"               — attackType from live model inference (predictionStatus == "success")
  "Prediction Unavailable"      — inference ran but failed
  "Insufficient Data"           — inference ran but required features were missing
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.services.posture_engine import posture_engine

ROOT_DIR = Path(__file__).resolve().parents[2]
FLOWS_JSON_PATH = ROOT_DIR / "vista-dashboard" / "src" / "data" / "realFlows.json"

# MITRE ATT&CK mappings keyed by attack class name.
# These are the documented attack classes in the VISTA repository dataset and
# the classes supported by the trained classification models.
MITRE_TECHNIQUES = {
    "PORT_SCAN": {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "severity": "Medium",
        "description": (
            "High-frequency probe packets attempting to map open ports through the IPsec tunnel."
        ),
    },
    "DOS": {
        "id": "T1499",
        "name": "Endpoint Denial of Service",
        "tactic": "Impact",
        "severity": "Critical",
        "description": (
            "Volumetric ESP flood designed to exhaust cryptoprocessor crypto SA states."
        ),
    },
    "DOS_FLOOD": {
        "id": "T1499",
        "name": "Endpoint Denial of Service",
        "tactic": "Impact",
        "severity": "Critical",
        "description": (
            "Volumetric ESP flood designed to exhaust cryptoprocessor crypto SA states."
        ),
    },
    "BRUTE_FORCE": {
        "id": "T1110",
        "name": "Brute Force Authentication",
        "tactic": "Credential Access",
        "severity": "High",
        "description": (
            "Repeated IKE_AUTH negotiation bursts attempting pre-shared key or user "
            "credential exhaustion."
        ),
    },
    "C2_BEACONING": {
        "id": "T1071.001",
        "name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "severity": "High",
        "description": (
            "Periodic low-jitter inter-arrival time encrypted pulses characteristic of C2 beacons."
        ),
    },
    "DATA_EXFILTRATION": {
        "id": "T1048",
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "severity": "Critical",
        "description": (
            "Asymmetric high-volume outbound ESP transfer to an external tunnel endpoint."
        ),
    },
}

# Labels that indicate benign/normal traffic — never mapped to threat events.
_BENIGN_LABELS = {"BENIGN", "NORMAL", "PREDICTION UNAVAILABLE", "INSUFFICIENT DATA"}


def _classify_flow_provenance(flow: Dict[str, Any], is_live: bool) -> Optional[str]:
    """
    Returns the evidence provenance string for a flow IF it represents a threat/attack,
    or None if the flow is benign, incomplete, or unclassified.

    Repository flows (is_live=False) carry ground-truth labels from the dataset CSV.
    Live PCAP flows (is_live=True) carry labels from live ML inference.
    """
    prediction_status = flow.get("predictionStatus")
    atk = str(flow.get("attackType", "")).strip().upper()

    if is_live:
        # Live PCAP flow — only include if inference succeeded and it's an attack.
        if prediction_status == "success":
            if flow.get("isAttack") == 1 or (atk and atk not in _BENIGN_LABELS):
                return "ML Prediction"
        return None

    # Repository dataset flow — has ground-truth labels from the CSV.
    # predictionStatus is absent (None) in exported repository flows.
    # These flows are labelled by the dataset authors, not by live inference.
    if prediction_status is None or prediction_status == "":
        if flow.get("isAttack") == 1 or flow.get("trafficType") == "Attack":
            if atk and atk not in _BENIGN_LABELS:
                return "Dataset ground-truth label"
        return None
    if prediction_status == "success":
        if flow.get("isAttack") == 1 or (atk and atk not in _BENIGN_LABELS):
            return "ML Prediction"
    return None


class SocService:
    def __init__(self) -> None:
        self._cached_flows: Optional[List[Dict[str, Any]]] = None

    def _get_all_flows(self) -> List[Dict[str, Any]]:
        if self._cached_flows is None:
            if FLOWS_JSON_PATH.exists():
                try:
                    self._cached_flows = json.loads(
                        FLOWS_JSON_PATH.read_text(encoding="utf-8")
                    )
                except Exception as err:
                    raise RuntimeError(
                        f"Failed to read flow records from {FLOWS_JSON_PATH}."
                    ) from err
            else:
                self._cached_flows = []
        return self._cached_flows

    def get_soc_status(
        self, custom_flows: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Summarises flow totals.

        For repository flows: attack counts come from dataset ground-truth labels.
        For live PCAP flows: attack counts come only from successful ML inference.
        Confidence is only surfaced when live inference provides it.
        """
        posture_summary = posture_engine.compute_summary_posture()
        is_live = custom_flows is not None
        flows_to_eval = custom_flows if is_live else self._get_all_flows()

        total_pkts = 0
        total_bytes = 0
        conf_sum = 0.0
        conf_count = 0
        attacks_detected = 0

        for flow in flows_to_eval:
            total_pkts += int(flow.get("packets") or 0)
            total_bytes += int(flow.get("bytes") or 0)

            provenance = _classify_flow_provenance(flow, is_live)
            if provenance is not None:
                attacks_detected += 1

            # Only accumulate live ML confidence.
            if is_live and flow.get("predictionStatus") == "success":
                confidence = flow.get("confidenceValue")
                if confidence is not None:
                    conf_sum += float(confidence)
                    conf_count += 1

        # Predicted = flows with successful live ML inference.
        predicted_count = (
            sum(1 for f in flows_to_eval if f.get("predictionStatus") == "success")
            if is_live
            else 0
        )
        insufficient_data_count = (
            sum(1 for f in flows_to_eval if f.get("predictionStatus") == "insufficient_data")
            if is_live
            else 0
        )
        unavailable_count = (
            sum(1 for f in flows_to_eval if f.get("predictionStatus") == "unavailable")
            if is_live
            else 0
        )
        # For repository data, "classified" means the flow has a ground-truth label.
        dataset_labelled = (
            0
            if is_live
            else sum(
                1 for f in flows_to_eval
                if f.get("isAttack") is not None
            )
        )
        benign_count = (
            sum(
                1 for f in flows_to_eval
                if f.get("predictionStatus") == "success"
                and (f.get("isAttack") == 0 or str(f.get("attackType", "")).strip().upper() in _BENIGN_LABELS)
            )
            if is_live
            else sum(
                1 for f in flows_to_eval
                if f.get("isAttack") == 0 or f.get("trafficType") == "Benign" or str(f.get("attackType", "")).strip().upper() in _BENIGN_LABELS
            )
        )

        return {
            "source": "Uploaded analysis" if is_live else "Repository dataset",
            "securityScore": posture_summary.get("overallScore"),
            "aiConfidence": round(conf_sum / conf_count, 1) if conf_count else None,
            "rawPacketsCount": total_pkts,
            "rawBytesCount": total_bytes,
            "threatsDetectedCount": attacks_detected,
            "totalFlows": len(flows_to_eval),
            "predictedFlows": predicted_count,
            "evaluatedFlows": predicted_count,
            "benignFlows": benign_count,
            "attackFlows": attacks_detected,
            "insufficientDataFlows": insufficient_data_count,
            "unavailableFlows": unavailable_count,
            "datasetLabelledFlows": dataset_labelled,
            "unclassifiedFlows": (
                len(flows_to_eval) - predicted_count if is_live else 0
            ),
            "postureSummary": posture_summary,
        }

    def get_threat_matrix(
        self, flows: Optional[List[Dict[str, Any]]] = None
    ) -> List[Dict[str, Any]]:
        """
        Returns threat events with MITRE ATT&CK mappings.

        Evidence provenance is clearly recorded on every returned record:
          - "Dataset ground-truth label": label from the repository CSV dataset.
          - "ML Prediction": label from live ML inference (predictionStatus == "success").

        Normal/benign flows are never included.
        Repository flows without an attack label are never included.
        Live flows without a successful inference result are never included.
        """
        is_live = flows is not None
        target_flows = flows if is_live else self._get_all_flows()

        if not target_flows:
            return []

        threat_events: List[Dict[str, Any]] = []
        event_id = 1

        for f in target_flows:
            provenance = _classify_flow_provenance(f, is_live)
            if provenance is None:
                continue

            atk = str(f.get("attackType", "")).strip().upper()
            if not atk or atk in _BENIGN_LABELS:
                continue

            # Normalise DOS_FLOOD → look up in table
            tech = MITRE_TECHNIQUES.get(atk) or MITRE_TECHNIQUES.get("DOS")
            if not tech:
                continue

            # Verification language differs by provenance.
            if provenance == "ML Prediction":
                verification = (
                    "Unverified ML prediction — not a confirmed incident"
                )
                description = (
                    f"Unverified ML model prediction mapped to {tech['name']}. "
                    "This is not a confirmed incident. " + tech["description"]
                )
            else:
                # Dataset ground-truth: these are known-labelled test/training flows.
                verification = (
                    "Repository dataset label — training/evaluation data, not live detection"
                )
                description = (
                    f"Flow labelled as {atk} in the VISTA repository dataset "
                    f"({FLOWS_JSON_PATH.name}). "
                    "This is a dataset record, not a live detection. " + tech["description"]
                )

            record: Dict[str, Any] = {
                "id": f"THR-{event_id:04d}",
                "flowId": f.get("flowId") or f.get("id"),
                "spi": f.get("spi"),
                "attackType": atk,
                "classificationSource": provenance,
                "verificationStatus": verification,
                "mitreId": tech["id"],
                "mitreName": tech["name"],
                "tactic": tech["tactic"],
                "severity": tech["severity"],
                "description": description,
                "packets": f.get("packets"),
                "bytes": f.get("bytes"),
                "source": "Uploaded analysis" if is_live else "Repository dataset",
                "modelUsed": f.get("inferenceEngine") or f.get("model_used") or "XGBoost",
            }

            # Only include network addresses for live PCAP flows (real observed data).
            if is_live:
                record["src"] = f.get("src")
                record["dst"] = f.get("dst")
                record["detectedAt"] = f.get("time")

            # Confidence: only from live ML inference.
            if provenance == "ML Prediction":
                record["confidence"] = f.get("confidence")
                record["confidenceValue"] = f.get("confidenceValue")
            else:
                record["confidence"] = None
                record["confidenceValue"] = None

            threat_events.append(record)
            event_id += 1

            if len(threat_events) >= 50:
                break

        return threat_events


soc_service = SocService()
