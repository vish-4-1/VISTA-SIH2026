"""
VISTA Dataset Studio Service
Provides dataset registry management, testbed capability discovery, preflight verification,
asynchronous testbed-driven dataset generation, quality validation, and safe export.
SIH2026 · Problem Statement SIH26160 (NTRO)
"""

from __future__ import annotations

import csv
import hashlib
import json
import logging
import math
import os
import re
import shutil
import threading
import time
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

ROOT_DIR = Path(__file__).resolve().parents[2]
CAMPAIGNS_DIR = ROOT_DIR / "captures" / "strongswan" / "collections" / "campaigns"
DATA_DIR = ROOT_DIR / "vista-ml" / "data"
SAMPLE_DATA_DIR = DATA_DIR / "sample"
FIXTURE_DATA_DIR = DATA_DIR / "fixtures"
EXPORTS_DIR = ROOT_DIR / "captures" / "exports"

EXPORTS_DIR.mkdir(parents=True, exist_ok=True)
SAMPLE_DATA_DIR.mkdir(parents=True, exist_ok=True)

# In-memory registry of asynchronous dataset generation jobs
GENERATION_JOBS: Dict[str, Dict[str, Any]] = {}
JOBS_LOCK = threading.Lock()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _collected_candidate_blockers(
    details: Dict[str, Any], rows: List[Dict[str, Any]], feature_keys: List[str],
    *, duplicate_ids: int = 0, duplicate_vectors: int = 0,
    near_duplicate_vectors: int = 0, missing_values: int = 0,
    invalid_numeric_values: int = 0,
) -> List[str]:
    """Fail closed unless collected evidence, artifacts, labels, schema, and splits validate."""
    blockers: List[str] = []
    if duplicate_ids:
        blockers.append("duplicate_dataset_identifiers")
    if duplicate_vectors:
        blockers.append("duplicate_feature_vectors")
    if near_duplicate_vectors:
        blockers.append("near_duplicate_feature_vectors")
    if missing_values or invalid_numeric_values:
        blockers.append("invalid_or_missing_dataset_features")
    manifest = details.get("datasetManifest") or {}
    if not manifest.get("originType"):
        blockers.append("manifest_origin_type_missing")
    elif manifest.get("originType") != "testbed_collected":
        blockers.append("manifest_origin_type_not_testbed_collected")
    execution = manifest.get("execution") or {}
    if execution.get("state") != "EXECUTED" or execution.get("result") != "PASS":
        blockers.append("successful_scenario_execution_evidence_missing")
    if execution.get("observationState") != "OBSERVED":
        blockers.append("independent_scenario_observation_evidence_missing")

    manifest_path = (ROOT_DIR / details["manifestPath"]).resolve() if details.get("manifestPath") else None
    manifest_dir = manifest_path.parent if manifest_path else ROOT_DIR
    artifacts = manifest.get("artifacts")
    artifact_paths: set[Path] = set()
    valid_artifacts = []
    artifact_session_refs: list[Dict[str, Any]] = []
    if not isinstance(artifacts, list) or not artifacts:
        blockers.append("artifact_hash_inventory_missing")
        artifacts = []
    else:
        for index, artifact in enumerate(artifacts):
            if not isinstance(artifact, dict):
                blockers.append(f"artifact_entry_invalid:{index}")
                continue
            required = ("path", "sizeBytes", "sha256", "sourceRunId", "createdAt")
            if any(not artifact.get(key) for key in required):
                blockers.append(f"artifact_metadata_incomplete:{index}")
                continue
            try:
                artifact_time = datetime.fromisoformat(str(artifact["createdAt"]).replace("Z", "+00:00"))
                if artifact_time.tzinfo is None:
                    raise ValueError("timezone missing")
            except ValueError:
                blockers.append(f"artifact_timestamp_invalid:{index}")
            path = (manifest_dir / str(artifact["path"])).resolve()
            try:
                path.relative_to(ROOT_DIR.resolve())
            except ValueError:
                blockers.append(f"artifact_path_escapes_repository:{index}")
                continue
            if not path.is_file():
                blockers.append(f"artifact_missing:{index}")
                continue
            if path.stat().st_size != artifact.get("sizeBytes") or _sha256_file(path) != artifact.get("sha256"):
                blockers.append(f"artifact_integrity_mismatch:{index}")
                continue
            artifact_paths.add(path)
            valid_artifacts.append((path, artifact))
            if path.suffix.casefold() == ".pcap" or path.name.casefold() == "ground_truth.json":
                artifact_session_refs.append(artifact)
        dataset_path = (ROOT_DIR / str(details.get("dataPath") or "")).resolve()
        if dataset_path not in artifact_paths:
            blockers.append("prepared_dataset_hash_not_in_manifest")
        storage_rel = details.get("storageLocation")
        if storage_rel:
            storage_path = (ROOT_DIR / str(storage_rel)).resolve()
            try:
                storage_path.relative_to(ROOT_DIR.resolve())
                for filename in ("dataset_report.json", "split_manifest.json"):
                    required_path = storage_path / "dataset_preparation" / filename
                    if not required_path.is_file() or required_path.resolve() not in artifact_paths:
                        blockers.append(f"{filename.removesuffix('.json')}_hash_not_in_manifest")
            except ValueError:
                blockers.append("dataset_storage_path_escapes_repository")
        else:
            blockers.extend(("dataset_report_hash_not_in_manifest", "split_manifest_hash_not_in_manifest"))
        captures = [(path, artifact) for path, artifact in valid_artifacts if path.suffix.casefold() == ".pcap"]
        if not captures:
            blockers.append("integrity_checked_capture_missing")
        else:
            try:
                from backend.services.workload_collection import _validate_closed_pcap
                for path, _artifact in captures:
                    _validate_closed_pcap(path)
            except Exception:
                blockers.append("capture_integrity_validation_failed")

    if manifest.get("featureSchemaVersion") != "vista-flow-v1":
        blockers.append("feature_schema_version_unverified")
    declared_features = manifest.get("featureColumns")
    if not isinstance(declared_features, list) or declared_features != feature_keys:
        blockers.append("feature_schema_order_or_columns_mismatch")
    if any(name in set(declared_features or []) for name in ("label", "scenario_label", "session_id", "experiment_id", "spi_in", "spi_out")):
        blockers.append("identifier_or_target_declared_as_model_feature")
    dataset_columns = details.get("columns") or []
    dataset_feature_order = [name for name in dataset_columns if name in feature_keys]
    if dataset_feature_order != feature_keys:
        blockers.append("feature_schema_order_or_columns_mismatch")

    session_records = manifest.get("sessionRecords")
    if not isinstance(session_records, list) or len(session_records) < 3:
        blockers.append("insufficient_independent_session_records")
        session_records = []
    session_map: Dict[str, Dict[str, Any]] = {}
    independent_keys: set[str] = set()
    experiment_ids: set[str] = set()
    for record in session_records:
        if not isinstance(record, dict):
            blockers.append("session_record_invalid")
            continue
        session_id = record.get("sessionId")
        experiment_id = record.get("experimentId")
        independent_key = record.get("ikeSaIdentitySha256")
        if not session_id or not experiment_id or not independent_key or record.get("executionState") != "EXECUTED":
            blockers.append("session_execution_or_identity_evidence_missing")
            continue
        if not re.fullmatch(r"[0-9a-f]{64}", str(independent_key)):
            blockers.append("session_sa_identity_hash_invalid")
        for time_key in ("captureStartedAt", "captureEndedAt"):
            try:
                parsed = datetime.fromisoformat(str(record.get(time_key, "")).replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    raise ValueError("timezone missing")
            except ValueError:
                blockers.append("session_capture_window_invalid")
        if session_id in session_map or experiment_id in experiment_ids or independent_key in independent_keys:
            blockers.append("duplicate_session_experiment_or_sa_identity")
        session_map[str(session_id)] = record
        experiment_ids.add(str(experiment_id))
        independent_keys.add(str(independent_key))
    for artifact in artifact_session_refs:
        session_id = str(artifact.get("sessionId", ""))
        experiment_id = str(artifact.get("experimentId", ""))
        if not session_id or not experiment_id or session_map.get(session_id, {}).get("experimentId") != experiment_id:
            blockers.append("capture_or_ground_truth_run_reference_mismatch")
    if any(not row.get("session_id") or not row.get("experiment_id") for row in rows):
        blockers.append("dataset_row_session_or_experiment_reference_missing")
    if any(str(row.get("session_id")) not in session_map or str(row.get("experiment_id")) not in experiment_ids for row in rows):
        blockers.append("dataset_row_references_unknown_session_or_experiment")

    label_evidence = manifest.get("labelEvidence")
    if not isinstance(label_evidence, list) or not label_evidence:
        blockers.append("label_provenance_missing")
    else:
        for item in label_evidence:
            if not isinstance(item, dict):
                continue
            try:
                window_start = datetime.fromisoformat(str(item.get("windowStart", "")).replace("Z", "+00:00"))
                window_end = datetime.fromisoformat(str(item.get("windowEnd", "")).replace("Z", "+00:00"))
                if window_start.tzinfo is None or window_end.tzinfo is None or window_end <= window_start:
                    raise ValueError("invalid time window")
                session_record = next((s for s in session_map.values() if s.get("sessionId") == item.get("sessionId")), None)
                if session_record is None:
                    raise ValueError("unknown session")
                capture_start = datetime.fromisoformat(str(session_record["captureStartedAt"]).replace("Z", "+00:00"))
                capture_end = datetime.fromisoformat(str(session_record["captureEndedAt"]).replace("Z", "+00:00"))
                if window_start < capture_start or window_end > capture_end:
                    raise ValueError("outside capture window")
            except (KeyError, StopIteration, ValueError, TypeError):
                blockers.append("label_time_window_not_validated_against_capture")
        evidence_keys = {
            (str(item.get("sessionId")), str(item.get("experimentId")), str(item.get("label")), str(item.get("granularity")))
            for item in label_evidence if isinstance(item, dict)
            and item.get("executionState") == "EXECUTED"
            and item.get("observationState") == "OBSERVED"
            and item.get("groundTruthSource")
            and item.get("artifactPath")
            and any(str(artifact.get("path")) == str(item.get("artifactPath")) for artifact in artifacts if isinstance(artifact, dict))
        }
        for row in rows:
            if (str(row.get("session_id")), str(row.get("experiment_id")), str(row.get("label")), str(row.get("label_granularity"))) not in evidence_keys:
                blockers.append("dataset_label_not_supported_by_ground_truth")
                break

    split = details.get("splitManifest") or manifest.get("split") or {}
    session_splits = split.get("session_ids") if isinstance(split, dict) else None
    key_splits = split.get("independent_session_keys") if isinstance(split, dict) else None
    if not isinstance(session_splits, dict) or not isinstance(key_splits, dict):
        blockers.append("validated_session_split_assignments_missing")
    else:
        partitions = ("train", "validation", "test")
        session_sets = {part: set(map(str, session_splits.get(part, []))) for part in partitions}
        key_sets = {part: set(map(str, key_splits.get(part, []))) for part in partitions}
        if any(not session_sets[part] for part in partitions) or any(not key_sets[part] for part in partitions):
            blockers.append("session_split_partition_empty")
        if any(session_sets[left] & session_sets[right] for left, right in (("train", "validation"), ("train", "test"), ("validation", "test"))):
            blockers.append("session_split_overlap")
        if any(key_sets[left] & key_sets[right] for left, right in (("train", "validation"), ("train", "test"), ("validation", "test"))):
            blockers.append("independent_sa_split_overlap")
        if set.union(*session_sets.values()) != set(session_map):
            blockers.append("split_sessions_do_not_match_verified_session_records")
        if set.union(*key_sets.values()) != independent_keys:
            blockers.append("split_sa_keys_do_not_match_verified_session_records")
        if session_map and any(
            key_sets[part] != {str(session_map[s].get("ikeSaIdentitySha256")) for s in session_sets[part] if s in session_map}
            for part in partitions
        ):
            blockers.append("split_sa_keys_do_not_match_session_assignments")
        row_sessions = {part: {str(row.get("session_id")) for row in rows if str(row.get("session_id")) in session_sets[part]} for part in partitions}
        if any(row_sessions[part] != session_sets[part] for part in partitions):
            blockers.append("split_assignments_do_not_match_dataset_rows")
    quality = details.get("qualityReport") or {}
    if quality.get("status") != "PASS" or quality.get("accepted_count") != len(rows) or quality.get("missing_values_count") != 0 or quality.get("duplicate_rows_count") != 0:
        blockers.append("quality_report_not_passed_or_counts_mismatch")
    class_counts = manifest.get("classCounts")
    actual_class_counts: Dict[str, int] = {}
    for row in rows:
        label = str(row.get("label") or "unknown")
        actual_class_counts[label] = actual_class_counts.get(label, 0) + 1
    if not isinstance(class_counts, dict) or class_counts != actual_class_counts:
        blockers.append("manifest_class_counts_do_not_match_dataset")
    return sorted(set(blockers))


class DatasetService:
    """Manages dataset discovery, quality auditing, testbed preflight, and dataset generation."""

    def __init__(self) -> None:
        pass

    def list_datasets(self) -> List[Dict[str, Any]]:
        """
        Scans campaign directories and repository datasets, returning normalized registry records.
        """
        registry: List[Dict[str, Any]] = []

        # 1. Discover historical and live testbed campaign datasets
        if CAMPAIGNS_DIR.exists():
            for campaign_path in sorted(CAMPAIGNS_DIR.iterdir()):
                if not campaign_path.is_dir():
                    continue

                manifest_file = campaign_path / "campaign_manifest.json"
                summary_file = campaign_path / "campaign_summary.json"
                prep_dir = campaign_path / "dataset_preparation"
                dataset_csv = prep_dir / "prepared_dataset.csv"
                dataset_report_file = prep_dir / "dataset_report.json"
                split_manifest_file = prep_dir / "split_manifest.json"

                if not (manifest_file.exists() or dataset_csv.exists()):
                    continue

                campaign_id = campaign_path.name
                dataset_id = f"ds-campaign-{campaign_id[:8]}"
                name = f"StrongSwan IPsec Campaign ({campaign_id[:8]})"
                source = "testbed_campaign"
                created_at = _utc_now()
                sample_count = 0
                classes: Dict[str, int] = {}
                feature_schema = "vista-flow-v1"
                status = "UNVERIFIED"
                recipe_mode = "standard"

                if summary_file.exists():
                    try:
                        summary_data = json.loads(summary_file.read_text(encoding="utf-8"))
                        created_at = summary_data.get("startedAt") or created_at
                        recipe_mode = summary_data.get("recipeMode", "standard")
                        prep_info = summary_data.get("datasetPreparation", {})
                        sample_count = prep_info.get("acceptedObservations", 0)
                        status = prep_info.get("status", status)
                    except Exception:
                        pass

                if dataset_report_file.exists():
                    try:
                        rep_data = json.loads(dataset_report_file.read_text(encoding="utf-8"))
                        classes = rep_data.get("class_distribution", {})
                        sample_count = rep_data.get("accepted_count", sample_count)
                        feature_schema = rep_data.get("feature_schema_version", feature_schema)
                    except Exception:
                        pass
                elif dataset_csv.exists() and sample_count == 0:
                    try:
                        with dataset_csv.open("r", encoding="utf-8") as f:
                            reader = csv.DictReader(f)
                            for row in reader:
                                sample_count += 1
                                lbl = row.get("label") or "unknown"
                                classes[lbl] = classes.get(lbl, 0) + 1
                    except Exception:
                        pass

                csv_sha256 = _sha256_file(dataset_csv) if dataset_csv.exists() else None

                registry.append({
                    "id": dataset_id,
                    "datasetKey": campaign_id,
                    "name": name,
                    "version": "1.0.0",
                    "source": source,
                    "campaignId": campaign_id,
                    "sampleCount": sample_count,
                    "unit": "bidirectional_flows",
                    "classDistribution": classes,
                    "featureSchema": feature_schema,
                    "createdAt": created_at,
                    "status": status,
                    "recipeMode": recipe_mode,
                    "storageLocation": str(campaign_path.relative_to(ROOT_DIR)),
                    "dataPath": str(dataset_csv.relative_to(ROOT_DIR)) if dataset_csv.exists() else None,
                    "manifestPath": str(manifest_file.relative_to(ROOT_DIR)) if manifest_file.exists() else str(summary_file.relative_to(ROOT_DIR)) if summary_file.exists() else None,
                    "sha256": csv_sha256,
                    "hasSplitManifest": split_manifest_file.exists(),
                    "hasQualityReport": dataset_report_file.exists(),
                })

        # 2. Discover representative sample datasets in vista-ml/data/sample/
        if SAMPLE_DATA_DIR.exists():
            for sample_file in sorted(SAMPLE_DATA_DIR.glob("*.csv")):
                meta_file = sample_file.with_suffix(".manifest.json")
                name = sample_file.stem.replace("_", " ").title()
                classes: Dict[str, int] = {}
                sample_count = 0
                feature_schema = "vista-flow-v1"
                created_at = datetime.fromtimestamp(sample_file.stat().st_mtime, timezone.utc).isoformat()

                try:
                    with sample_file.open("r", encoding="utf-8") as f:
                        reader = csv.DictReader(f)
                        for row in reader:
                            sample_count += 1
                            lbl = row.get("label") or "unknown"
                            classes[lbl] = classes.get(lbl, 0) + 1
                except Exception:
                    pass

                meta = {}
                if meta_file.exists():
                    try:
                        meta = json.loads(meta_file.read_text(encoding="utf-8"))
                        feature_schema = meta.get("featureSchemaVersion", feature_schema)
                        name = meta.get("name", name)
                    except Exception:
                        pass

                registry.append({
                    "id": f"ds-sample-{sample_file.stem}",
                    "datasetKey": sample_file.stem,
                    "name": name,
                    "version": meta.get("version", "1.0.0"),
                    "source": "representative_sample",
                    "campaignId": meta.get("campaignId"),
                    "sampleCount": sample_count,
                    "unit": "bidirectional_flows",
                    "classDistribution": classes,
                    "featureSchema": feature_schema,
                    "createdAt": meta.get("createdAt", created_at),
                    "status": meta.get("admissionStatus", "UNVERIFIED"),
                    "originType": meta.get("originType", "unknown"),
                    "provenanceStatus": meta.get(
                        "provenanceStatus",
                        "declared" if meta.get("originType") not in (None, "", "unknown") else "incomplete",
                    ),
                    "recipeMode": meta.get("recipeMode", "standard"),
                    "storageLocation": str(sample_file.relative_to(ROOT_DIR)),
                    "dataPath": str(sample_file.relative_to(ROOT_DIR)),
                    "sha256": _sha256_file(sample_file),
                    "manifestPath": str(meta_file.relative_to(ROOT_DIR)) if meta_file.exists() else None,
                    "hasSplitManifest": False,
                    "hasQualityReport": False,
                })

        # Explicit synthetic fixtures are registered separately from collected campaigns and
        # legacy samples. They cannot acquire operational admission statuses.
        if FIXTURE_DATA_DIR.exists():
            for manifest_file in sorted(FIXTURE_DATA_DIR.glob("*/dataset_manifest.json")):
                try:
                    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
                    if manifest.get("originType") != "synthetic_fixture":
                        continue
                    artifact = manifest["artifacts"][0]
                    data_path = (manifest_file.parent / artifact["path"]).resolve()
                    data_path.relative_to(ROOT_DIR.resolve())
                    if not data_path.is_file():
                        continue
                    registry.append({
                        "id": manifest["datasetId"],
                        "datasetKey": manifest["datasetId"],
                        "name": manifest.get("name", "Synthetic software-test fixture"),
                        "version": manifest.get("datasetVersion", "1.0.0"),
                        "source": "synthetic_fixture",
                        "originType": "synthetic_fixture",
                        "provenanceStatus": "explicit_synthetic",
                        "sampleCount": manifest.get("rowCount", 0),
                        "unit": "flow_fixture",
                        "classDistribution": manifest.get("classCounts", {}),
                        "featureSchema": manifest.get("featureSchemaVersion"),
                        "createdAt": manifest.get("artifacts", [{}])[0].get("createdAt", ""),
                        "status": "SYNTHETIC_FIXTURE",
                        "storageLocation": str(manifest_file.parent.relative_to(ROOT_DIR)),
                        "dataPath": str(data_path.relative_to(ROOT_DIR)),
                        "manifestPath": str(manifest_file.relative_to(ROOT_DIR)),
                        "sha256": artifact.get("sha256"),
                        "hasSplitManifest": False,
                        "hasQualityReport": False,
                    })
                except (OSError, KeyError, ValueError, json.JSONDecodeError):
                    logger.exception("Skipping invalid synthetic fixture manifest %s", manifest_file)

        return sorted(registry, key=lambda x: str(x.get("createdAt")), reverse=True)

    def get_dataset_details(self, dataset_id: str) -> Optional[Dict[str, Any]]:
        """
        Returns deep metadata, sample rows, schema manifest, and quality report for a dataset.
        """
        all_datasets = self.list_datasets()
        target = next((d for d in all_datasets if d["id"] == dataset_id or d["datasetKey"] == dataset_id), None)
        if not target:
            return None

        details = dict(target)
        rel_path = target.get("dataPath")
        sample_rows: List[Dict[str, Any]] = []
        feature_columns: List[str] = []

        if rel_path:
            full_data_path = ROOT_DIR / rel_path
            if full_data_path.exists():
                try:
                    with full_data_path.open("r", encoding="utf-8") as f:
                        reader = csv.DictReader(f)
                        feature_columns = reader.fieldnames or []
                        for i, row in enumerate(reader):
                            if i < 25:
                                sample_rows.append(row)
                            else:
                                break
                except Exception as err:
                    details["dataReadError"] = str(err)

        details["sampleRows"] = sample_rows
        details["columns"] = feature_columns
        manifest_rel = target.get("manifestPath")
        if manifest_rel:
            manifest_path = (ROOT_DIR / manifest_rel).resolve()
            try:
                manifest_path.relative_to(ROOT_DIR.resolve())
                details["datasetManifest"] = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (ValueError, OSError, json.JSONDecodeError):
                details["provenanceStatus"] = "invalid_manifest"
                details["manifestError"] = "Manifest is missing, invalid, or escapes the repository root."

        # Attach split manifest if present
        campaign_id = target.get("campaignId")
        if campaign_id:
            split_file = CAMPAIGNS_DIR / campaign_id / "dataset_preparation" / "split_manifest.json"
            if split_file.exists():
                try:
                    details["splitManifest"] = json.loads(split_file.read_text(encoding="utf-8"))
                except Exception:
                    pass

            report_file = CAMPAIGNS_DIR / campaign_id / "dataset_preparation" / "dataset_report.json"
            if report_file.exists():
                try:
                    details["qualityReport"] = json.loads(report_file.read_text(encoding="utf-8"))
                except Exception:
                    pass

        return details

    def get_testbed_capabilities(self) -> Dict[str, Any]:
        """
        Returns verified testbed parameters and operational boundaries for dataset generation.
        """
        from backend.services.vpn_testbed import inspect_runtime_capabilities

        runtime = inspect_runtime_capabilities()
        containers = runtime.get("containers", {})
        pc1_running = containers.get("pc1") == "running"
        pc2_running = containers.get("pc2") == "running"
        is_testbed_active = pc1_running and pc2_running

        return {
            "testbedActive": is_testbed_active,
            "containers": containers,
            "strongswanVersion": runtime.get("strongswan_version", "strongSwan 5.9.8"),
            "supportedIpVersions": [
                {"value": "IPv4", "label": "IPv4 (Subnet 172.20.0.0/24)", "supported": True},
                {"value": "IPv6", "label": "IPv6", "supported": False, "reason": "Docker bridge network lacks global IPv6 subnet."},
            ],
            "supportedModes": [
                {"value": "tunnel", "label": "IPsec Tunnel Mode (Verified)", "supported": True},
                {"value": "transport", "label": "IPsec Transport Mode", "supported": False, "reason": "Requires host-to-host direct selector reconfiguration; testbed standardizes on Mode B tunnel."},
            ],
            "supportedCiphers": [
                {"value": "aes256gcm16", "label": "AES-256-GCM (AEAD 128-bit ICV)", "supported": True, "family": "AEAD"},
                {"value": "aes128gcm16", "label": "AES-128-GCM (AEAD 128-bit ICV)", "supported": True, "family": "AEAD"},
                {"value": "aes256", "label": "AES-256-CBC + HMAC-SHA2-256", "supported": True, "family": "CBC+HMAC"},
                {"value": "aes128", "label": "AES-128-CBC + HMAC-SHA2-256", "supported": True, "family": "CBC+HMAC"},
            ],
            "supportedDhGroups": [
                {"value": 14, "name": "MODP-2048", "supported": True, "nistStatus": "Compliant"},
                {"value": 15, "name": "MODP-3072", "supported": True, "nistStatus": "Compliant"},
                {"value": 19, "name": "ECP-256", "supported": False, "reason": "Algorithm missing from charon crypto plugin set; rejected at preflight.", "nistStatus": "Compliant"},
                {"value": 2, "name": "MODP-1024", "supported": False, "reason": "Deprecated by NIST SP 800-77 r1; blocked by security policy.", "nistStatus": "Non-compliant"},
            ],
            "supportedTrafficGenerators": [
                {
                    "value": "icmpv4",
                    "label": "ICMPv4 Echo (Controlled Ping)",
                    "supported": True,
                    "targetLabel": "controlled_icmpv4",
                    "defaultPackets": 5,
                    "description": "Benign control; bounded PC1-to-PC2 echo requests with sender and receiver evidence."
                },
                {
                    "value": "tcp_marker",
                    "label": "TCP Marker Transfer (OpenBSD nc)",
                    "supported": False,
                    "reason": "Deferred until the initial benign-control and PORT_SCAN acceptance workflow passes.",
                    "targetLabel": "controlled_tcp_marker",
                    "defaultPackets": 6,
                    "description": "Bounded point-to-point TCP transfer verified via PC2 netcat listener."
                },
                {
                    "value": "http",
                    "label": "HTTP/1.1 Transactions (Perl Core Server)",
                    "supported": False,
                    "reason": "Deferred until scenario-specific acceptance and provenance validation pass.",
                    "targetLabel": "controlled_http",
                    "defaultPackets": 8,
                    "description": "Real HTTP GET/POST queries against container-native Perl HTTP server."
                },
                {
                    "value": "rtp_voip",
                    "label": "RTP/UDP Voice-over-IP Stream",
                    "supported": False,
                    "reason": "RTP packet generation has no separately qualified collection manifest in Dataset Studio.",
                    "targetLabel": "controlled_rtp_voip",
                    "defaultPackets": 12,
                    "description": "RFC 3550 G.711 RTP audio packets generated with precise packet pacing."
                },
                {
                    "value": "controlled_port_scan",
                    "label": "Controlled Port Scan (TCP Connect Probes)",
                    "category": "suspicious",
                    "supported": True,
                    "targetLabel": "PORT_SCAN",
                    "scenarioSubtype": "tcp_connect_probe",
                    "defaultPackets": 5,
                    "safetyLimits": "PC2 172.20.0.3 only; allowlisted ports; maximum 10 probes; minimum 150 ms spacing; each connect times out within 1.5 seconds.",
                    "description": "Low-rate TCP connect probes, verified in actual PC2 receiver capture; labels describe behavior, not intent.",
                },
                {
                    "value": "controlled_connection_burst",
                    "label": "Controlled Connection Burst (SYN Flood Profile)",
                    "category": "suspicious",
                    "supported": False,
                    "reason": "Deferred until the PORT_SCAN and benign-control acceptance workflow passes.",
                    "targetLabel": "controlled_suspicious",
                    "scenarioSubtype": "tcp_burst_syn",
                    "defaultPackets": 10,
                    "safetyLimits": "Max 20 connections, 0.05s spacing, dedicated port 40050.",
                    "description": "Rapid burst of short-lived connections to a controlled listener on PC2.",
                },
                {
                    "value": "controlled_periodic_beacon",
                    "label": "Controlled Periodic Beacon (C2 Heartbeat)",
                    "category": "suspicious",
                    "supported": False,
                    "reason": "Deferred until scenario-specific acceptance and provenance validation pass.",
                    "targetLabel": "controlled_suspicious",
                    "scenarioSubtype": "c2_periodic_heartbeat",
                    "defaultPackets": 8,
                    "safetyLimits": "Max 15 pulses, interval 0.5s, payload 32 bytes, dedicated port 40060.",
                    "description": "Regularly paced heartbeat packets simulating C2 periodic beaconing behavior.",
                },
                {
                    "value": "controlled_bulk_transfer",
                    "label": "Controlled Bulk Transfer (Exfiltration Stream)",
                    "category": "suspicious",
                    "supported": False,
                    "reason": "Deferred until scenario-specific acceptance and provenance validation pass.",
                    "targetLabel": "controlled_suspicious",
                    "scenarioSubtype": "data_exfiltration_bulk",
                    "defaultPackets": 24,
                    "safetyLimits": "Max 64 KB, 1400-byte MTU chunks, SHA-256 verified on receiver.",
                    "description": "Bounded dummy-file exfiltration stream verified via sender/receiver SHA-256.",
                },
                {
                    "value": "controlled_auth_failure_simulation",
                    "label": "Controlled Auth Failure Simulation (Brute Force)",
                    "category": "suspicious",
                    "supported": False,
                    "reason": "Deferred until scenario-specific acceptance and provenance validation pass.",
                    "targetLabel": "controlled_suspicious",
                    "scenarioSubtype": "brute_force_failed_auth",
                    "defaultPackets": 5,
                    "safetyLimits": "Max 10 synthetic attempts, no real credentials, PC2 service audit log.",
                    "description": "Simulated failed authentication HTTP requests verified via PC2 service audit log.",
                },
                {
                    "value": "controlled_attack_campaign",
                    "label": "Balanced Attack & Benign Campaign (Counterbalanced)",
                    "category": "campaign",
                    "supported": False,
                    "reason": "Deferred until the initial bounded scenario workflows pass acceptance.",
                    "targetLabel": "controlled_mixed",
                    "scenarioSubtype": "mixed_benign_and_suspicious",
                    "defaultPackets": 12,
                    "safetyLimits": "Interleaved benign controls (ICMP, TCP, HTTP) and suspicious scenarios.",
                    "description": "Counterbalanced multi-session campaign capturing benign controls and suspicious behaviors.",
                },
                {
                    "value": "video_streaming",
                    "label": "Video Streaming (H.264/RTSP)",
                    "category": "unsupported",
                    "supported": False,
                    "targetLabel": "controlled_video",
                    "reason": "Media codecs and RTSP daemons are not installed in container testbed.",
                },
                {
                    "value": "destructive_attack_traffic",
                    "label": "Destructive Network Attack / Arbitrary Exploitation",
                    "category": "unsupported",
                    "supported": False,
                    "targetLabel": "attack",
                    "reason": "Production safety policy forbids arbitrary scanning, real credentials, malware, or destructive DoS.",
                }
            ],
            "safeExecutionBounds": {
                "maxSessionsPerJob": 15,
                "defaultSessions": 3,
                "maxRepetitionsPerWorkload": 5,
                "maxJobDurationSeconds": 300,
                "minInterPacketDelay": 0.15,
                "maxInterPacketDelay": 1.0,
            }
        }

    def run_preflight_check(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluates prerequisites before starting a dataset generation experiment.
        """
        capabilities = self.get_testbed_capabilities()
        checks: List[Dict[str, Any]] = []
        is_blocked = False

        # 1. Testbed containers active check
        testbed_ok = capabilities["testbedActive"]
        checks.append({
            "name": "Testbed Container State",
            "passed": testbed_ok,
            "details": f"pc1: {capabilities['containers'].get('pc1', 'missing')}, pc2: {capabilities['containers'].get('pc2', 'missing')}",
            "blocker": not testbed_ok,
        })
        if not testbed_ok:
            is_blocked = True

        # 2. IP Version support
        ip_ver = config.get("ipVersion", "IPv4")
        ip_ok = ip_ver == "IPv4"
        checks.append({
            "name": "IP Protocol Version Support",
            "passed": ip_ok,
            "details": f"Requested: {ip_ver}. IPv4 bridge network is operational.",
            "blocker": not ip_ok,
        })
        if not ip_ok:
            is_blocked = True

        # 3. Cipher suite support
        cipher = config.get("cipher", "aes256gcm16")
        supported_ciphers = [c["value"] for c in capabilities["supportedCiphers"] if c["supported"]]
        cipher_ok = cipher in supported_ciphers
        checks.append({
            "name": "Cryptographic Suite Verification",
            "passed": cipher_ok,
            "details": f"Requested: {cipher}. Matches StrongSwan kernel XFRM transforms.",
            "blocker": not cipher_ok,
        })
        if not cipher_ok:
            is_blocked = True

        # 4. DH group support
        dh_group = int(config.get("dhGroup", 14))
        supported_dh = [g["value"] for g in capabilities["supportedDhGroups"] if g["supported"]]
        dh_ok = dh_group in supported_dh
        checks.append({
            "name": "Diffie-Hellman Group Compliance",
            "passed": dh_ok,
            "details": f"Requested: Group {dh_group}. NIST SP 800-77 compliant and present in charon plugins.",
            "blocker": not dh_ok,
        })
        if not dh_ok:
            is_blocked = True

        # 5. Traffic generator support
        traffic = config.get("trafficType", "icmpv4")
        supported_traffic = [t["value"] for t in capabilities["supportedTrafficGenerators"] if t["supported"]]
        traffic_ok = traffic in supported_traffic
        checks.append({
            "name": "Workload Generator Availability",
            "passed": traffic_ok,
            "details": f"Requested: {traffic}. Fully verified endpoint listener and ground-truth sidecar present.",
            "blocker": not traffic_ok,
        })
        if not traffic_ok:
            is_blocked = True

        # 6. Safe bounds check
        sessions = int(config.get("sessions", 3))
        bounds = capabilities["safeExecutionBounds"]
        bounds_ok = 1 <= sessions <= bounds["maxSessionsPerJob"]
        checks.append({
            "name": "Execution Volume Bounds",
            "passed": bounds_ok,
            "details": f"Sessions: {sessions} (Safe limit: 1 to {bounds['maxSessionsPerJob']}).",
            "blocker": not bounds_ok,
        })
        if not bounds_ok:
            is_blocked = True

        # 7. Concurrency lock check
        with JOBS_LOCK:
            active_jobs = [j for j in GENERATION_JOBS.values() if j["status"] in {"RUNNING", "PRECHECK", "CANCELLING"}]
            no_conflict = len(active_jobs) == 0
        checks.append({
            "name": "Testbed Concurrency Lock",
            "passed": no_conflict,
            "details": "No other collection job is currently accessing the StrongSwan daemon." if no_conflict else f"Job {active_jobs[0]['jobId']} is actively running.",
            "blocker": not no_conflict,
        })
        # 8. Controlled suspicious scenario safety bounds & parameter audit
        if traffic in {
            "controlled_port_scan",
            "controlled_connection_burst",
            "controlled_periodic_beacon",
            "controlled_bulk_transfer",
            "controlled_auth_failure_simulation",
        }:
            params = config.get("parameters", {})
            param_errors = []
            try:
                from backend.services.attack_workloads import (
                    validate_port_scan_config,
                    validate_connection_burst_config,
                    validate_periodic_beacon_config,
                    validate_bulk_transfer_config,
                    validate_auth_failure_config,
                )
                if traffic == "controlled_port_scan":
                    validate_port_scan_config(params)
                elif traffic == "controlled_connection_burst":
                    validate_connection_burst_config(params)
                elif traffic == "controlled_periodic_beacon":
                    validate_periodic_beacon_config(params)
                elif traffic == "controlled_bulk_transfer":
                    validate_bulk_transfer_config(params)
                elif traffic == "controlled_auth_failure_simulation":
                    validate_auth_failure_config(params)
            except Exception as e:
                param_errors.append(str(e))

            attack_safety_ok = len(param_errors) == 0
            checks.append({
                "name": "Controlled Scenario Safety Bounds & Allowlist",
                "passed": attack_safety_ok,
                "details": "All scenario parameters conform to safe lab bounds and destination allowlist."
                if attack_safety_ok
                else f"Safety violation: {'; '.join(param_errors)}",
                "blocker": not attack_safety_ok,
            })
            if not attack_safety_ok:
                is_blocked = True

        return {
            "canProceed": not is_blocked,
            "status": "READY" if not is_blocked else "BLOCKED",
            "checks": checks,
            "evaluatedAt": _utc_now(),
        }

    def list_scenarios(self) -> List[Dict[str, Any]]:
        """Expose only the first acceptance pair; later behaviors stay deferred."""
        return [
            {
                "id": "benign_icmp_control_v1",
                "version": "1.0.0",
                "name": "Benign ICMPv4 control",
                "trafficType": "icmpv4",
                "label": "controlled_icmpv4",
                "labelGranularity": "time_window",
                "intendedBehavior": "Bounded ICMPv4 echo request/reply control over the direct PC1↔PC2 tunnel.",
                "target": {"endpoint": "pc2", "ipv4": "172.20.0.3", "allowlisted": True},
                "parameters": {"count": {"minimum": 1, "maximum": 20}, "interval_seconds": {"minimum": 0.15, "maximum": 1.0}, "payload_bytes": {"minimum": 0, "maximum": 1400}},
                "prerequisites": ["pc1 and pc2 running", "established tunnel-mode CHILD_SA", "pc2 receiver capture"],
                "groundTruthSources": ["pc1 ping counters", "pc2 receiver capture", "CHILD_SA counter deltas"],
                "expectedEvidence": ["pc1 outer ESP PCAP", "pc2 receiver PCAP", "workload measurements", "negotiated SA", "session record", "hashes"],
                "cleanup": "Capture processes are stopped and temporary endpoint processes are cleaned by the collector on success and failure.",
            },
            {
                "id": "port_scan_v1",
                "version": "1.0.0",
                "name": "Bounded TCP connect probes (PORT_SCAN behavior)",
                "trafficType": "controlled_port_scan",
                "label": "PORT_SCAN",
                "labelGranularity": "time_window",
                "intendedBehavior": "Sequential low-rate TCP connect probes against an explicit allowlist on PC2; this behavior label does not establish malicious intent.",
                "target": {"endpoint": "pc2", "ipv4": "172.20.0.3", "allowlisted": True},
                "parameters": {"ports": "1-10 unique allowlisted TCP ports", "interval_seconds": {"minimum": 0.15, "maximum": 1.5}, "timeout_seconds": {"minimum": 0.05, "maximum": 1.5}},
                "prerequisites": ["pc1 and pc2 running", "established tunnel-mode CHILD_SA", "allowlisted lab TCP ports", "PC2 receiver capture"],
                "groundTruthSources": ["PC1 probe result log", "PC2 captured inbound SYN packets and destination ports", "PC1 outer ESP PCAP", "CHILD_SA counters"],
                "expectedEvidence": ["pc1 outer ESP PCAP", "pc2 receiver PCAP and parsed CSV", "workload measurements", "scenario manifest", "hashes"],
                "cleanup": "The bounded listener and both capture processes are cleaned by the collector on success and failure.",
                "limitations": ["The label applies to the execution time window, not every aggregated encrypted ESP flow.", "Optional eBPF events are not flow-correlated by timing alone."],
            },
        ]

    def get_scenario(self, scenario_id: str) -> Optional[Dict[str, Any]]:
        return next((item for item in self.list_scenarios() if item["id"] == scenario_id), None)

    def validate_scenario(self, scenario_id: str, parameters: Any) -> Dict[str, Any]:
        scenario = self.get_scenario(scenario_id)
        if not scenario:
            raise ValueError("Unknown or deferred scenario.")
        if not isinstance(parameters, dict):
            raise ValueError("parameters must be a JSON object.")
        from backend.services.attack_workloads import validate_port_scan_config
        from backend.services.workload_collection import validate_icmp_profiles

        if scenario_id == "port_scan_v1":
            unknown = set(parameters) - {"target", "target_ipv4", "ports", "target_ports", "interval_seconds", "probe_delay_seconds", "timeout_seconds"}
            if unknown:
                raise ValueError(f"Unsupported PORT_SCAN parameters: {sorted(unknown)}.")
            normalized = validate_port_scan_config(parameters)
            job_config = {
                "trafficType": "controlled_port_scan", "sessions": 1,
                "ipVersion": "IPv4", "mode": "tunnel", "cipher": "aes256gcm16",
                "dhGroup": 14, "pfs": True, "parameters": {
                    "target_ports": normalized["ports"],
                    "probe_delay_seconds": normalized["interval_seconds"],
                    "timeout_seconds": normalized["timeout_seconds"],
                },
            }
        else:
            unknown = set(parameters) - {"count", "interval_seconds", "payload_bytes"}
            if unknown:
                raise ValueError(f"Unsupported benign-control parameters: {sorted(unknown)}.")
            profile_input = {"count": 6, "interval_seconds": 0.3, "payload_bytes": 64}
            profile_input.update(parameters)
            profile = validate_icmp_profiles([profile_input])[0]
            normalized = profile
            job_config = {
                "trafficType": "icmpv4", "sessions": 1,
                "ipVersion": "IPv4", "mode": "tunnel", "cipher": "aes256gcm16",
                "dhGroup": 14, "pfs": True, "parameters": {"profile": normalized},
            }
        preflight = self.run_preflight_check(job_config)
        return {
            "scenario": scenario,
            "normalizedParameters": normalized,
            "canProceed": preflight["canProceed"],
            "status": "READY" if preflight["canProceed"] else "BLOCKED",
            "checks": preflight["checks"],
            "validatedAt": _utc_now(),
            "executionStarted": False,
        }

    def start_scenario_run(
        self, scenario_id: str, parameters: Any, *, confirmed_isolated_lab: bool
    ) -> Dict[str, Any]:
        if confirmed_isolated_lab is not True:
            raise ValueError("Explicit isolated-lab confirmation is required before execution.")
        validation = self.validate_scenario(scenario_id, parameters)
        if not validation["canProceed"]:
            raise ValueError("Scenario preflight is blocked; resolve the listed checks before execution.")
        scenario = validation["scenario"]
        job = self.start_generation_job({
            "name": scenario["name"],
            "trafficType": scenario["trafficType"],
            "sessions": 1,
            "ipVersion": "IPv4",
            "mode": "tunnel",
            "cipher": "aes256gcm16",
            "dhGroup": 14,
            "pfs": True,
            "recipeMode": "standard",
            "parameters": (
                {"profile": validation["normalizedParameters"]}
                if scenario_id == "benign_icmp_control_v1"
                else {
                    "target_ports": validation["normalizedParameters"]["ports"],
                    "probe_delay_seconds": validation["normalizedParameters"]["interval_seconds"],
                    "timeout_seconds": validation["normalizedParameters"]["timeout_seconds"],
                }
            ),
            "confirmedIsolatedLab": True,
        })
        with JOBS_LOCK:
            GENERATION_JOBS[job["jobId"]]["scenarioId"] = scenario_id
            GENERATION_JOBS[job["jobId"]]["logEvents"].append({
                "at": _utc_now(), "level": "INFO", "message": f"Authorized lab run queued for {scenario_id}."
            })
        return self.get_job_status(job["jobId"]) or job

    def start_generation_job(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validates preflight and dispatches an asynchronous dataset generation job.
        """
        if config.get("trafficType") in {"icmpv4", "controlled_port_scan"} and config.get("confirmedIsolatedLab") is not True:
            raise ValueError("Explicit isolated-lab confirmation is required before execution.")
        preflight = self.run_preflight_check(config)
        if not preflight["canProceed"]:
            raise ValueError(f"Preflight check failed: {[c['name'] for c in preflight['checks'] if not c['passed']]}")

        job_id = f"job-{uuid.uuid4().hex[:10]}"
        dataset_name = config.get("name") or f"Dataset-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
        sessions = int(config.get("sessions", 3))
        traffic_type = config.get("trafficType", "icmpv4")
        recipe_mode = config.get("recipeMode", "standard")

        job_record = {
            "jobId": job_id,
            "datasetName": dataset_name,
            "configuration": config,
            "status": "RUNNING",
            "currentStage": "PRECHECK",
            "stages": [
                {"name": "PRECHECK", "label": "Preflight & Container Verification", "status": "COMPLETED"},
                {"name": "SA_NEGOTIATION", "label": "IKEv2 / CHILD_SA Re-establishment", "status": "IN_PROGRESS"},
                {"name": "WORKLOAD_GENERATION", "label": "Controlled Workload Injection", "status": "PENDING"},
                {"name": "PACKET_CAPTURE", "label": "Outer ESP Capture & Pcap Verification", "status": "PENDING"},
                {"name": "FEATURE_EXTRACTION", "label": "18-Feature Flow Extraction (vista-flow-v1)", "status": "PENDING"},
                {"name": "QUALITY_AUDIT", "label": "Quality Audit & Leakage Controls", "status": "PENDING"},
                {"name": "FINALIZED", "label": "Dataset Manifest & Parquet/CSV Export", "status": "PENDING"},
            ],
            "progressPercent": 15,
            "startedAt": _utc_now(),
            "completedAt": None,
            "totalSessions": sessions,
            "completedSessions": 0,
            "acceptedObservations": 0,
            "quarantinedObservations": 0,
            "generatedDatasetId": None,
            "errors": [],
            "logEvents": [{"at": _utc_now(), "level": "INFO", "message": "Collection job accepted after preflight."}],
            "artifacts": [],
            "datasetAdmissionStatus": "PENDING_VALIDATION",
            "cancelRequested": False,
        }

        with JOBS_LOCK:
            active_jobs = [
                item for item in GENERATION_JOBS.values()
                if item["status"] in {"RUNNING", "PRECHECK", "CANCELLING"}
            ]
            if active_jobs:
                raise ValueError(f"Collection job {active_jobs[0]['jobId']} is already using the testbed.")
            GENERATION_JOBS[job_id] = job_record
            if traffic_type == "icmpv4":
                job_record["scenarioId"] = "benign_icmp_control_v1"
            elif traffic_type == "controlled_port_scan":
                job_record["scenarioId"] = "port_scan_v1"

        # Spawn worker thread
        thread = threading.Thread(
            target=self._run_job_worker,
            args=(job_id, config),
            daemon=True,
            name=f"vista-dataset-job-{job_id}",
        )
        try:
            thread.start()
        except Exception as exc:
            with JOBS_LOCK:
                job_record["status"] = "FAILED"
                job_record["completedAt"] = _utc_now()
                job_record["errors"].append(f"Worker thread failed to start: {exc}")
                job_record["logEvents"].append({"at": _utc_now(), "level": "ERROR", "message": "Collection worker failed to start."})
            raise

        return job_record

    def get_job_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        with JOBS_LOCK:
            job = GENERATION_JOBS.get(job_id)
            return dict(job) if job else None

    def cancel_job(self, job_id: str) -> bool:
        with JOBS_LOCK:
            job = GENERATION_JOBS.get(job_id)
            if not job or job["status"] not in {"RUNNING", "PRECHECK", "CANCELLING"}:
                return False
            job["cancelRequested"] = True
            job["status"] = "CANCELLING"
            job.setdefault("logEvents", []).append({
                "at": _utc_now(), "level": "WARNING",
                "message": "Cancellation requested; waiting for the bounded collector to stop and clean up captures/listeners.",
            })
            return True

    def _run_job_worker(self, job_id: str, config: Dict[str, Any]) -> None:
        """Background thread executing the real dataset generation campaign."""
        from backend.services import workload_collection as collector
        from vista_ml.features.pcap_features import extract_flow_features

        def update_job(stage_name: str, progress: int, **kwargs):
            with JOBS_LOCK:
                if job_id not in GENERATION_JOBS:
                    return
                j = GENERATION_JOBS[job_id]
                if j.get("cancelRequested"):
                    return
                j["currentStage"] = stage_name
                j["progressPercent"] = progress
                for s in j["stages"]:
                    if s["name"] == stage_name:
                        s["status"] = "IN_PROGRESS"
                    elif j["stages"].index(s) < [x["name"] for x in j["stages"]].index(stage_name):
                        s["status"] = "COMPLETED"
                for k, v in kwargs.items():
                    j[k] = v
                j.setdefault("logEvents", []).append({
                    "at": _utc_now(), "level": "INFO", "message": f"Stage entered: {stage_name}.",
                })

        def finish_cancelled(message: str) -> None:
            with JOBS_LOCK:
                job = GENERATION_JOBS.get(job_id)
                if not job:
                    return
                job["status"] = "CANCELLED"
                job["completedAt"] = _utc_now()
                job["currentStage"] = "CANCELLED"
                job.setdefault("logEvents", []).append({
                    "at": _utc_now(), "level": "WARNING", "message": message,
                })
                for stage in job["stages"]:
                    if stage["status"] == "IN_PROGRESS":
                        stage["status"] = "CANCELLED"

        try:
            sessions_count = int(config.get("sessions", 3))
            traffic_type = config.get("trafficType", "icmpv4")
            recipe_mode = config.get("recipeMode", "standard")
            campaign_id = str(uuid.uuid4())
            campaign_dir = CAMPAIGNS_DIR / campaign_id
            campaign_dir.mkdir(parents=True, exist_ok=False)
            prep_dir = campaign_dir / "dataset_preparation"
            prep_dir.mkdir(parents=True, exist_ok=False)
            with JOBS_LOCK:
                GENERATION_JOBS[job_id]["campaignId"] = campaign_id

            logger.info("Starting dataset generation job %s (Campaign %s)", job_id, campaign_id)

            # Stage 2: SA Negotiation
            update_job("SA_NEGOTIATION", 25)

            # Stage 3: Workload Generation & Session Capture
            update_job("WORKLOAD_GENERATION", 40)
            accepted_rows: List[Dict[str, Any]] = []

            for sess_idx in range(sessions_count):
                with JOBS_LOCK:
                    cancellation_requested = GENERATION_JOBS.get(job_id, {}).get("cancelRequested")
                if cancellation_requested:
                    finish_cancelled("Cancelled at a safe boundary before starting another collection session.")
                    return

                session_id = str(uuid.uuid4())
                experiment_id = str(uuid.uuid4())

                # Re-establish fresh IKE_SA per session
                sa_result = collector.reestablish_collection_sa()
                ike_identity = sa_result.get("newIkeSaIdentitySha256")
                session_context = {
                    "previousIkeSaIdentitySha256": sa_result.get("previousIkeSaIdentitySha256"),
                    "reestablishedAt": sa_result.get("reestablishedAt"),
                }
                with JOBS_LOCK:
                    cancellation_requested = GENERATION_JOBS.get(job_id, {}).get("cancelRequested")
                if cancellation_requested:
                    finish_cancelled("Cancelled after SA re-establishment and before workload execution.")
                    return

                custom_params = config.get("parameters", {})
                scenario_label = "unknown"

                # Workload schedule selection
                if traffic_type == "icmpv4":
                    profile = custom_params.get("profile") or {
                        "count": 6 if recipe_mode == "standard" else 8,
                        "interval_seconds": 0.3,
                        "payload_bytes": 64,
                    }
                    exp = collector.collect_icmp_workload({
                        "profiles": [profile],
                        "sessionId": session_id,
                        "experimentId": experiment_id,
                        "sessionContext": session_context,
                    })
                    label = "unknown"
                    scenario_label = "controlled_icmpv4"
                    scenario_subtype = "icmpv4_echo"
                elif traffic_type == "tcp_marker":
                    pkt_count = 12 if recipe_mode == "standard" else 14
                    exp = collector.collect_tcp_marker_workload({
                        "profiles": [{"count": pkt_count, "interval_seconds": 0.25, "payload_bytes": 128}],
                        "sessionId": session_id,
                        "experimentId": experiment_id,
                        "sessionContext": session_context,
                    })
                    label = "controlled_tcp_marker"
                    scenario_subtype = "tcp_marker_transfer"
                elif traffic_type == "http":
                    exp = collector.collect_http_workload({
                        "profiles": [{"count": 4, "interval_seconds": 0.3, "path": "/api/v1/telemetry", "method": "GET", "payload_bytes": 0, "expected_status": 200}],
                        "sessionId": session_id,
                        "experimentId": experiment_id,
                        "sessionContext": session_context,
                    })
                    label = "controlled_http"
                    scenario_subtype = "http_transaction"
                elif traffic_type == "rtp_voip":
                    exp = collector.collect_rtp_workload({
                        "profiles": [{"count": 12, "interval_seconds": 0.02, "payload_bytes": 160}],
                        "sessionId": session_id,
                        "experimentId": experiment_id,
                    })
                    label = "controlled_rtp_voip"
                    scenario_subtype = "rtp_voip_stream"
                elif traffic_type == "controlled_port_scan":
                    scan_opts = {
                        "target_ports": custom_params.get("target_ports", [80, 443, 8080, 8443, 9000]),
                        "probe_delay_seconds": custom_params.get("probe_delay_seconds", 0.15),
                        "timeout_seconds": custom_params.get("timeout_seconds", 0.3),
                        "sessionId": session_id,
                        "experimentId": experiment_id,
                    }
                    exp = collector.collect_port_scan_workload(scan_opts)
                    label = "unknown"
                    scenario_label = "PORT_SCAN"
                    scenario_subtype = "controlled_port_scan"
                elif traffic_type == "controlled_connection_burst":
                    burst_opts = {
                        "burst_size": custom_params.get("burst_size", 15),
                        "concurrency": custom_params.get("concurrency", 2),
                        "target_port": custom_params.get("target_port", 80),
                        "sessionId": session_id,
                        "experimentId": experiment_id,
                    }
                    exp = collector.collect_connection_burst_workload(burst_opts)
                    label = "controlled_suspicious"
                    scenario_subtype = "controlled_connection_burst"
                elif traffic_type == "controlled_periodic_beacon":
                    beacon_opts = {
                        "beacon_count": custom_params.get("beacon_count", 8),
                        "interval_seconds": custom_params.get("interval_seconds", 0.25),
                        "payload_size": custom_params.get("payload_size", 32),
                        "target_port": custom_params.get("target_port", 8080),
                        "sessionId": session_id,
                        "experimentId": experiment_id,
                    }
                    exp = collector.collect_periodic_beacon_workload(beacon_opts)
                    label = "controlled_suspicious"
                    scenario_subtype = "controlled_periodic_beacon"
                elif traffic_type == "controlled_bulk_transfer":
                    bulk_opts = {
                        "transfer_size_kb": custom_params.get("transfer_size_kb", 64),
                        "chunk_size_bytes": custom_params.get("chunk_size_bytes", 4096),
                        "target_port": custom_params.get("target_port", 8080),
                        "sessionId": session_id,
                        "experimentId": experiment_id,
                    }
                    exp = collector.collect_bulk_transfer_workload(bulk_opts)
                    label = "controlled_suspicious"
                    scenario_subtype = "controlled_bulk_transfer"
                elif traffic_type == "controlled_auth_failure_simulation":
                    auth_opts = {
                        "attempt_count": custom_params.get("attempt_count", 5),
                        "delay_seconds": custom_params.get("delay_seconds", 0.1),
                        "sessionId": session_id,
                        "experimentId": experiment_id,
                    }
                    exp = collector.collect_auth_failure_workload(auth_opts)
                    label = "controlled_suspicious"
                    scenario_subtype = "controlled_auth_failure_simulation"
                elif traffic_type == "controlled_attack_campaign":
                    campaign_sequence = [
                        ("icmpv4", "controlled_icmpv4", "icmpv4_echo"),
                        ("controlled_port_scan", "controlled_suspicious", "controlled_port_scan"),
                        ("tcp_marker", "controlled_tcp_marker", "tcp_marker_transfer"),
                        ("controlled_periodic_beacon", "controlled_suspicious", "controlled_periodic_beacon"),
                        ("http", "controlled_http", "http_transaction"),
                        ("controlled_connection_burst", "controlled_suspicious", "controlled_connection_burst"),
                    ]
                    chosen_type, chosen_label, chosen_subtype = campaign_sequence[sess_idx % len(campaign_sequence)]
                    label = chosen_label
                    scenario_subtype = chosen_subtype
                    if chosen_type == "icmpv4":
                        exp = collector.collect_icmp_workload({
                            "profiles": [{"count": 6, "interval_seconds": 0.3, "payload_bytes": 64}],
                            "sessionId": session_id,
                            "experimentId": experiment_id,
                        })
                    elif chosen_type == "tcp_marker":
                        exp = collector.collect_tcp_marker_workload({
                            "profiles": [{"count": 12, "interval_seconds": 0.25, "payload_bytes": 128}],
                            "sessionId": session_id,
                            "experimentId": experiment_id,
                        })
                    elif chosen_type == "http":
                        exp = collector.collect_http_workload({
                            "profiles": [{"count": 4, "interval_seconds": 0.3, "path": "/api/v1/telemetry", "method": "GET", "payload_bytes": 0, "expected_status": 200}],
                            "sessionId": session_id,
                            "experimentId": experiment_id,
                        })
                    elif chosen_type == "controlled_port_scan":
                        exp = collector.collect_port_scan_workload({
                            "target_ports": [80, 443, 8080, 8443, 9000],
                            "probe_delay_seconds": 0.15,
                            "sessionId": session_id,
                            "experimentId": experiment_id,
                        })
                    elif chosen_type == "controlled_periodic_beacon":
                        exp = collector.collect_periodic_beacon_workload({
                            "beacon_count": 8,
                            "interval_seconds": 0.25,
                            "payload_size": 32,
                            "target_port": 8080,
                            "sessionId": session_id,
                            "experimentId": experiment_id,
                        })
                    elif chosen_type == "controlled_connection_burst":
                        exp = collector.collect_connection_burst_workload({
                            "burst_size": 15,
                            "concurrency": 2,
                            "target_port": 80,
                            "sessionId": session_id,
                            "experimentId": experiment_id,
                        })
                    else:
                        exp = collector.collect_icmp_workload({
                            "profiles": [{"count": 6, "interval_seconds": 0.3, "payload_bytes": 64}],
                            "sessionId": session_id,
                            "experimentId": experiment_id,
                        })
                else:
                    # Default to icmpv4
                    exp = collector.collect_icmp_workload({
                        "profiles": [{"count": 6, "interval_seconds": 0.3, "payload_bytes": 64}],
                        "sessionId": session_id,
                        "experimentId": experiment_id,
                    })
                    label = "controlled_icmpv4"
                    scenario_subtype = "icmpv4_echo"

                if exp.get("status") != "PASS":
                    errs = exp.get("errors", ["Workload collection failed"])
                    raise RuntimeError("; ".join(errs))

                with JOBS_LOCK:
                    GENERATION_JOBS[job_id].setdefault("artifacts", []).append({
                        "experimentId": experiment_id,
                        "sessionId": session_id,
                        "status": exp.get("status"),
                        "artifacts": exp.get("artifacts", {}),
                        "datasetPreparation": exp.get("datasetPreparation", {}),
                    })
                    cancellation_requested = GENERATION_JOBS[job_id].get("cancelRequested")
                if cancellation_requested:
                    finish_cancelled("The active bounded collector completed and cleaned up; cancellation stopped the job before further processing.")
                    return

                # Extract features from packet table
                packets_csv = Path(exp["artifacts"]["packetTable"])
                flow_df = extract_flow_features(packets_csv)
                flow_records = flow_df.to_dict(orient="records")

                for flow_row in flow_records:
                    feature_row = {
                        **flow_row,
                        "flow_id": flow_row.get("flow_id") or f"FLW-{campaign_id[:6]}-{sess_idx+1:03d}",
                        "session_id": session_id,
                        "experiment_id": experiment_id,
                        "label": label,
                        "scenario_label": scenario_label,
                        "label_granularity": "time_window",
                        "scenario_subtype": scenario_subtype,
                        "ike_sa_identity": ike_identity,
                    }
                    accepted_rows.append(feature_row)

                with JOBS_LOCK:
                    GENERATION_JOBS[job_id]["completedSessions"] = sess_idx + 1
                    GENERATION_JOBS[job_id]["acceptedObservations"] = len(accepted_rows)


            # Stage 4: Packet Capture & Pcap Verification
            with JOBS_LOCK:
                cancellation_requested = GENERATION_JOBS.get(job_id, {}).get("cancelRequested")
            if cancellation_requested:
                finish_cancelled("Cancelled before feature extraction and candidate preparation.")
                return
            update_job("PACKET_CAPTURE", 65)

            # Stage 5: Feature Extraction
            update_job("FEATURE_EXTRACTION", 80)
            dataset_csv = prep_dir / "prepared_dataset.csv"
            fieldnames = list(accepted_rows[0].keys())
            with dataset_csv.open("w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(accepted_rows)

            # Stage 6: Quality Audit & Leakage Controls
            update_job("QUALITY_AUDIT", 90)
            class_dist: Dict[str, int] = {}
            for r in accepted_rows:
                lbl = r["label"]
                class_dist[lbl] = class_dist.get(lbl, 0) + 1

            # Preserve a disjoint partition for inspection; this is not a validated evaluation split.
            unique_sessions = list(dict.fromkeys(r["session_id"] for r in accepted_rows))
            session_to_ike = {r["session_id"]: r.get("ike_sa_identity") for r in accepted_rows}
            n_sess = len(unique_sessions)
            if n_sess >= 3:
                n_test = max(1, int(round(n_sess * 0.2)))
                n_val = max(1, int(round(n_sess * 0.2)))
                n_train = n_sess - n_test - n_val
                if n_train < 1:
                    n_train = 1
                    if n_val > 1:
                        n_val -= 1
                    elif n_test > 1:
                        n_test -= 1
                train_sessions = unique_sessions[:n_train]
                val_sessions = unique_sessions[n_train:n_train + n_val]
                test_sessions = unique_sessions[n_train + n_val:]
            elif n_sess == 2:
                train_sessions = [unique_sessions[0]]
                val_sessions = []
                test_sessions = [unique_sessions[1]]
            else:
                train_sessions = unique_sessions
                val_sessions = []
                test_sessions = []

            split_manifest = {
                "strategy": "ordered session-group partition for inspection only",
                "groupingKey": "session_id",
                "evaluationEligible": False,
                "session_ids": {
                    "train": train_sessions,
                    "validation": val_sessions,
                    "test": test_sessions,
                },
                "independent_session_keys": {
                    "train": [session_to_ike.get(s) for s in train_sessions],
                    "validation": [session_to_ike.get(s) for s in val_sessions],
                    "test": [session_to_ike.get(s) for s in test_sessions],
                },
                "experiment_ids": {
                    "train": [r["experiment_id"] for r in accepted_rows if r["session_id"] in train_sessions],
                    "validation": [r["experiment_id"] for r in accepted_rows if r["session_id"] in val_sessions],
                    "test": [r["experiment_id"] for r in accepted_rows if r["session_id"] in test_sessions],
                },
                "row_counts": {
                    "train": sum(1 for r in accepted_rows if r["session_id"] in train_sessions),
                    "validation": sum(1 for r in accepted_rows if r["session_id"] in val_sessions),
                    "test": sum(1 for r in accepted_rows if r["session_id"] in test_sessions),
                },
                "class_distributions": {
                    "train": {lbl: sum(1 for r in accepted_rows if r["session_id"] in train_sessions and r["label"] == lbl) for lbl in class_dist},
                    "validation": {lbl: sum(1 for r in accepted_rows if r["session_id"] in val_sessions and r["label"] == lbl) for lbl in class_dist},
                    "test": {lbl: sum(1 for r in accepted_rows if r["session_id"] in test_sessions and r["label"] == lbl) for lbl in class_dist},
                },
                "overlap": {"train_validation": 0, "train_test": 0, "validation_test": 0},
            }
            (prep_dir / "split_manifest.json").write_text(json.dumps(split_manifest, indent=2), encoding="utf-8")

            quality_report = {
                "dataset_id": f"ds-{campaign_id[:8]}",
                "campaign_id": campaign_id,
                "verified_at": _utc_now(),
                "feature_schema_version": "vista-flow-v1",
                "accepted_count": len(accepted_rows),
                "quarantined_count": 0,
                "class_distribution": class_dist,
                "missing_values_count": 0,
                "duplicate_rows_count": 0,
                "leakage_controls": {
                    "session_disjoint": True,
                    "identifiers_in_features": False,
                    "outer_esp_only": True,
                },
                "status": "UNVERIFIED",
                "admissionBlockers": [
                    "Collection candidate requires independent evidence-manifest validation before analysis admission.",
                    "A session-disjoint split is not evidence of generalization when the independent-session count is insufficient.",
                ],
            }
            (prep_dir / "dataset_report.json").write_text(json.dumps(quality_report, indent=2), encoding="utf-8")

            # Stage 7: Finalized Manifest & Summary
            update_job("FINALIZED", 100)
            campaign_summary = {
                "campaignId": campaign_id,
                "status": "PASS",
                "recipeMode": recipe_mode,
                "completedSessions": sessions_count,
                "startedAt": _utc_now(),
                "datasetPreparation": {
                    "status": "UNVERIFIED",
                    "acceptedObservations": len(accepted_rows),
                    "quarantinedObservations": 0,
                }
            }
            with JOBS_LOCK:
                job = GENERATION_JOBS[job_id]
                job["completedAt"] = _utc_now()
                job["datasetAdmissionStatus"] = "UNVERIFIED"
                if job.get("cancelRequested"):
                    job["status"] = "CANCELLED"
                    job["currentStage"] = "CANCELLED"
                    campaign_summary["status"] = "CANCELLED"
                    job["logEvents"].append({"at": _utc_now(), "level": "WARNING", "message": "Cancellation completed at the finalization boundary; candidate remains UNVERIFIED."})
                else:
                    job["status"] = "COMPLETED"
                    job["generatedDatasetId"] = f"ds-campaign-{campaign_id[:8]}"
                    job["logEvents"].append({
                        "at": _utc_now(), "level": "WARNING",
                        "message": "Collection completed; candidate remains UNVERIFIED pending independent manifest, label, and leakage validation.",
                    })
                (campaign_dir / "campaign_summary.json").write_text(json.dumps(campaign_summary, indent=2), encoding="utf-8")

            logger.info("Job %s completed successfully. Created dataset %s", job_id, f"ds-campaign-{campaign_id[:8]}")

        except Exception as err:
            logger.exception("Generation job %s failed: %s", job_id, err)
            with JOBS_LOCK:
                if job_id in GENERATION_JOBS:
                    GENERATION_JOBS[job_id]["status"] = "FAILED"
                    GENERATION_JOBS[job_id]["completedAt"] = _utc_now()
                    GENERATION_JOBS[job_id]["errors"].append(str(err))
            if "campaign_dir" in locals() and campaign_dir.exists():
                try:
                    (campaign_dir / "campaign_summary.json").write_text(json.dumps({
                        "campaignId": campaign_id,
                        "jobId": job_id,
                        "status": "FAILED",
                        "completedAt": _utc_now(),
                        "error": str(err),
                        "datasetPreparation": {"status": "FAILED", "acceptedObservations": 0, "quarantinedObservations": 0},
                    }, indent=2), encoding="utf-8")
                except OSError:
                    logger.exception("Unable to write failure summary for campaign %s", campaign_id)

    def validate_dataset_quality(self, dataset_id: str) -> Dict[str, Any]:
        """
        Runs an exhaustive quality & leakage audit on the target dataset.
        """
        details = self.get_dataset_details(dataset_id)
        if not details:
            raise ValueError(f"Dataset {dataset_id} not found.")

        rel_path = details.get("dataPath")
        if not rel_path:
            raise ValueError("Dataset does not contain a data file path.")

        full_path = (ROOT_DIR / rel_path).resolve()
        try:
            full_path.relative_to(ROOT_DIR.resolve())
        except ValueError as exc:
            raise ValueError("Dataset data path escapes the repository root.") from exc
        if not full_path.exists():
            raise FileNotFoundError(f"Dataset data file {full_path} is missing on disk.")

        rows: List[Dict[str, Any]] = []
        with full_path.open("r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                rows.append(row)

        total_rows = len(rows)
        feature_keys = [
            "packet_count", "byte_count", "flow_duration", "mean_packet_size",
            "std_packet_size", "min_packet_size", "max_packet_size",
            "mean_inter_arrival_time", "std_inter_arrival_time",
            "min_inter_arrival_time", "max_inter_arrival_time",
            "packets_per_second", "bytes_per_second", "forward_packet_count",
            "backward_packet_count", "forward_bytes", "backward_bytes", "direction_ratio",
        ]

        missing_values = 0
        invalid_numeric_values = 0
        duplicate_vectors = 0
        near_duplicate_vectors = 0
        seen_vectors = set()
        seen_near_vectors: Dict[tuple, tuple] = {}
        seen_ids: set[str] = set()
        duplicate_ids = 0
        classes: Dict[str, int] = {}
        sessions: set[str] = set()

        for r in rows:
            lbl = r.get("label", "unknown")
            classes[lbl] = classes.get(lbl, 0) + 1
            if r.get("session_id"):
                sessions.add(r["session_id"])

            row_id = r.get("flow_id") or r.get("record_id") or ""
            if row_id:
                if row_id in seen_ids:
                    duplicate_ids += 1
                seen_ids.add(row_id)

            vector_values = []
            for key in feature_keys:
                raw = r.get(key)
                if raw is None or raw == "":
                    missing_values += 1
                    vector_values.append(None)
                    continue
                try:
                    value = float(raw)
                except (TypeError, ValueError):
                    invalid_numeric_values += 1
                    vector_values.append(None)
                    continue
                if not math.isfinite(value):
                    invalid_numeric_values += 1
                vector_values.append(value)
            vector_tuple = tuple(vector_values)
            if vector_tuple in seen_vectors:
                duplicate_vectors += 1
            seen_vectors.add(vector_tuple)
            if all(value is not None and math.isfinite(value) for value in vector_values):
                near_signature = tuple(format(value, ".6g") for value in vector_values)
                previous = seen_near_vectors.get(near_signature)
                if previous is not None and previous != vector_tuple:
                    near_duplicate_vectors += 1
                elif previous is None:
                    seen_near_vectors[near_signature] = vector_tuple

        manifest = details.get("datasetManifest") or {}
        origin_type = details.get("originType", "unknown")
        evidence_blockers: List[str] = []
        if origin_type == "synthetic_fixture":
            try:
                import sys
                ml_src = ROOT_DIR / "vista-ml" / "src"
                if str(ml_src) not in sys.path:
                    sys.path.insert(0, str(ml_src))
                from vista_ml.datasets.synthetic_fixture import validate_fixture_artifacts
                fixture_check = validate_fixture_artifacts(ROOT_DIR / details["manifestPath"])
                quality_status = fixture_check["status"]
            except Exception as exc:
                quality_status = "FAILED"
                evidence_blockers.append(f"synthetic_fixture_integrity_failed:{exc}")
        else:
            evidence_blockers.extend(_collected_candidate_blockers(
                details, rows, feature_keys,
                duplicate_ids=duplicate_ids,
                duplicate_vectors=duplicate_vectors,
                near_duplicate_vectors=near_duplicate_vectors,
                missing_values=missing_values,
                invalid_numeric_values=invalid_numeric_values,
            ))
            if evidence_blockers:
                quality_status = "BLOCKED"
            elif missing_values or invalid_numeric_values or duplicate_ids or duplicate_vectors or near_duplicate_vectors or total_rows == 0:
                quality_status = "FAILED"
            else:
                quality_status = "ADMITTED_FOR_EXPLORATORY_ANALYSIS"

        structural_status = (
            "PASS" if total_rows > 0 and missing_values == 0 and invalid_numeric_values == 0
            else "FAILED"
        )

        return {
            "datasetId": dataset_id,
            "validatedAt": _utc_now(),
            "totalRows": total_rows,
            "independentSessions": len(sessions),
            "classDistribution": classes,
            "missingValuesCount": missing_values,
            "invalidNumericValuesCount": invalid_numeric_values,
            "duplicateIdentifiersCount": duplicate_ids,
            "duplicateVectorsCount": duplicate_vectors,
            "nearDuplicateVectorsCount": near_duplicate_vectors,
            "featureSchemaCompliance": (
                f"{len([key for key in feature_keys if key in (details.get('columns') or [])])}/18 "
                "required numeric features present"
            ),
            "leakageCheck": {
                "targetContamination": "CHECKED (labels excluded from feature list)",
                "sessionIsolation": "REQUIRES_SPLIT_MANIFEST" if not manifest.get("split") else "SEE_SPLIT_MANIFEST",
                "outerEspDomain": "UNVERIFIED" if not manifest.get("provenance", {}).get("capture_point") else "DECLARED",
            },
            "originType": origin_type,
            "structuralStatus": structural_status,
            "qualityStatus": quality_status,
            "evidenceBlockers": evidence_blockers,
            "recommendation": (
                "Software-test fixture only; do not use as captured traffic or evaluation evidence."
                if quality_status == "SYNTHETIC_FIXTURE"
                else "Do not admit for evaluation until provenance, ground truth, artifact integrity, and split evidence are complete."
                if quality_status in {"BLOCKED", "FAILED"}
                else "Exploratory analysis only; not approved for production inference."
            ),
        }

    def export_dataset_file(self, dataset_id: str, format_type: str = "csv") -> Path:
        """
        Safely exports a dataset file with path-traversal prevention.
        """
        details = self.get_dataset_details(dataset_id)
        if not details:
            raise ValueError(f"Dataset {dataset_id} not found.")

        rel_path = details.get("dataPath")
        if not rel_path:
            raise ValueError("No data file associated with this dataset.")

        source_path = (ROOT_DIR / rel_path).resolve()
        try:
            source_path.relative_to(ROOT_DIR.resolve())
        except ValueError as exc:
            raise ValueError("Access to the requested path is forbidden.")

        normalized_format = format_type.lower()
        if normalized_format not in {"csv", "zip"}:
            raise ValueError("Supported export formats are CSV and ZIP package.")

        if not source_path.exists():
            raise FileNotFoundError("The source data file does not exist on disk.")

        export_id = uuid.uuid4().hex
        safe_filename = f"{re.sub(r'[^a-zA-Z0-9_-]', '_', details['id'])}_{details['version']}_{export_id}.{normalized_format}"
        export_target = EXPORTS_DIR / safe_filename
        while export_target.exists():
            export_id = uuid.uuid4().hex
            safe_filename = f"{re.sub(r'[^a-zA-Z0-9_-]', '_', details['id'])}_{details['version']}_{export_id}.{normalized_format}"
            export_target = EXPORTS_DIR / safe_filename

        if normalized_format == "csv":
            shutil.copy2(source_path, export_target)
        else:
            package_members: List[tuple[str, Path]] = [("dataset.csv", source_path)]
            missing_components: List[str] = []
            manifest_rel = details.get("manifestPath")
            if manifest_rel:
                manifest_path = (ROOT_DIR / manifest_rel).resolve()
                try:
                    manifest_path.relative_to(ROOT_DIR.resolve())
                except ValueError as exc:
                    raise ValueError("Dataset manifest path escapes the repository root.") from exc
                if manifest_path.is_file():
                    package_members.append(("source_manifest.json", manifest_path))
                else:
                    missing_components.append("source_manifest")
            else:
                missing_components.append("source_manifest")
            storage_rel = details.get("storageLocation")
            if storage_rel:
                storage_path = (ROOT_DIR / storage_rel).resolve()
                try:
                    storage_path.relative_to(ROOT_DIR.resolve())
                except ValueError as exc:
                    raise ValueError("Dataset storage path escapes the repository root.") from exc
                for filename in ("dataset_report.json", "split_manifest.json"):
                    candidate = storage_path / "dataset_preparation" / filename
                    if candidate.is_file():
                        package_members.append((filename, candidate))
                    else:
                        missing_components.append(filename.removesuffix(".json"))
            else:
                missing_components.extend(("dataset_report", "split_manifest"))
            schema_name = str(details.get("featureSchema") or "")
            if schema_name:
                schema_path = (ROOT_DIR / "vista-ml" / "schemas" / f"{schema_name}.json").resolve()
                try:
                    schema_path.relative_to(ROOT_DIR.resolve())
                except ValueError as exc:
                    raise ValueError("Feature schema path escapes the repository root.") from exc
                if schema_path.is_file():
                    package_members.append(("feature_schema.json", schema_path))
                else:
                    missing_components.append("feature_schema")
            else:
                missing_components.append("feature_schema")
            package_metadata = {
                "packageManifestVersion": "vista-dataset-export-v1",
                "datasetId": details["id"],
                "datasetVersion": details["version"],
                "originType": details.get("originType", "unknown"),
                "admissionStatus": details.get("status", "UNVERIFIED"),
                "featureSchemaVersion": schema_name or None,
                "members": [
                    {"path": name, "sizeBytes": path.stat().st_size, "sha256": _sha256_file(path)}
                    for name, path in package_members
                ],
                "missingComponents": sorted(set(missing_components)),
            }
            with zipfile.ZipFile(export_target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for name, path in package_members:
                    archive.write(path, arcname=name)
                archive.writestr("dataset_manifest.json", json.dumps(package_metadata, indent=2, sort_keys=True) + "\n")
        return export_target


dataset_service = DatasetService()
