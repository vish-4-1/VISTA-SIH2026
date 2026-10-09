"""
VISTA Security Posture & Compliance Assessment Engine
Deterministic rule evaluation compliant with NIST SP 800-77 Rev. 1,
NIST SP 800-52 Rev. 2, and BSI TR-02102-3.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT_DIR = Path(__file__).resolve().parents[2]
SCENARIO_AUDITS_JSON_PATH = ROOT_DIR / "vista-dashboard" / "src" / "data" / "realAudits.json"


class PostureEngine:
    def __init__(self) -> None:
        self._cached_audits: Optional[List[Dict[str, Any]]] = None

    def get_audit_sessions(self) -> List[Dict[str, Any]]:
        """Returns operational audit sessions; no operational source is configured yet."""
        return []

    def evaluate_sessions(self, sessions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Returns recalculated posture results for explicitly supplied audit inputs."""
        return [self.evaluate_session(session) for session in sessions]

    def get_scenario_audit_sessions(self) -> List[Dict[str, Any]]:
        """Loads generated scenario records for explicit offline evaluation only."""
        if self._cached_audits is not None:
            return self._cached_audits
        if SCENARIO_AUDITS_JSON_PATH.exists():
            try:
                self._cached_audits = json.loads(SCENARIO_AUDITS_JSON_PATH.read_text(encoding="utf-8"))
                return self._cached_audits
            except Exception as err:
                raise RuntimeError(f"Failed to read scenario audit records from {SCENARIO_AUDITS_JSON_PATH}.") from err
        return []

    def evaluate_session(self, session: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluates a single session against NIST SP 800-77 guidelines and assigns
        a deterministic risk score and list of vulnerabilities.
        """
        enc_value = session.get("encryption")
        auth_value = session.get("auth")
        dh = session.get("dhGroup")
        try:
            dh = int(dh)
        except (ValueError, TypeError):
            dh = None
        pfs = session.get("pfs")
        anti_replay = session.get("antiReplay")
        lifetime = session.get("lifetime")
        try:
            lifetime = int(lifetime)
        except (ValueError, TypeError):
            lifetime = None
        ike_ver = session.get("ikeVersion")
        try:
            ike_ver = int(ike_ver)
        except (ValueError, TypeError):
            ike_ver = None

        missing_fields = [
            name for name, value in (
                ("encryption", enc_value),
                ("auth", auth_value),
                ("dhGroup", dh),
                ("pfs", pfs),
                ("antiReplay", anti_replay),
                ("lifetime", lifetime),
                ("ikeVersion", ike_ver),
            )
            if value is None or value == ""
        ]
        if not isinstance(pfs, bool):
            missing_fields.append("pfs")
        if not isinstance(anti_replay, bool):
            missing_fields.append("antiReplay")
        if missing_fields:
            return {
                "sessionId": session.get("sessionId"),
                "spi": session.get("spi"),
                "ipVersion": session.get("ipVersion"),
                "ikeVersion": ike_ver,
                "mode": session.get("mode"),
                "encryption": enc_value,
                "auth": auth_value,
                "dhGroup": dh,
                "pfs": pfs if isinstance(pfs, bool) else None,
                "antiReplay": anti_replay if isinstance(anti_replay, bool) else None,
                "lifetime": lifetime,
                "riskScore": None,
                "securityScore": None,
                "compliance": "Insufficient Data",
                "vulnerabilities": [],
                "missingFields": sorted(set(missing_fields)),
            }

        enc = str(enc_value).upper()
        auth = str(auth_value).upper()

        risk_score = 0
        vulnerabilities: List[str] = []

        # Cipher evaluation
        if "3DES" in enc or "DES" in enc:
            risk_score += 45
            vulnerabilities.append("Broken_Symmetric_Cipher(3DES)_Sweet32_Vulnerability")
        elif "CBC" in enc:
            risk_score += 20
            vulnerabilities.append("Legacy_CBC_Mode_Padding_Oracle_Risk")
            if "128" in enc:
                risk_score += 5
        elif "GCM" not in enc and "CHACHA" not in enc:
            risk_score += 15
            vulnerabilities.append("Non_AEAD_Cipher_Suite")

        # Integrity / HMAC evaluation
        if "MD5" in auth:
            risk_score += 35
            vulnerabilities.append("Cryptographically_Broken_HMAC(MD5)")
        elif "SHA1" in auth:
            risk_score += 25
            vulnerabilities.append("Cryptographically_Deprecated_HMAC(SHA1)")
        elif "SHA" not in auth and "GCM" not in enc:
            risk_score += 15
            vulnerabilities.append("Weak_Integrity_Algorithm")

        # DH Group evaluation
        if dh in [1, 2, 5]:
            risk_score += 30
            vulnerabilities.append(f"Sub_2048bit_DH_Group_MODP{dh * 512 if dh <= 2 else 1536}")
        elif dh < 14 and dh not in [19, 20, 21]:
            risk_score += 15
            vulnerabilities.append("DH_Group_Below_NIST_Recommended_2048bit")

        # Perfect Forward Secrecy
        if not pfs:
            risk_score += 15
            vulnerabilities.append("PFS_Disabled_Key_Compromise_Retroactive_Decryption")

        # Anti-Replay
        if not anti_replay:
            risk_score += 25
            vulnerabilities.append("Anti_Replay_Protection_Disabled_Replay_Attack_Risk")

        # SA Lifetime
        if lifetime > 28800:
            risk_score += 10
            vulnerabilities.append("Excessive_SA_Lifetime_Exceeds_NIST_8h_Limit")

        # IKE version
        if ike_ver == 1:
            risk_score += 15
            vulnerabilities.append("Legacy_IKEv1_Aggressive_Mode_Pre_Shared_Key_Exposure")

        risk_score = min(100, risk_score)

        if risk_score <= 15:
            compliance = "Compliant"
        elif risk_score <= 35:
            compliance = "Low Risk"
        elif risk_score <= 65:
            compliance = "Medium Risk"
        else:
            compliance = "High Risk"

        return {
            "sessionId": session.get("sessionId"),
            "spi": session.get("spi"),
            "ipVersion": session.get("ipVersion"),
            "ikeVersion": ike_ver,
            "mode": session.get("mode"),
            "encryption": enc_value,
            "auth": auth_value,
            "dhGroup": dh,
            "pfs": pfs,
            "antiReplay": anti_replay,
            "lifetime": lifetime,
            "riskScore": risk_score,
            "securityScore": max(0, 100 - risk_score),
            "compliance": compliance,
            "vulnerabilities": vulnerabilities,
        }

    def compute_summary_posture(self, sessions: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """
        Calculates aggregate security score, compliance rates, and vulnerability distribution.
        """
        items = sessions if sessions is not None else self.get_audit_sessions()
        if not items:
            return {
                "overallScore": None,
                "totalSessions": 0,
                "assessedSessions": 0,
                "insufficientDataCount": 0,
                "compliantCount": 0,
                "highRiskCount": 0,
                "mediumRiskCount": 0,
                "compliancePercentage": None,
                "aeadAdoptionRate": None,
                "strongCipherRate": None,
                "strongAuthRate": None,
                "pfsAdoptionRate": None,
                "antiReplayEnforcedRate": None,
                "strongDhRate": None,
                "lifetimeCompliantRate": None,
                "source": "No operational audit source configured",
            }

        def numeric_value(value: Any) -> Optional[float]:
            if isinstance(value, bool) or value is None:
                return None
            try:
                number = float(value)
            except (TypeError, ValueError):
                return None
            return number if math.isfinite(number) else None

        def rate_for(field: str, predicate, valid=lambda value: value not in (None, "")) -> Optional[float]:
            observed = [
                session[field] for session in items
                if valid(session.get(field))
            ]
            if not observed:
                return None
            return round(sum(1 for value in observed if predicate(value)) / len(observed) * 100, 1)

        def has_evaluation_inputs(session: Dict[str, Any]) -> bool:
            if any(session.get(field) in (None, "") for field in (
                "encryption", "auth", "dhGroup", "pfs", "antiReplay", "lifetime", "ikeVersion",
            )):
                return False
            if not isinstance(session.get("pfs"), bool) or not isinstance(session.get("antiReplay"), bool):
                return False
            return all(numeric_value(session.get(field)) is not None for field in ("dhGroup", "lifetime", "ikeVersion"))

        scored_items = []
        for session in items:
            if not has_evaluation_inputs(session):
                continue
            evaluation = self.evaluate_session(session)
            risk_score = numeric_value(evaluation.get("riskScore"))
            if risk_score is None:
                continue
            scored_items.append({
                "riskScore": risk_score,
                "compliance": evaluation.get("compliance"),
            })
        compliance_items = [
            session for session in scored_items
            if session.get("compliance") not in (None, "")
            and str(session["compliance"]).lower() != "insufficient data"
        ]
        scores = [max(0, 100 - session["riskScore"]) for session in scored_items]
        mean_score = round(float(sum(scores) / len(scores)), 1) if scores else None

        compliant = sum(
            1 for session in compliance_items
            if str(session["compliance"]).strip().lower()
            in {"compliant", "secure compliant", "low risk"}
        )
        medium = sum(1 for session in compliance_items if "medium" in str(session["compliance"]).lower())
        high = sum(
            1 for session in compliance_items
            if "high" in str(session["compliance"]).lower()
            or "critical" in str(session["compliance"]).lower()
        )

        dh_rate = rate_for(
            "dhGroup",
            lambda value: numeric_value(value) is not None and numeric_value(value) >= 14,
            lambda value: numeric_value(value) is not None,
        )
        lifetime_rate = rate_for(
            "lifetime",
            lambda value: numeric_value(value) is not None and numeric_value(value) <= 28800,
            lambda value: numeric_value(value) is not None,
        )
        strong_auth_rate = rate_for(
            "auth",
            lambda value: (
                "AEAD" in str(value).upper()
                or (
                    "SHA" in str(value).upper()
                    and "SHA1" not in str(value).upper()
                    and "MD5" not in str(value).upper()
                )
            ),
            lambda value: isinstance(value, str) and bool(value.strip()),
        )

        return {
            "overallScore": mean_score,
            "totalSessions": len(items),
            "assessedSessions": len(scored_items),
            "insufficientDataCount": len(items) - len(scored_items),
            "compliantCount": compliant,
            "mediumRiskCount": medium,
            "highRiskCount": high,
            "compliancePercentage": (
                round((compliant / len(compliance_items)) * 100, 1)
                if compliance_items else None
            ),
            "aeadAdoptionRate": rate_for(
                "encryption", lambda value: "GCM" in str(value).upper(),
            ),
            "strongCipherRate": rate_for(
                "encryption",
                lambda value: "GCM" in str(value).upper() or "256" in str(value).upper(),
            ),
            "strongAuthRate": strong_auth_rate,
            "pfsAdoptionRate": rate_for(
                "pfs", lambda value: value is True, lambda value: isinstance(value, bool),
            ),
            "antiReplayEnforcedRate": rate_for(
                "antiReplay", lambda value: value is True, lambda value: isinstance(value, bool),
            ),
            "strongDhRate": dh_rate,
            "lifetimeCompliantRate": lifetime_rate,
            "source": "Supplied audit records",
        }


posture_engine = PostureEngine()
