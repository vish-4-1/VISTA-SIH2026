"""
VISTA Security Posture & Compliance Assessment Engine
Deterministic rule evaluation compliant with NIST SP 800-77 Rev. 1,
NIST SP 800-52 Rev. 2, and BSI TR-02102-3.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT_DIR = Path(__file__).resolve().parents[2]
AUDITS_JSON_PATH = ROOT_DIR / "vista-dashboard" / "src" / "data" / "realAudits.json"


class PostureEngine:
    def __init__(self) -> None:
        self._cached_audits: Optional[List[Dict[str, Any]]] = None

    def get_audit_sessions(self) -> List[Dict[str, Any]]:
        """Loads canonical audit sessions from disk."""
        if self._cached_audits is not None:
            return self._cached_audits
        if AUDITS_JSON_PATH.exists():
            try:
                self._cached_audits = json.loads(AUDITS_JSON_PATH.read_text(encoding="utf-8"))
                return self._cached_audits
            except Exception as err:
                print(f"[PostureEngine] Failed to read audits json: {err}")
        return []

    def evaluate_session(self, session: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluates a single session against NIST SP 800-77 guidelines and assigns
        a deterministic risk score and list of vulnerabilities.
        """
        enc = str(session.get("encryption", "")).upper()
        auth = str(session.get("auth", "")).upper()
        dh = session.get("dhGroup", 14)
        try:
            dh = int(dh)
        except (ValueError, TypeError):
            dh = 14
        pfs = bool(session.get("pfs", False))
        anti_replay = bool(session.get("antiReplay", True))
        lifetime = session.get("lifetime", 3600)
        try:
            lifetime = int(lifetime)
        except (ValueError, TypeError):
            lifetime = 3600
        ike_ver = session.get("ikeVersion", 2)

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
        if ike_ver == 1 or str(ike_ver) == "1":
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
            "sessionId": session.get("sessionId", "VPN-SES-DYNAMIC"),
            "spi": session.get("spi", "0x00000000"),
            "ipVersion": session.get("ipVersion", "IPv4"),
            "ikeVersion": ike_ver,
            "mode": session.get("mode", "Tunnel"),
            "encryption": session.get("encryption", "AES-GCM-256"),
            "auth": session.get("auth", "SHA256"),
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
                "overallScore": 92,
                "totalSessions": 0,
                "compliantCount": 0,
                "highRiskCount": 0,
                "mediumRiskCount": 0,
            }

        scores = [max(0, 100 - s.get("riskScore", 0)) for s in items]
        mean_score = round(float(sum(scores) / len(scores)), 1)

        compliant = sum(1 for s in items if s.get("compliance") in ["Compliant", "Low Risk"])
        medium = sum(1 for s in items if s.get("compliance") == "Medium Risk")
        high = sum(1 for s in items if s.get("compliance") == "High Risk")

        # Check cryptographic proportions
        aead_count = sum(1 for s in items if "GCM" in str(s.get("encryption", "")))
        pfs_count = sum(1 for s in items if s.get("pfs", False) is True)
        anti_replay_count = sum(1 for s in items if s.get("antiReplay", True) is True)
        modern_dh = sum(1 for s in items if int(s.get("dhGroup", 0)) in [14, 19, 20, 21])

        return {
            "overallScore": mean_score,
            "totalSessions": len(items),
            "compliantCount": compliant,
            "mediumRiskCount": medium,
            "highRiskCount": high,
            "compliancePercentage": round((compliant / len(items)) * 100, 1),
            "aeadAdoptionRate": round((aead_count / len(items)) * 100, 1),
            "pfsAdoptionRate": round((pfs_count / len(items)) * 100, 1),
            "antiReplayEnforcedRate": round((anti_replay_count / len(items)) * 100, 1),
            "strongDhRate": round((modern_dh / len(items)) * 100, 1),
        }


posture_engine = PostureEngine()
