"""
VISTA Dataset Generator (V2 - Upgraded)
=======================================
Implements the revised VISTA data generation architecture:
1. Fixes unit calculation for byte_rate vs bit_rate (byte_rate_Bps & bit_rate_bps).
2. Introduces realistic flow dynamics (log-normal IATs, packet jitter, decoupled duration/counts).
3. Adds 5 key VISTA attack scenarios (PORT_SCAN, DOS_FLOOD, BRUTE_FORCE, C2_BEACONING, DATA_EXFILTRATION).
4. Adds eBPF-observable telemetry features for multi-layer correlation.
5. Implements the Rule-Based Security Posture Engine (NIST SP 800-77 Rev. 1 & BSI guidelines).
6. Preserves session_id and spi/esp_spi correlation keys across all generated datasets.
"""

import random
from pathlib import Path
import numpy as np
import pandas as pd


def compute_security_posture(enc: str, auth: str, dh: int, pfs: int, replay_prot: int, key_life: int) -> tuple[int, str, list[str]]:
    """
    Deterministic Rule-Based Security Posture Engine.
    Evaluates cryptographic and operational security according to:
    - NIST SP 800-77 Rev. 1 (Guide to IPsec VPNs)
    - RFC 4301 / RFC 7296 (IPsec architecture and IKEv2)
    - BSI TR-02102-3 Cryptographic Mechanisms recommendation.
    """
    risk_score = 0
    vulns = []

    # 1. Cipher evaluation
    if enc == "3DES":
        risk_score += 40
        vulns.append("Sweet32_Vulnerable_Cipher(3DES)")
    elif enc == "AES-CBC-128":
        risk_score += 10
        vulns.append("Legacy_CBC_Mode_Padding_Oracle_Risk")

    # 2. Integrity / HMAC evaluation
    if auth in ["MD5", "SHA1"]:
        risk_score += 30
        vulns.append(f"Cryptographically_Broken_HMAC({auth})")

    # 3. Diffie-Hellman Key Exchange group
    if dh in [2, 5]:
        risk_score += 25
        vulns.append(f"Sub_2048bit_DH_Group_MODP{1024 if dh == 2 else 1536}")

    # 4. Perfect Forward Secrecy (PFS)
    if pfs == 0:
        risk_score += 15
        vulns.append("PFS_Disabled_Key_Compromise_Exposure")

    # 5. Anti-Replay Window Protection
    if replay_prot == 0:
        risk_score += 25
        vulns.append("Anti_Replay_Protection_Disabled")

    # 6. Key Lifetime / Rekey interval exposure
    if key_life > 28800:
        risk_score += 10
        vulns.append("Excessive_Key_Lifetime_Rekey_Exposure")

    # Compliance categorization
    if risk_score >= 45:
        compliance_status = "High_Risk"
    elif risk_score >= 20:
        compliance_status = "Medium_Risk"
    else:
        compliance_status = "Secure_Compliant"

    return risk_score, compliance_status, vulns


def generate_vista_datasets(
    num_sessions: int = 1000,
    flows_per_session_range: tuple[int, int] = (3, 8),
    attack_ratio: float = 0.25,
    random_seed: int = 42,
    output_dir: str = ".",
):
    """
    Generates correlated VISTA datasets:
    1. ipsec_security_audit.csv -> Session-level security configuration & posture score.
    2. ipsec_traffic_classification.csv -> Flow-level side-channel & attack features.
    3. vista_correlated_sessions.csv -> Unified session-flow correlation matrix.
    """
    np.random.seed(random_seed)
    random.seed(random_seed)

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    ciphers = ["3DES", "AES-CBC-128", "AES-CBC-256", "AES-GCM-128", "AES-GCM-256"]
    hashes = ["MD5", "SHA1", "SHA256", "SHA512"]
    dh_groups = [2, 5, 14, 19, 20]
    lifetimes = [1800, 3600, 7200, 14400, 28800, 86400]

    # Application Profiles (Normal Traffic - Realistic overlapping network characteristics)
    app_profiles = {
        "VoIP": {
            "mean_len": 150, "std_len": 45, "len_bounds": (60, 320),
            "iat_loc": -3.2, "iat_scale": 0.55, "duration_range": (10, 120), "out_ratio": 0.50,
            "pkt_rate_range": (20, 55), "ebpf_mult": 1.0,
        },
        "Video_Streaming": {
            "mean_len": 1280, "std_len": 240, "len_bounds": (300, 1500),
            "iat_loc": -3.5, "iat_scale": 0.70, "duration_range": (20, 300), "out_ratio": 0.12,
            "pkt_rate_range": (50, 200), "ebpf_mult": 1.3,
        },
        "Web_Browsing": {
            "mean_len": 720, "std_len": 460, "len_bounds": (64, 1480),
            "iat_loc": -1.2, "iat_scale": 0.95, "duration_range": (5, 90), "out_ratio": 0.35,
            "pkt_rate_range": (8, 50), "ebpf_mult": 1.1,
        },
        "WhatsApp": {
            "mean_len": 320, "std_len": 220, "len_bounds": (64, 850),
            "iat_loc": -0.4, "iat_scale": 0.90, "duration_range": (8, 180), "out_ratio": 0.46,
            "pkt_rate_range": (3, 22), "ebpf_mult": 0.9,
        },
        "Email_IMAP": {
            "mean_len": 780, "std_len": 410, "len_bounds": (80, 1460),
            "iat_loc": -0.8, "iat_scale": 0.80, "duration_range": (4, 60), "out_ratio": 0.52,
            "pkt_rate_range": (4, 30), "ebpf_mult": 0.95,
        },
        "ICMP": {
            "mean_len": 105, "std_len": 25, "len_bounds": (70, 180),
            "iat_loc": -0.1, "iat_scale": 0.35, "duration_range": (3, 30), "out_ratio": 0.50,
            "pkt_rate_range": (1, 8), "ebpf_mult": 0.6,
        },
    }

    # Attack Profiles (Realistic stealthy and overlapping IPsec attack scenarios)
    attack_profiles = {
        "PORT_SCAN": {
            "mean_len": 95, "std_len": 30, "len_bounds": (60, 200),
            "iat_loc": -3.8, "iat_scale": 0.60, "duration_range": (2, 20), "out_ratio": 0.80,
            "pkt_rate_range": (80, 300), "ebpf_mult": 2.6,
        },
        "DOS_FLOOD": {
            "mean_len": 130, "std_len": 40, "len_bounds": (64, 300),
            "iat_loc": -5.2, "iat_scale": 0.45, "duration_range": (5, 45), "out_ratio": 0.92,
            "pkt_rate_range": (400, 1600), "ebpf_mult": 4.2,
        },
        "BRUTE_FORCE": {
            "mean_len": 260, "std_len": 110, "len_bounds": (80, 550),
            "iat_loc": -2.0, "iat_scale": 0.65, "duration_range": (8, 60), "out_ratio": 0.62,
            "pkt_rate_range": (15, 65), "ebpf_mult": 1.9,
        },
        "C2_BEACONING": {
            "mean_len": 210, "std_len": 80, "len_bounds": (70, 420),
            "iat_loc": 1.2, "iat_scale": 0.50, "duration_range": (60, 400), "out_ratio": 0.54,
            "pkt_rate_range": (0.3, 2.5), "ebpf_mult": 1.1,
        },
        "DATA_EXFILTRATION": {
            "mean_len": 1320, "std_len": 180, "len_bounds": (800, 1500),
            "iat_loc": -3.8, "iat_scale": 0.50, "duration_range": (20, 180), "out_ratio": 0.89,
            "pkt_rate_range": (70, 260), "ebpf_mult": 2.9,
        },
    }

    security_records = []
    traffic_records = []
    correlated_records = []
    global_flow_id = 1

    for session_idx in range(1, num_sessions + 1):
        session_id = f"VPN-SES-{session_idx:05d}"
        spi = hex(random.randint(0x10000000, 0xFFFFFFFF))

        # --- DATASET 1: CONTROL PLANE CONFIGURATION ---
        ike_ver = random.choices([1, 2], weights=[0.25, 0.75])[0]
        mode = random.choices(["Tunnel", "Transport"], weights=[0.70, 0.30])[0]
        ip_ver = random.choices(["IPv4", "IPv6"], weights=[0.85, 0.15])[0]
        enc = random.choices(ciphers, weights=[0.08, 0.22, 0.30, 0.20, 0.20])[0]
        auth = "Combined-AEAD" if "GCM" in enc else random.choices(hashes, weights=[0.08, 0.12, 0.55, 0.25])[0]
        dh = random.choices(dh_groups, weights=[0.10, 0.10, 0.40, 0.20, 0.20])[0]
        pfs = random.choices([0, 1], weights=[0.30, 0.70])[0]
        replay_prot = random.choices([0, 1], weights=[0.05, 0.95])[0]
        key_life = random.choice(lifetimes)

        # Execute Posture Engine
        risk_score, compliance_status, vulns = compute_security_posture(
            enc=enc, auth=auth, dh=dh, pfs=pfs, replay_prot=replay_prot, key_life=key_life
        )
        vulnerability_str = "|".join(vulns) if vulns else "No_Vulnerabilities"

        sec_entry = {
            "session_id": session_id,
            "spi": spi,
            "ip_version": ip_ver,
            "ike_version": ike_ver,
            "ipsec_mode": mode,
            "encryption_algo": enc,
            "auth_algo": auth,
            "dh_group": dh,
            "pfs_enabled": pfs,
            "anti_replay": replay_prot,
            "key_lifetime_sec": key_life,
            "risk_score": risk_score,
            "compliance_status": compliance_status,
            "vulnerabilities_detected": vulnerability_str,
        }
        security_records.append(sec_entry)

        # --- DATASET 2: ENCRYPTED DATA PLANE FLOWS ---
        num_flows = random.randint(*flows_per_session_range)
        for _ in range(num_flows):
            flow_id = f"FLW-{global_flow_id:07d}"
            global_flow_id += 1

            # Decide whether this flow is benign or an attack
            is_attack = random.random() < attack_ratio
            if is_attack:
                attack_type = random.choice(list(attack_profiles.keys()))
                traffic_type = "Attack"
                spec = attack_profiles[attack_type]
            else:
                attack_type = "BENIGN"
                traffic_type = random.choice(list(app_profiles.keys()))
                spec = app_profiles[traffic_type]

            # Generate dynamic flow attributes with realistic jitter
            duration = round(random.uniform(*spec["duration_range"]) * np.random.uniform(0.7, 1.3), 2)
            duration = max(1.0, duration)
            base_pkt_rate = random.uniform(*spec["pkt_rate_range"])
            pkt_count = max(8, int(duration * base_pkt_rate * np.random.uniform(0.75, 1.35)))

            # Side-channel packet length features (natural continuous distributions with realistic variance)
            mean_len = round(np.clip(np.random.normal(spec["mean_len"], spec["std_len"] * 0.45), spec["len_bounds"][0], spec["len_bounds"][1]), 2)
            std_len = round(max(4.0, np.random.normal(spec["std_len"], spec["std_len"] * 0.25)), 2)
            min_len = int(max(40, mean_len - np.random.uniform(1.2, 2.2) * std_len))
            max_len = int(min(1500, mean_len + np.random.uniform(1.2, 2.2) * std_len))

            # Side-channel timing features (log-normal distribution with per-flow latency jitter)
            flow_iat_loc = spec["iat_loc"] + float(np.random.normal(0, 0.40))
            flow_iat_scale = max(0.15, spec["iat_scale"] + float(np.random.normal(0, 0.12)))
            iat_samples = np.random.lognormal(flow_iat_loc, flow_iat_scale, size=min(120, pkt_count))
            mean_iat = round(float(np.mean(iat_samples)), 6)
            std_iat = round(float(np.std(iat_samples)), 6)

            # Directionality with realistic noise
            out_ratio = round(np.clip(np.random.normal(spec["out_ratio"], 0.08), 0.02, 0.98), 3)

            # Realistic packet length total bytes with header & MTU variations
            total_bytes = int(pkt_count * mean_len * np.random.uniform(0.90, 1.10))

            # Byte Rate vs Bit Rate calculation
            byte_rate_Bps = round(total_bytes / duration, 2)
            bit_rate_bps = round((total_bytes * 8.0) / duration, 2)

            # eBPF / Kernel Side-Channel Telemetry Simulation (natural overlap)
            ebpf_events = max(1, int(pkt_count * spec["ebpf_mult"] * np.random.uniform(0.75, 1.35) + np.random.normal(5, 3)))
            # Packet loss and buffer drops happen in normal high-bandwidth flows too
            is_high_volume = (base_pkt_rate > 80)
            socket_buffer_drops = int(np.random.poisson(lam=2.5 if attack_type == "DOS_FLOOD" else (0.5 if is_high_volume else 0.08)))
            # Network retransmissions naturally occur on lossy channels for both benign and attack flows
            tcp_retrans_count = int(np.random.poisson(lam=2.2 if is_attack else 0.8))

            flow_entry = {
                "flow_id": flow_id,
                "session_id": session_id,
                "esp_spi": spi,
                "flow_duration_sec": duration,
                "packet_count": pkt_count,
                "total_bytes": total_bytes,
                "byte_rate_Bps": byte_rate_Bps,
                "byte_rate_bps": bit_rate_bps,  # Maintained key name for backward compatibility, now mathematically bits/sec
                "bit_rate_bps": bit_rate_bps,
                "mean_packet_length": mean_len,
                "std_packet_length": std_len,
                "min_packet_length": min_len,
                "max_packet_length": max_len,
                "mean_iat_sec": mean_iat,
                "std_iat_sec": std_iat,
                "outbound_bytes_ratio": out_ratio,
                "traffic_type": traffic_type,
                "attack_type": attack_type,
                "is_attack": int(is_attack),
                "ebpf_event_count": ebpf_events,
                "socket_buffer_drops": socket_buffer_drops,
                "tcp_retrans_count": tcp_retrans_count,
            }
            traffic_records.append(flow_entry)

            # Correlated View (for Multi-Layer Security Analytics & XAI)
            correlated_entry = {**sec_entry, **flow_entry}
            correlated_records.append(correlated_entry)

    df_security = pd.DataFrame(security_records)
    df_traffic = pd.DataFrame(traffic_records)
    df_correlated = pd.DataFrame(correlated_records)

    sec_file = output_path / "ipsec_security_audit_v2.csv"
    traffic_file = output_path / "ipsec_traffic_classification_v2.csv"
    corr_file = output_path / "vista_correlated_sessions_v2.csv"

    df_security.to_csv(sec_file, index=False)
    df_traffic.to_csv(traffic_file, index=False)
    df_correlated.to_csv(corr_file, index=False)

    print("=" * 65)
    print("VISTA Datasets Generated Successfully (V2 Upgraded):")
    print(f"1. {sec_file.name}       -> {len(df_security)} sessions (Posture audit)")
    print(f"2. {traffic_file.name}   -> {len(df_traffic)} flows (Encrypted + Attack)")
    print(f"3. {corr_file.name}      -> {len(df_correlated)} correlated session-flows")
    print("=" * 65)
    print("Traffic distribution:\n", df_traffic['traffic_type'].value_counts())
    print("-" * 65)
    print("Attack distribution:\n", df_traffic['attack_type'].value_counts())
    print("=" * 65)


if __name__ == "__main__":
    generate_vista_datasets(num_sessions=1000, output_dir=".")
