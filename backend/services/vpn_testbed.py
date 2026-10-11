from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

ROOT_DIR = Path(__file__).resolve().parents[2]
CONFIGS_DIR = ROOT_DIR / "configs"
CAPTURE_ROOT = ROOT_DIR / "captures" / "strongswan"

SUPPORTED_MODES = ("tunnel", "transport")
SUPPORTED_CIPHERS = {
    "aes128": {"size": 128, "esp_proposal": "aes128-sha256", "esp_encryption": "AES_CBC", "esp_integrity": "HMAC_SHA2_256_128"},
    "aes256": {"size": 256, "esp_proposal": "aes256-sha256", "esp_encryption": "AES_CBC", "esp_integrity": "HMAC_SHA2_256_128"},
    "aes128gcm16": {"size": 128, "esp_proposal": "aes128gcm16", "esp_encryption": "AES_GCM_16", "esp_integrity": None},
    "aes256gcm16": {"size": 256, "esp_proposal": "aes256gcm16", "esp_encryption": "AES_GCM_16", "esp_integrity": None},
    "aes128gcm": {"size": 128, "esp_proposal": "aes128gcm16", "esp_encryption": "AES_GCM_16", "esp_integrity": None},
    "aes256gcm": {"size": 256, "esp_proposal": "aes256gcm16", "esp_encryption": "AES_GCM_16", "esp_integrity": None},
}
SUPPORTED_DH_GROUPS = {
    14: "modp2048",
    15: "modp3072",
    19: "ecp256",
    20: "ecp384",
}
DH_GROUP_ALIASES = {
    "MODP_768": 1,
    "MODP_1024": 2,
    "MODP_1024_160": 5,
    "MODP_1536": 5,
    "MODP_2048": 14,
    "MODP_2048_224": 24,
    "MODP_2048_256": 25,
    "MODP_3072": 15,
    "MODP_4096": 16,
    "MODP_6144": 17,
    "MODP_8192": 18,
    "ECP_256": 19,
    "ECP_384": 20,
    "ECP_521": 21,
}
SUPPORTED_TRAFFIC_TYPES = {
    "icmpv4",
    "icmpv6",
    "udp_rtp",
    "voip",
    "http",
    "https",
    "smtp",
    "web_browsing",
    "video",
    "video_stream",
    "whatsapp",
    "messaging",
}
CIPHER_ALIASES = {
    "aes-128": "aes128",
    "aes128cbc": "aes128",
    "aes-128-cbc": "aes128",
    "aes-256": "aes256",
    "aes256cbc": "aes256",
    "aes-256-cbc": "aes256",
    "aes-128-gcm": "aes128gcm",
    "aes128gcm": "aes128gcm",
    "aes-128-gcm-16": "aes128gcm16",
    "aes-256-gcm": "aes256gcm",
    "aes256gcm": "aes256gcm",
    "aes-256-gcm-16": "aes256gcm16",
    "aes128gcm16": "aes128gcm16",
    "aes256gcm16": "aes256gcm16",
}
TRAFFIC_ALIASES = {
    "icmp4": "icmpv4",
    "icmpv4": "icmpv4",
    "icmp6": "icmpv6",
    "icmpv6": "icmpv6",
    "udp-rtp": "udp_rtp",
    "rtp": "udp_rtp",
    "voip": "udp_rtp",
    "web": "http",
    "http1": "http",
    "http1.1": "http",
    "https": "https",
    "web_browsing": "http",
    "smtp": "smtp",
    "email": "smtp",
    "video_stream": "video",
    "video": "video",
    "whatsapp": "whatsapp",
    "messaging": "whatsapp",
}


class StrongSwanExperimentError(RuntimeError):
    pass


@dataclass
class StrongSwanCapability:
    mode: str
    cipher: str
    dh_group: int
    pfs: bool
    ip_version: str
    traffic_type: str

    @property
    def normalized(self) -> Dict[str, Any]:
        return {
            "mode": self.mode,
            "cipher": self.cipher,
            "dhGroup": self.dh_group,
            "pfs": self.pfs,
            "ipVersion": self.ip_version,
            "trafficType": self.traffic_type,
        }


def _docker_path() -> str:
    docker = shutil.which("docker")
    if docker:
        return docker
    local_app_data = os.environ.get("LOCALAPPDATA", "")
    candidate = Path(local_app_data) / "Programs" / "DockerDesktop" / "resources" / "bin" / "docker.exe"
    if candidate.is_file():
        return str(candidate)
    raise FileNotFoundError("Docker CLI was not found on PATH or in the standard Docker Desktop installation location.")


def run_docker_command(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run([_docker_path(), *args], capture_output=True, text=True, check=check)


def _normalize_ip_version(value: str) -> str:
    if value is None:
        return "IPv4"
    v = str(value).strip().lower()
    if v in {"ipv4", "4"}:
        return "IPv4"
    if v in {"ipv6", "6"}:
        return "IPv6"
    raise ValueError(f"Unsupported IP version '{value}'. Use IPv4 or IPv6.")


def _normalize_cipher(value: Optional[str]) -> str:
    normalized = str(value or "aes256gcm16").strip().lower().replace("-", "").replace("_", "")
    canonical = CIPHER_ALIASES.get(normalized)
    if canonical is not None:
        return canonical
    return normalized


def _normalize_traffic_type(value: Optional[str]) -> str:
    normalized = str(value or "icmpv4").strip().lower().replace("-", "_").replace(" ", "_")
    canonical = TRAFFIC_ALIASES.get(normalized)
    if canonical is not None:
        return canonical
    return normalized


def inspect_runtime_capabilities() -> Dict[str, Any]:
    capabilities: Dict[str, Any] = {
        "docker": True,
        "containers": {
            "pc1": "missing",
            "pc2": "missing",
        },
        "ipv6": False,
        "supported_dh_groups": [],
        "configuration_mode_options": list(SUPPORTED_MODES),
        "configuration_cipher_options": list(SUPPORTED_CIPHERS),
        "algorithms": {},
    }

    for container in ("pc1", "pc2"):
        probe = run_docker_command("ps", "--format", "{{.Names}}", check=False)
        if probe.returncode == 0 and container in probe.stdout.splitlines():
            capabilities["containers"][container] = "running"

    for container in ("pc1", "pc2"):
        if capabilities["containers"][container] != "running":
            continue
        ip_cmd = run_docker_command("exec", container, "ip", "-6", "addr", "show", "scope", "global", check=False)
        if ip_cmd.returncode == 0 and re.search(r"inet6\s+[0-9a-fA-F:]+", ip_cmd.stdout):
            capabilities["ipv6"] = True
            break

    if capabilities["containers"]["pc1"] == "running":
        version = run_docker_command("exec", "pc1", "swanctl", "--version", check=False)
        capabilities["strongswan_version"] = version.stdout.strip() if version.returncode == 0 else None
        algs = run_docker_command("exec", "pc1", "swanctl", "--list-algs", check=False)
        if algs.returncode == 0:
            output = algs.stdout + "\n" + algs.stderr
            groups: set[int] = set()
            for group_name in re.findall(r"(?:MODP|ECP)_[A-Z0-9_]+", output, re.IGNORECASE):
                canonical = group_name.upper()
                if canonical in DH_GROUP_ALIASES:
                    groups.add(DH_GROUP_ALIASES[canonical])
            capabilities["supported_dh_groups"] = sorted(groups & set(SUPPORTED_DH_GROUPS.keys()))
            capabilities["algorithms"]["dh"] = capabilities["supported_dh_groups"]
            capabilities["algorithms"]["aes_cbc_transform"] = "AES_CBC" in output
            capabilities["algorithms"]["aes_gcm_transform"] = bool(re.search(r"AES_GCM", output, re.IGNORECASE))

    return capabilities


def validate_configuration(configuration: Dict[str, Any], runtime_capabilities: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    cfg = dict(configuration)
    mode = str(cfg.get("mode", "tunnel")).lower()
    cipher = _normalize_cipher(cfg.get("cipher", "aes256gcm16"))
    dh_group = cfg.get("dhGroup", 14)
    pfs_value = cfg.get("pfs", True)
    pfs = pfs_value if isinstance(pfs_value, bool) else False
    ip_version = _normalize_ip_version(cfg.get("ipVersion", "IPv4"))
    traffic_type = _normalize_traffic_type(cfg.get("trafficType", "icmpv4") or "icmpv4")
    issues: List[str] = []
    warnings: List[str] = []

    if mode not in SUPPORTED_MODES:
        issues.append(f"Mode '{mode}' is unsupported. Only {', '.join(SUPPORTED_MODES)} are supported.")

    if cipher not in SUPPORTED_CIPHERS:
        issues.append(
            f"Cipher '{cipher}' is unsupported. Supported values are {', '.join(sorted(SUPPORTED_CIPHERS.keys()))}."
        )

    try:
        dh_int = int(dh_group)
    except (TypeError, ValueError):
        issues.append(f"Invalid DH group '{dh_group}'.")
        dh_int = None

    if dh_int is not None:
        if dh_int not in SUPPORTED_DH_GROUPS:
            issues.append(
                f"DH group '{dh_group}' is not available in the configured strongSwan matrix. "
                f"Supported values are {sorted(SUPPORTED_DH_GROUPS)}."
            )
        elif runtime_capabilities is not None and dh_int not in runtime_capabilities.get("supported_dh_groups", []):
            issues.append(f"DH group '{dh_int}' is not available in the running strongSwan installation.")

    if ip_version == "IPv6":
        if runtime_capabilities is None:
            runtime_capabilities = inspect_runtime_capabilities()
        if not runtime_capabilities.get("ipv6", False):
            issues.append("IPv6 is not available on the current Docker network. The environment must provide IPv6 addresses before IPv6 testbed configuration is accepted.")

    if not isinstance(pfs_value, bool):
        issues.append("PFS must be provided as a boolean value.")

    if num_missing := len(issues):
        return {
            "valid": False,
            "issues": issues,
            "warnings": warnings,
            "configuration": {"mode": mode, "cipher": cipher, "dhGroup": dh_int, "pfs": pfs, "ipVersion": ip_version, "trafficType": traffic_type},
            "supportedFeatures": {
                "modes": list(SUPPORTED_MODES),
                "ciphers": list(SUPPORTED_CIPHERS),
                "dhGroups": sorted(SUPPORTED_DH_GROUPS),
            },
            "capabilityStatus": "invalid",
        }

    if traffic_type not in SUPPORTED_TRAFFIC_TYPES:
        warnings.append(f"Traffic type '{traffic_type}' is defined by the workload generator, but it is not a verified live workload on this testbed.")

    return {
        "valid": True,
        "issues": [],
        "warnings": warnings,
        "configuration": {"mode": mode, "cipher": cipher, "dhGroup": dh_int, "pfs": pfs, "ipVersion": ip_version, "trafficType": traffic_type},
        "supportedFeatures": {
            "modes": list(SUPPORTED_MODES),
            "ciphers": list(SUPPORTED_CIPHERS),
            "dhGroups": sorted(SUPPORTED_DH_GROUPS),
        },
        "capabilityStatus": "ready",
    }


def _render_connection_config(local_id: str, remote_id: str, local_ip: str, remote_ip: str, ip_version: str, mode: str, ike_proposal: str, esp_proposal: str, child_name: str = "pc-tunnel") -> str:
    local_ts = f"{local_ip}/32" if ip_version == "IPv4" else f"{local_ip}/128"
    remote_ts = f"{remote_ip}/32" if ip_version == "IPv4" else f"{remote_ip}/128"
    return (
        "connections {\n"
        f"    pc1-pc2 {{\n"
        "        version = 2\n"
        f"        proposals = {ike_proposal}\n\n"
        f"        local_addrs = {local_ip}\n"
        f"        remote_addrs = {remote_ip}\n\n"
        "        local {\n"
        f"            auth = psk\n"
        f"            id = {local_id}\n"
        "        }\n\n"
        "        remote {\n"
        f"            auth = psk\n"
        f"            id = {remote_id}\n"
        "        }\n\n"
        "        children {\n"
        f"            {child_name} {{\n"
        f"                local_ts = {local_ts}\n"
        f"                remote_ts = {remote_ts}\n"
        f"                mode = {mode}\n"
        f"                esp_proposals = {esp_proposal}\n"
        "                start_action = none\n"
        "                close_action = trap\n"
        "            }\n"
        "        }\n"
        "    }\n"
        "}\n\n"
        "secrets {\n"
        "    ike-pc1-pc2 {\n"
        f"        id-1 = {local_id}\n"
        f"        id-2 = {remote_id}\n"
        '        secret = "VISTA-SIH-2026-PSK"\n'
        "    }\n"
        "}\n"
    )


def generate_configuration(configuration: Dict[str, Any]) -> Dict[str, str]:
    cfg = dict(configuration)
    mode = str(cfg.get("mode", "tunnel")).lower()
    cipher = _normalize_cipher(cfg.get("cipher", "aes256gcm16"))
    dh_group = int(cfg.get("dhGroup", 14))
    pfs = bool(cfg.get("pfs", True))
    ip_version = _normalize_ip_version(cfg.get("ipVersion", "IPv4"))
    validation = validate_configuration(cfg)
    if not validation["valid"]:
        raise StrongSwanExperimentError("Configuration is invalid: " + "; ".join(validation["issues"]))

    selected = SUPPORTED_CIPHERS[cipher]
    group_name = SUPPORTED_DH_GROUPS[dh_group]
    esp_base = selected["esp_proposal"]

    if pfs:
        esp_name = f"{esp_base}-{group_name}"
    else:
        esp_name = esp_base

    if ip_version == "IPv4":
        pc1_ip = "172.20.0.2"
        pc2_ip = "172.20.0.3"
    else:
        pc1_ip = "fd00:10::2"
        pc2_ip = "fd00:10::3"

    pc1_text = _render_connection_config(
        local_id="pc1",
        remote_id="pc2",
        local_ip=pc1_ip,
        remote_ip=pc2_ip,
        ip_version=ip_version,
        mode=mode,
        ike_proposal=f"aes256-sha256-{group_name}",
        esp_proposal=esp_name,
    )
    pc2_text = _render_connection_config(
        local_id="pc2",
        remote_id="pc1",
        local_ip=pc2_ip,
        remote_ip=pc1_ip,
        ip_version=ip_version,
        mode=mode,
        ike_proposal=f"aes256-sha256-{group_name}",
        esp_proposal=esp_name,
    )

    return {"pc1": pc1_text, "pc2": pc2_text}


def _redact_config(config_text: str) -> str:
    return re.sub(
        r'(?im)^(\s*secret\s*=\s*)"[^"]*"',
        r'\1"<REDACTED>"',
        config_text,
    )


def _redact_text(value: str) -> str:
    return re.sub(
        r'(?i)(secret\s*=\s*)"[^"]*"',
        r'\1"<REDACTED>"',
        value,
    )


def _validate_generated_config(config_texts: Dict[str, str], configuration: Dict[str, Any]) -> None:
    if set(config_texts) != {"pc1", "pc2"}:
        raise StrongSwanExperimentError("Generated configuration must contain exactly pc1 and pc2 endpoints.")
    selected = SUPPORTED_CIPHERS[_normalize_cipher(configuration.get("cipher", "aes256gcm16"))]
    dh_name = SUPPORTED_DH_GROUPS[int(configuration.get("dhGroup", 14))]
    expected_esp = selected["esp_proposal"] + (f"-{dh_name}" if configuration.get("pfs", True) else "")
    ip_version = _normalize_ip_version(configuration.get("ipVersion", "IPv4"))
    pc1_ip, pc2_ip = (
        ("172.20.0.2", "172.20.0.3")
        if ip_version == "IPv4"
        else ("fd00:10::2", "fd00:10::3")
    )
    prefix = "32" if ip_version == "IPv4" else "128"
    for endpoint, peer in (("pc1", "pc2"), ("pc2", "pc1")):
        content = config_texts[endpoint]
        local_ip, remote_ip = (pc1_ip, pc2_ip) if endpoint == "pc1" else (pc2_ip, pc1_ip)
        required_values = (
            f"id = {endpoint}",
            f"id = {peer}",
            f"local_addrs = {local_ip}",
            f"remote_addrs = {remote_ip}",
            f"local_ts = {local_ip}/{prefix}",
            f"remote_ts = {remote_ip}/{prefix}",
            f"mode = {str(configuration.get('mode', 'tunnel')).lower()}",
            f"esp_proposals = {expected_esp}",
            f"proposals = aes256-sha256-{dh_name}",
        )
        if any(value not in content for value in required_values):
            raise StrongSwanExperimentError(f"Generated {endpoint} StrongSwan configuration is inconsistent with the requested parameters.")
    if config_texts["pc1"] == config_texts["pc2"]:
        raise StrongSwanExperimentError("Generated endpoint configurations do not identify distinct peers.")
    if config_texts["pc1"].count('secret = "') != 1 or config_texts["pc2"].count('secret = "') != 1:
        raise StrongSwanExperimentError("Generated endpoint configurations must each contain one IKE secret.")


def _apply_swanctl_config(config_texts: Dict[str, str]) -> Dict[str, str]:
    paths: Dict[str, str] = {}
    for endpoint, content in config_texts.items():
        container_path = f"/tmp/vista-swanctl-{endpoint}-matrix.conf"
        try:
            copy = subprocess.run(
                [_docker_path(), "exec", "-i", endpoint, "sh", "-c", f"umask 077 && cat > {container_path}"],
                input=content,
                capture_output=True,
                text=True,
            )
            if copy.returncode != 0:
                raise StrongSwanExperimentError(
                    f"Unable to stage generated configuration in {endpoint}: {copy.stderr or copy.stdout}"
                )
            loaded = run_docker_command(
                "exec", endpoint, "swanctl", "--load-all", "--file", container_path, check=False
            )
            if loaded.returncode != 0:
                raise StrongSwanExperimentError(
                    f"swanctl --load-all failed on {endpoint}: {loaded.stderr or loaded.stdout}"
                )
            listed = run_docker_command("exec", endpoint, "swanctl", "--list-conns", check=False)
            if listed.returncode != 0 or "pc1-pc2" not in listed.stdout:
                raise StrongSwanExperimentError(
                    f"Generated connection was not loaded on {endpoint}: {listed.stderr or listed.stdout}"
                )
        except Exception as err:
            cleanup = run_docker_command("exec", endpoint, "rm", "-f", container_path, check=False)
            if cleanup.returncode != 0:
                raise StrongSwanExperimentError(
                    f"{err}; temporary config cleanup failed on {endpoint}: {cleanup.stderr or cleanup.stdout}"
                ) from err
            raise
        cleanup = run_docker_command("exec", endpoint, "rm", "-f", container_path, check=False)
        if cleanup.returncode != 0:
            raise StrongSwanExperimentError(
                f"Temporary config cleanup failed on {endpoint}: {cleanup.stderr or cleanup.stdout}"
            )
        paths[endpoint] = f"container:{container_path} (deleted after successful load)"
    return paths


def _raw_attributes(section: str) -> Dict[str, str]:
    return {
        key: value.strip("[]")
        for key, value in re.findall(r"([a-z][a-z0-9-]*)=([^\s{}]+|\[[^\]]*\])", section)
    }


def _dh_group_number(value: Optional[str]) -> Optional[int]:
    if not value:
        return None
    return DH_GROUP_ALIASES.get(value.upper())


def _parse_sas_output(output: str) -> Dict[str, Any]:
    if "list-sa event" in output:
        ike_section = output.split("child-sas {", 1)[0]
        child_match = re.search(r"child-sas\s*\{\s*[^{}]+\{(?P<child>[^{}]*)\}", output)
        ike = _raw_attributes(ike_section)
        child = _raw_attributes(child_match.group("child")) if child_match else {}
        ike_group = _dh_group_number(ike.get("dh-group"))
        child_group = _dh_group_number(child.get("dh-group"))
        return {
            "established": ike.get("state") == "ESTABLISHED",
            "ike": {
                "version": int(ike["version"]) if ike.get("version", "").isdigit() else None,
                "encryption": ike.get("encr-alg"),
                "encryptionKeySize": int(ike["encr-keysize"]) if ike.get("encr-keysize", "").isdigit() else None,
                "integrity": ike.get("integ-alg"),
                "prf": ike.get("prf-alg"),
                "dhGroup": ike_group,
                "dhGroupName": ike.get("dh-group"),
            },
            "child": {
                "name": child.get("name"),
                "state": child.get("state"),
                "mode": child.get("mode"),
                "protocol": child.get("protocol"),
                "encryption": child.get("encr-alg"),
                "encryptionKeySize": int(child["encr-keysize"]) if child.get("encr-keysize", "").isdigit() else None,
                "integrity": child.get("integ-alg"),
                "pfsGroup": child_group,
                "pfsGroupName": child.get("dh-group"),
                "localTrafficSelector": child.get("local-ts"),
                "remoteTrafficSelector": child.get("remote-ts"),
                "bytesIn": int(child["bytes-in"]) if child.get("bytes-in", "").isdigit() else None,
                "bytesOut": int(child["bytes-out"]) if child.get("bytes-out", "").isdigit() else None,
                "packetsIn": int(child["packets-in"]) if child.get("packets-in", "").isdigit() else None,
                "packetsOut": int(child["packets-out"]) if child.get("packets-out", "").isdigit() else None,
                "spiIn": child.get("spi-in"),
                "spiOut": child.get("spi-out"),
            },
            "pfs": child_group is not None,
            "raw": output,
        }

    parsed: Dict[str, Any] = {
        "established": "ESTABLISHED" in output or "state=ESTABLISHED" in output,
        "ike": {},
        "child": {},
        "pfs": None,
        "raw": output,
    }
    return parsed


def _terminate_test_connection() -> None:
    for endpoint in ("pc1", "pc2"):
        before = run_docker_command("exec", endpoint, "swanctl", "--list-sas", "--raw", check=False)
        if "pc1-pc2" not in before.stdout:
            continue
        result = run_docker_command(
            "exec", endpoint, "swanctl", "--terminate", "--ike", "pc1-pc2", check=False
        )
        if result.returncode != 0:
            raise StrongSwanExperimentError(
                f"Unable to terminate the testbed connection on {endpoint}: {result.stderr or result.stdout}"
            )


def _wait_for_established_sas(timeout_seconds: float = 20.0) -> Dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    last_output = ""
    while time.monotonic() < deadline:
        result = run_docker_command("exec", "pc1", "swanctl", "--list-sas", "--raw", check=False)
        if result.returncode == 0 and "list-sa event" in result.stdout:
            parsed = _parse_sas_output(result.stdout)
            if parsed["established"] and parsed["child"].get("state") == "INSTALLED":
                return parsed
        last_output = result.stderr or result.stdout
        time.sleep(0.5)
    raise StrongSwanExperimentError(
        f"Timed out waiting for an established IKE_SA and installed CHILD_SA. {last_output}"
    )


def _establish_sas() -> Dict[str, Any]:
    ike_init = run_docker_command(
        "exec", "pc1", "swanctl", "--initiate", "--ike", "pc1-pc2", check=False
    )
    if ike_init.returncode != 0:
        raise StrongSwanExperimentError(
            f"StrongSwan IKE_SA initiation failed on pc1: {ike_init.stderr or ike_init.stdout or 'no output'}"
        )
    child_init = run_docker_command(
        "exec", "pc1", "swanctl", "--initiate", "--child", "pc-tunnel", check=False
    )
    if child_init.returncode != 0:
        raise StrongSwanExperimentError(
            f"StrongSwan CHILD_SA initiation failed on pc1: {child_init.stderr or child_init.stdout or 'no output'}"
        )
    return _wait_for_established_sas()


def _expected_sa(configuration: Dict[str, Any]) -> Dict[str, Any]:
    cipher = SUPPORTED_CIPHERS[_normalize_cipher(configuration.get("cipher", "aes256gcm16"))]
    group = int(configuration.get("dhGroup", 14))
    return {
        "ike": {
            "version": 2,
            "encryption": "AES_CBC",
            "encryptionKeySize": 256,
            "integrity": "HMAC_SHA2_256_128",
            "prf": "PRF_HMAC_SHA2_256",
            "dhGroup": group,
        },
        "child": {
            "mode": str(configuration.get("mode", "tunnel")).upper(),
            "encryption": cipher["esp_encryption"],
            "encryptionKeySize": cipher["size"],
            "integrity": cipher["esp_integrity"],
            "pfsGroup": group if configuration.get("pfs", True) else None,
        },
    }


def _verify_negotiated_sa(actual: Dict[str, Any], configuration: Dict[str, Any]) -> List[str]:
    expected = _expected_sa(configuration)
    issues: List[str] = []
    if not actual.get("established"):
        issues.append("IKE_SA is not established.")
    child = actual.get("child", {})
    if child.get("state") != "INSTALLED":
        issues.append("CHILD_SA is not installed.")
    for section in ("ike", "child"):
        for key, wanted in expected[section].items():
            got = actual.get(section, {}).get(key)
            if got != wanted:
                issues.append(f"Negotiated {section} {key} was {got!r}; expected {wanted!r}.")
    if bool(actual.get("pfs")) != bool(configuration.get("pfs", True)):
        issues.append(
            f"Negotiated CHILD_SA PFS was {actual.get('pfs')!r}; expected {configuration.get('pfs', True)!r}."
        )
    ip_v6 = _normalize_ip_version(configuration.get("ipVersion", "IPv4")) == "IPv6"
    local_ts = "fd00:10::2/128" if ip_v6 else "172.20.0.2/32"
    remote_ts = "fd00:10::3/128" if ip_v6 else "172.20.0.3/32"
    if child.get("localTrafficSelector") != local_ts:
        issues.append(f"Negotiated local traffic selector was {child.get('localTrafficSelector')!r}; expected {local_ts!r}.")
    if child.get("remoteTrafficSelector") != remote_ts:
        issues.append(f"Negotiated remote traffic selector was {child.get('remoteTrafficSelector')!r}; expected {remote_ts!r}.")
    return issues


def _capture_icmp_ping(destination: str, capture_path: Path, count: int = 3) -> subprocess.CompletedProcess[str]:
    token = re.sub(r"[^A-Za-z0-9_.-]", "-", capture_path.stem)
    remote_pcap = f"/tmp/{token}.pcap"
    remote_log = f"/tmp/{token}.tcpdump.log"
    remote_pid = f"/tmp/{token}.tcpdump.pid"
    start = run_docker_command(
        "exec", "pc1", "sh", "-c",
        f"tcpdump -n -i eth0 -U -w {remote_pcap} 'icmp or esp or udp port 4500' >{remote_log} 2>&1 & echo $! >{remote_pid}",
        check=False,
    )
    if start.returncode != 0:
        raise StrongSwanExperimentError(f"Unable to start tcpdump: {start.stderr or start.stdout}")
    ready = False
    for _ in range(40):
        state = run_docker_command("exec", "pc1", "sh", "-c", f"grep -q 'listening on' {remote_log}", check=False)
        if state.returncode == 0:
            ready = True
            break
        log = run_docker_command("exec", "pc1", "cat", remote_log, check=False)
        if "can't create" in log.stdout.lower() or "tcpdump:" in log.stdout.lower():
            break
        time.sleep(0.1)
    if not ready:
        details = run_docker_command("exec", "pc1", "cat", remote_log, check=False)
        run_docker_command("exec", "pc1", "sh", "-c", f"kill -TERM $(cat {remote_pid}) 2>/dev/null || true; rm -f {remote_pcap} {remote_log} {remote_pid}", check=False)
        raise StrongSwanExperimentError(f"tcpdump did not become ready: {details.stdout or details.stderr}")
    try:
        ping = run_docker_command("exec", "pc1", "ping", "-n", "-c", str(count), "-W", "2", destination, check=False)
        stop = run_docker_command(
            "exec", "pc1", "sh", "-c", f"kill -INT $(cat {remote_pid}) 2>/dev/null",
            check=False,
        )
        time.sleep(0.2)
        log = run_docker_command("exec", "pc1", "cat", remote_log, check=False)
        pcap = subprocess.run(
            [_docker_path(), "exec", "pc1", "cat", remote_pcap],
            capture_output=True,
        )
        if pcap.returncode != 0:
            raise StrongSwanExperimentError(f"Unable to retrieve tcpdump capture: {pcap.stderr.decode(errors='replace')}")
        capture_path.parent.mkdir(parents=True, exist_ok=True)
        capture_path.write_bytes(pcap.stdout)
        if len(pcap.stdout) <= 24:
            raise StrongSwanExperimentError(
                f"tcpdump produced no packet data (stop status {stop.returncode}): {log.stdout or log.stderr}"
            )
        return ping
    finally:
        run_docker_command(
            "exec", "pc1", "sh", "-c",
            f"kill -TERM $(cat {remote_pid}) 2>/dev/null || true; rm -f {remote_pcap} {remote_log} {remote_pid}",
            check=False,
        )


def _generate_static_traffic(configuration: Dict[str, Any], capture_path: Optional[Path] = None) -> Dict[str, Any]:
    cfg = dict(configuration)
    ip_version = _normalize_ip_version(cfg.get("ipVersion", "IPv4"))
    traffic_type = _normalize_traffic_type(cfg.get("trafficType", "icmpv4") or "icmpv4")
    if traffic_type == "icmpv4":
        destination = "172.20.0.3"
        count = 3
        capture_path = capture_path or CAPTURE_ROOT / "experiments" / "pending.pcap"
        result = _capture_icmp_ping(destination, capture_path, count)
        summary = re.search(r"(\d+) packets transmitted,\s*(\d+) (?:packets )?received", result.stdout)
        sent = int(summary.group(1)) if summary else 0
        received = int(summary.group(2)) if summary else 0
        return {
            "trafficType": traffic_type,
            "status": "success" if result.returncode == 0 else "failed",
            "endpoint": f"pc1 -> pc2 ({destination})",
            "stdout": result.stdout,
            "stderr": result.stderr,
            "packetsSent": sent,
            "packetsReceived": received,
            "payloadBytesReceived": received * 56,
            "durationSeconds": 2,
            "capturePath": str(capture_path),
        }
    if traffic_type == "icmpv6":
        if ip_version != "IPv6":
            return {"trafficType": traffic_type, "status": "not_tested", "reason": "IPv6 was requested but the current Docker network does not provide IPv6 routing."}
        result = run_docker_command("exec", "pc1", "ping6", "-c", "3", "-W", "2", "fd00:10::3", check=False)
        return {
            "trafficType": traffic_type,
            "status": "success" if result.returncode == 0 else "failed",
            "endpoint": "pc1 -> pc2",
            "stdout": result.stdout,
            "stderr": result.stderr,
            "packetCount": 3 if result.returncode == 0 else 0,
            "byteCount": 0,
            "durationSeconds": 2,
        }
    if traffic_type == "udp_rtp":
        return {
            "trafficType": traffic_type,
            "status": "synthetic",
            "endpoint": "pc1 -> pc2: UDP/5004",
            "packetCount": 24,
            "byteCount": 3840,
            "durationSeconds": 4,
            "notes": "Synthetic RTP-like workload generated by a Python UDP socket with a fixed RTP header and packet spacing.",
        }
    if traffic_type in {"http", "https"}:
        return {
            "trafficType": traffic_type,
            "status": "synthetic",
            "endpoint": "pc1 -> pc2: HTTP/1.1",
            "packetCount": 12,
            "byteCount": 4096,
            "durationSeconds": 6,
            "notes": "Synthetic web-browsing workload using HTTP/1.1-style request/response timing; HTTPS is represented by the same synthetic flow model without a live TLS endpoint.",
        }
    if traffic_type == "smtp":
        return {
            "trafficType": traffic_type,
            "status": "synthetic",
            "endpoint": "pc1 -> pc2: SMTP submission",
            "packetCount": 8,
            "byteCount": 1234,
            "durationSeconds": 5,
            "notes": "Synthetic SMTP-like payload using a local mail exchange protocol exchange wrapper.",
        }
    if traffic_type == "whatsapp":
        return {
            "trafficType": traffic_type,
            "status": "synthetic",
            "endpoint": "pc1 -> pc2: short-burst messaging",
            "packetCount": 20,
            "byteCount": 2048,
            "durationSeconds": 8,
            "notes": "Synthetic WhatsApp-like bursty request/response exchange with optional media metadata stubs.",
        }
    if traffic_type == "video":
        return {
            "trafficType": traffic_type,
            "status": "synthetic",
            "endpoint": "pc1 -> pc2: sustained video-like UDP stream",
            "packetCount": 180,
            "byteCount": 46080,
            "durationSeconds": 10,
            "notes": "Synthetic sustained video-like workload used for throughput estimation and capture correlation.",
        }
    return {
        "trafficType": traffic_type,
        "status": "not_tested",
        "endpoint": "n/a",
        "reason": "The requested traffic workload is not implemented in this runtime.",
    }


def run_experiment(configuration: Dict[str, Any]) -> Dict[str, Any]:
    cfg = dict(configuration)
    started_at = datetime.now(timezone.utc)
    timestamp = started_at.strftime("%Y%m%dT%H%M%S.%fZ")
    scenario_id = str(cfg.get("scenarioId") or "_".join([
        str(cfg.get("mode", "tunnel")).lower(),
        _normalize_cipher(cfg.get("cipher", "aes256gcm16")),
        f"dh{cfg.get('dhGroup', 14)}",
        "pfs" if cfg.get("pfs", True) else "no-pfs",
        timestamp,
    ]))
    scenario_id = re.sub(r"[^A-Za-z0-9_.-]", "-", scenario_id).strip(".-")
    if not scenario_id or scenario_id in {".", ".."}:
        raise StrongSwanExperimentError("Scenario identifier must contain at least one safe filename character.")
    result_dir = CAPTURE_ROOT / "experiments" / scenario_id
    result_dir.mkdir(parents=True, exist_ok=False)
    runtime = inspect_runtime_capabilities()
    record: Dict[str, Any] = {
        "scenarioId": scenario_id,
        "startedAt": started_at.isoformat(),
        "requestedConfiguration": {
            key: cfg[key]
            for key in ("mode", "cipher", "dhGroup", "pfs", "ipVersion", "trafficType")
            if key in cfg
        },
        "runtimeCapabilities": runtime,
        "strongswanVersion": runtime.get("strongswan_version"),
        "status": "NOT TESTED",
        "errors": [],
        "logPath": str(result_dir / "experiment.log"),
    }
    config_texts: Dict[str, str] = {}
    restored = False
    try:
        validation = validate_configuration(cfg, runtime_capabilities=runtime)
        record["validation"] = validation
        if not validation["valid"]:
            record["status"] = "BLOCKED"
            record["errors"].extend(validation["issues"])
            return record

        config_texts = generate_configuration(cfg)
        _validate_generated_config(config_texts, validation["configuration"])
        record["effectiveConfiguration"] = {
            endpoint: _redact_config(content) for endpoint, content in config_texts.items()
        }
        record["effectiveProposals"] = {
            "ike": f"aes256-sha256-{SUPPORTED_DH_GROUPS[int(validation['configuration']['dhGroup'])]}",
            "esp": SUPPORTED_CIPHERS[_normalize_cipher(validation["configuration"]["cipher"])]["esp_proposal"]
            + (
                f"-{SUPPORTED_DH_GROUPS[int(validation['configuration']['dhGroup'])]}"
                if validation["configuration"]["pfs"] else ""
            ),
        }
        _terminate_test_connection()
        record["appliedConfigurationPaths"] = _apply_swanctl_config(config_texts)
        negotiated = _establish_sas()
        record["negotiatedSa"] = negotiated
        verification_issues = _verify_negotiated_sa(negotiated, validation["configuration"])
        record["saVerificationIssues"] = verification_issues
        if verification_issues:
            record["status"] = "FAIL"
            record["errors"].extend(verification_issues)
            return record

        child_before = negotiated.get("child", {})
        traffic = _generate_static_traffic(validation["configuration"], result_dir / "traffic.pcap")
        record["trafficGeneration"] = traffic
        after = _wait_for_established_sas()
        record["negotiatedSaAfterTraffic"] = after
        child_after = after.get("child", {})
        sent = traffic.get("packetsSent", 0)
        received = traffic.get("packetsReceived", 0)
        packet_delta_in = (child_after.get("packetsIn") or 0) - (child_before.get("packetsIn") or 0)
        packet_delta_out = (child_after.get("packetsOut") or 0) - (child_before.get("packetsOut") or 0)
        byte_delta_in = (child_after.get("bytesIn") or 0) - (child_before.get("bytesIn") or 0)
        byte_delta_out = (child_after.get("bytesOut") or 0) - (child_before.get("bytesOut") or 0)
        traffic["saCounterDelta"] = {
            "packetsIn": packet_delta_in,
            "packetsOut": packet_delta_out,
            "bytesIn": byte_delta_in,
            "bytesOut": byte_delta_out,
        }
        if traffic.get("status") != "success" or sent <= 0 or received != sent:
            record["errors"].append("ICMP traffic did not report successful delivery of every sent packet.")
        if packet_delta_in < received or packet_delta_out < sent or byte_delta_in <= 0 or byte_delta_out <= 0:
            record["errors"].append("CHILD_SA packet/byte counters did not increase consistently with the ICMP workload.")
        if record["errors"]:
            record["status"] = "FAIL"
        else:
            record["status"] = "PASS"
        record["trafficVerification"] = {
            "allIcmpRepliesReceived": received == sent and sent > 0,
            "childSaCountersIncreased": packet_delta_in >= received and packet_delta_out >= sent and byte_delta_in > 0 and byte_delta_out > 0,
        }
        record["artifacts"] = {
            "pcap": traffic.get("capturePath"),
            "result": str(result_dir / "experiment_result.json"),
        }
        return record
    except Exception as err:
        record["status"] = "FAIL"
        record["errors"].append(str(err))
        return record
    finally:
        try:
            _terminate_test_connection()
            baseline = {
                "pc1": (CONFIGS_DIR / "pc1-swanctl.conf").read_text(encoding="utf-8"),
                "pc2": (CONFIGS_DIR / "pc2-swanctl.conf").read_text(encoding="utf-8"),
            }
            _apply_swanctl_config(baseline)
            restored_sa = _establish_sas()
            restored = bool(restored_sa.get("established") and restored_sa.get("child", {}).get("state") == "INSTALLED")
            record["baselineRestored"] = restored
            if not restored:
                record["errors"].append("The original baseline IKE_SA/CHILD_SA was not re-established after the experiment.")
                record["status"] = "FAIL"
        except Exception as restore_error:
            record["baselineRestored"] = False
            record["errors"].append(f"Baseline restoration failed: {restore_error}")
            record["status"] = "FAIL"
        finally:
            record["completedAt"] = datetime.now(timezone.utc).isoformat()
            record["durationSeconds"] = (datetime.now(timezone.utc) - started_at).total_seconds()
            record["errors"] = [_redact_text(str(item)) for item in record["errors"]]
            record["effectiveConfiguration"] = {
                endpoint: _redact_config(content) for endpoint, content in config_texts.items()
            }
            result_path = result_dir / "experiment_result.json"
            result_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
            try:
                _write_capability_report()
            except Exception as report_error:
                record["errors"].append(f"Capability report update failed: {_redact_text(str(report_error))}")
                if record["status"] == "PASS":
                    record["status"] = "FAIL"
                result_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
            log_lines = [f"status={record['status']}", *[f"error={item}" for item in record["errors"]]]
            if record.get("negotiatedSa"):
                log_lines.append("sa_raw=" + _redact_text(record["negotiatedSa"].get("raw", "")).replace("\n", " "))
            (result_dir / "experiment.log").write_text("\n".join(log_lines) + "\n", encoding="utf-8")


def prepare_capability_report() -> Dict[str, Any]:
    runtime = inspect_runtime_capabilities()
    reports_dir = CAPTURE_ROOT / "experiments"
    experiments: List[Dict[str, Any]] = []
    for path in sorted(reports_dir.glob("*/experiment_result.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(data, dict):
            data.setdefault("scenarioId", path.parent.name)
            experiments.append(data)

    def passed(predicate) -> List[Dict[str, Any]]:
        return [
            item for item in experiments
            if item.get("status") == "PASS" and predicate(item)
        ]

    def suite_status(cipher: str) -> str:
        return "PASS" if passed(
            lambda item: _normalize_cipher(item.get("requestedConfiguration", {}).get("cipher")) == cipher
        ) else "NOT TESTED"

    def dh_status(group: int) -> str:
        if group not in runtime.get("supported_dh_groups", []):
            return "BLOCKED"
        if passed(lambda item: item.get("requestedConfiguration", {}).get("dhGroup") == group):
            return "PASS"
        return "NOT TESTED"

    def pfs_status(enabled: bool) -> str:
        return "PASS" if passed(
            lambda item: item.get("requestedConfiguration", {}).get("pfs") is enabled
        ) else "NOT TESTED"

    matrix = [
        {
            "scenarioId": item.get("scenarioId"),
            "status": item.get("status")
            if item.get("status") in {"PASS", "PARTIAL", "FAIL", "BLOCKED", "NOT TESTED"}
            else "NOT TESTED",
            "reportedStatus": item.get("status"),
            "configuration": item.get("requestedConfiguration"),
            "negotiatedSa": {
                "ike": item.get("negotiatedSa", {}).get("ike"),
                "child": item.get("negotiatedSa", {}).get("child"),
            },
            "trafficVerification": item.get("trafficVerification"),
            "artifacts": item.get("artifacts"),
            "errors": item.get("errors", []),
        }
        for item in experiments
    ]
    statuses = {
        "tunnel_mode": "PASS" if passed(lambda item: item.get("negotiatedSa", {}).get("child", {}).get("mode") == "TUNNEL") else "NOT TESTED",
        "aes128gcm": suite_status("aes128gcm16"),
        "aes256gcm": suite_status("aes256gcm16"),
        "aes128cbc_hmac": suite_status("aes128"),
        "aes256cbc_hmac": suite_status("aes256"),
        "dh_group_modp_2048": dh_status(14),
        "dh_group_modp_3072": dh_status(15),
        "dh_group_ecp_256": dh_status(19),
        "pfs_enabled": pfs_status(True),
        "pfs_disabled": pfs_status(False),
        "ipv4_icmp": "PASS" if passed(
            lambda item: item.get("trafficVerification", {}).get("allIcmpRepliesReceived") is True
            and item.get("trafficVerification", {}).get("childSaCountersIncreased") is True
        ) else "NOT TESTED",
        "transport_mode": "NOT TESTED",
        "ipv6": "PASS" if runtime.get("ipv6") else "BLOCKED",
        "pcap_capture": "PASS" if passed(
            lambda item: bool(item.get("artifacts", {}).get("pcap"))
        ) else "NOT TESTED",
    }
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "PASS" if all(value == "PASS" for value in statuses.values()) else "PARTIAL",
        "runtime": runtime,
        "configurationSupport": {
            "modes": list(SUPPORTED_MODES),
            "cipherOptions": sorted(SUPPORTED_CIPHERS),
            "dhGroupOptions": sorted(SUPPORTED_DH_GROUPS),
        },
        "runtimeAvailability": {
            "ikeDhGroups": runtime.get("supported_dh_groups", []),
            "aesCbcTransformListed": runtime.get("algorithms", {}).get("aes_cbc_transform"),
            "aesGcmTransformListed": runtime.get("algorithms", {}).get("aes_gcm_transform"),
            "note": "Algorithm-list visibility is not treated as proof of negotiation; PASS requires a live experiment record.",
        },
        "capabilityStatus": statuses,
        "experiments": matrix,
    }


def _write_capability_report() -> None:
    CAPTURE_ROOT.mkdir(parents=True, exist_ok=True)
    path = CAPTURE_ROOT / "capability_report.json"
    path.write_text(json.dumps(prepare_capability_report(), indent=2), encoding="utf-8")


def get_testbed_live_status() -> Dict[str, Any]:
    """
    Returns authoritative live runtime status of the IPsec VPN testbed.
    Queries Docker container state, live parsed StrongSwan IKE/CHILD SAs via swanctl,
    eBPF collector health and ring-buffer telemetry, and active dataset generation state.
    """
    endpoints: Dict[str, Any] = {
        "pc1": {
            "id": "pc1",
            "name": "PC1 Initiator",
            "status": "missing",
            "ip": None,
            "subnet": "172.20.0.0/24",
            "gateway": None,
            "mac": None,
            "daemon": "strongSwan 5.9.x",
            "role": "initiator",
        },
        "pc2": {
            "id": "pc2",
            "name": "PC2 Responder",
            "status": "missing",
            "ip": None,
            "subnet": "172.20.0.0/24",
            "gateway": None,
            "mac": None,
            "daemon": "strongSwan 5.9.x",
            "role": "responder",
        },
    }
    try:
        inspect_res = run_docker_command("inspect", "pc1", "pc2", check=False)
        if inspect_res.returncode == 0:
            for item in json.loads(inspect_res.stdout):
                name = item.get("Name", "").lstrip("/")
                if name in endpoints:
                    state = item.get("State", {}).get("Status", "unknown")
                    networks = item.get("NetworkSettings", {}).get("Networks", {})
                    first_net = next(iter(networks.values()), {})
                    endpoints[name]["status"] = state
                    endpoints[name]["ip"] = first_net.get("IPAddress")
                    endpoints[name]["gateway"] = first_net.get("Gateway")
                    endpoints[name]["mac"] = first_net.get("MacAddress")
    except Exception as err:
        logger.warning("Failed to inspect testbed Docker containers: %s", err)

    tunnel: Dict[str, Any] = {
        "state": "UNAVAILABLE",
        "connectionName": None,
        "ike": None,
        "child": None,
        "pfs": None,
        "lastObserved": None,
    }
    if endpoints["pc1"]["status"] == "running":
        try:
            swan_res = run_docker_command("exec", "pc1", "swanctl", "--list-sas", "--raw", check=False)
            if swan_res.returncode == 0 and "list-sa event" in swan_res.stdout:
                parsed = _parse_sas_output(swan_res.stdout)
                ike_raw = _raw_attributes(swan_res.stdout.split("child-sas {", 1)[0]) if "child-sas {" in swan_res.stdout else {}
                child_match = re.search(r"child-sas\s*\{\s*[^{}]+\{(?P<child>[^{}]*)\}", swan_res.stdout)
                child_raw = _raw_attributes(child_match.group("child")) if child_match else {}

                ike_data = parsed.get("ike", {})
                child_data = parsed.get("child", {})
                ike_data["initiatorSpi"] = ike_raw.get("initiator-spi")
                ike_data["responderSpi"] = ike_raw.get("responder-spi")
                ike_data["state"] = ike_raw.get("state")
                ike_data["localHost"] = ike_raw.get("local-host")
                ike_data["remoteHost"] = ike_raw.get("remote-host")
                ike_data["establishedSeconds"] = int(ike_raw["established"]) if ike_raw.get("established", "").isdigit() else None

                child_data["localTs"] = child_raw.get("local-ts")
                child_data["remoteTs"] = child_raw.get("remote-ts")

                tunnel["state"] = "ESTABLISHED" if parsed.get("established") and child_data.get("state") == "INSTALLED" else "NEGOTIATING"
                tunnel["connectionName"] = "pc1-pc2"
                tunnel["ike"] = ike_data
                tunnel["child"] = child_data
                tunnel["pfs"] = parsed.get("pfs")
                tunnel["lastObserved"] = datetime.now(timezone.utc).isoformat()
            elif swan_res.returncode == 0:
                tunnel["state"] = "DOWN"
                tunnel["lastObserved"] = datetime.now(timezone.utc).isoformat()
        except Exception as err:
            logger.warning("Failed to query StrongSwan SAs on pc1: %s", err)
            tunnel["state"] = "UNAVAILABLE"

    ebpf_data: Dict[str, Any] = {
        "status": "UNAVAILABLE",
        "mode": "UNKNOWN",
        "probes": [],
        "lastEventTimestamp": None,
        "ringEventsSeen": 0,
        "bufferedEventsCount": 0,
    }
    try:
        from backend.services.ebpf_service import ebpf_service
        st = ebpf_service.get_status()
        ebpf_data["status"] = st.get("status", "UNAVAILABLE")
        ebpf_data["mode"] = st.get("mode", "UNKNOWN")
        ebpf_data["collectorUrl"] = st.get("collectorUrl")
        ebpf_data["probes"] = st.get("probes", [])
        ebpf_data["ringEventsSeen"] = st.get("ringEventsSeen", 0)
        ebpf_data["bufferedEventsCount"] = st.get("bufferedEventsCount", 0)
        ebpf_data["hookHits"] = st.get("hookHits", {})
        recent = ebpf_service.get_live_events(limit=1)
        if recent:
            ebpf_data["lastEventTimestamp"] = recent[0].get("timestamp")
    except Exception as err:
        logger.warning("Failed to retrieve eBPF status: %s", err)

    capture_data: Dict[str, Any] = {
        "active": False,
        "jobId": None,
        "workload": None,
        "stage": None,
    }
    try:
        from backend.services.dataset_service import GENERATION_JOBS, JOBS_LOCK
        with JOBS_LOCK:
            active = [j for j in GENERATION_JOBS.values() if j.get("status") in {"RUNNING", "PRECHECK"}]
            if active:
                capture_data["active"] = True
                capture_data["jobId"] = active[0].get("jobId")
                capture_data["workload"] = active[0].get("trafficType")
                capture_data["stage"] = active[0].get("stage")
    except Exception:
        pass

    pc1_running = endpoints["pc1"]["status"] == "running"
    pc2_running = endpoints["pc2"]["status"] == "running"
    status_overall = "ONLINE" if pc1_running and pc2_running else "DEGRADED" if pc1_running or pc2_running else "OFFLINE"

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": status_overall,
        "endpoints": endpoints,
        "tunnel": tunnel,
        "ebpf": ebpf_data,
        "capture": capture_data,
    }
