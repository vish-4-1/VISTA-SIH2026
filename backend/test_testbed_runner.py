from __future__ import annotations

import os

import pytest

from backend.services import vpn_testbed
from backend.services.vpn_testbed import (
    StrongSwanExperimentError,
    _parse_sas_output,
    generate_configuration,
    run_experiment,
    validate_configuration,
)


def test_validate_supported_tunnel_configuration():
    result = validate_configuration({
        "mode": "tunnel",
        "cipher": "aes256gcm16",
        "dhGroup": 14,
        "pfs": True,
        "ipVersion": "IPv4",
        "trafficType": "icmpv4",
    })
    assert result["valid"] is True
    assert result["capabilityStatus"] == "ready"


def test_reject_unsupported_ipv6_runtime():
    result = validate_configuration({
        "mode": "tunnel",
        "cipher": "aes256gcm16",
        "dhGroup": 14,
        "pfs": True,
        "ipVersion": "IPv6",
        "trafficType": "icmpv6",
    }, runtime_capabilities={"ipv6": False, "supported_dh_groups": [14]})
    assert result["valid"] is False
    assert any("IPv6 is not available" in issue for issue in result["issues"])


def test_reject_dh_group_missing_from_runtime():
    result = validate_configuration({
        "mode": "tunnel",
        "cipher": "aes256gcm16",
        "dhGroup": 15,
        "pfs": True,
        "ipVersion": "IPv4",
        "trafficType": "icmpv4",
    }, runtime_capabilities={"ipv6": False, "supported_dh_groups": [14]})
    assert result["valid"] is False
    assert any("DH group '15' is not available" in issue for issue in result["issues"])


def test_generate_transport_mode_configuration():
    config = generate_configuration({
        "mode": "transport",
        "cipher": "aes256gcm16",
        "dhGroup": 15,
        "pfs": True,
        "ipVersion": "IPv4",
        "trafficType": "udp_rtp",
    })
    assert "mode = transport" in config["pc1"]
    assert "esp_proposals = aes256gcm16-modp3072" in config["pc1"]
    assert "secret = \"VISTA-SIH-2026-PSK\"" in config["pc1"]


def test_accept_aliases_and_https_traffic():
    result = validate_configuration({
        "mode": "tunnel",
        "cipher": "aes256gcm",
        "dhGroup": 14,
        "pfs": True,
        "ipVersion": "IPv4",
        "trafficType": "https",
    })
    assert result["valid"] is True
    assert result["configuration"]["cipher"] == "aes256gcm"
    assert result["configuration"]["trafficType"] == "https"


@pytest.mark.parametrize(
    ("cipher", "proposal", "integrity"),
    [
        ("aes128gcm16", "aes128gcm16", None),
        ("aes256gcm16", "aes256gcm16", None),
        ("aes128", "aes128-sha256", "HMAC_SHA2_256_128"),
        ("aes256", "aes256-sha256", "HMAC_SHA2_256_128"),
    ],
)
def test_crypto_configuration_separates_ike_and_esp(cipher, proposal, integrity):
    config = generate_configuration({
        "mode": "tunnel",
        "cipher": cipher,
        "dhGroup": 14,
        "pfs": True,
        "ipVersion": "IPv4",
        "trafficType": "icmpv4",
    })
    assert "proposals = aes256-sha256-modp2048" in config["pc1"]
    assert f"esp_proposals = {proposal}-modp2048" in config["pc1"]
    if integrity is None:
        assert "esp_proposals = aes128gcm16-modp2048" in config["pc1"] or "esp_proposals = aes256gcm16-modp2048" in config["pc1"]
        assert "-sha256-modp2048" not in config["pc1"].split("esp_proposals =", 1)[1].splitlines()[0]
    else:
        assert "sha256" in config["pc1"].split("esp_proposals =", 1)[1].splitlines()[0]


def test_pfs_disabled_omits_child_dh_transform():
    config = generate_configuration({
        "mode": "tunnel",
        "cipher": "aes256gcm16",
        "dhGroup": 14,
        "pfs": False,
        "ipVersion": "IPv4",
        "trafficType": "icmpv4",
    })
    assert "proposals = aes256-sha256-modp2048" in config["pc1"]
    assert "esp_proposals = aes256gcm16\n" in config["pc1"]


def test_raw_sa_parser_separates_ike_dh_from_child_pfs_group():
    raw = (
        "list-sa event {pc1-pc2 {uniqueid=4 version=2 state=ESTABLISHED "
        "encr-alg=AES_CBC encr-keysize=256 integ-alg=HMAC_SHA2_256_128 "
        "prf-alg=PRF_HMAC_SHA2_256 dh-group=MODP_2048 child-sas "
        "{pc-tunnel-2 {name=pc-tunnel state=INSTALLED mode=TUNNEL protocol=ESP "
        "encr-alg=AES_GCM_16 encr-keysize=128 dh-group=MODP_3072 "
        "bytes-in=252 bytes-out=252 packets-in=3 packets-out=3 "
        "local-ts=[172.20.0.2/32] remote-ts=[172.20.0.3/32]}}}}\n"
    )
    parsed = _parse_sas_output(raw)
    assert parsed["ike"]["dhGroup"] == 14
    assert parsed["child"]["pfsGroup"] == 15
    assert parsed["child"]["encryption"] == "AES_GCM_16"
    assert parsed["child"]["localTrafficSelector"] == "172.20.0.2/32"
    assert parsed["pfs"] is True


def test_raw_sa_parser_reports_no_pfs_without_child_dh_group():
    raw = (
        "list-sa event {pc1-pc2 {uniqueid=4 version=2 state=ESTABLISHED "
        "encr-alg=AES_CBC encr-keysize=256 integ-alg=HMAC_SHA2_256_128 "
        "prf-alg=PRF_HMAC_SHA2_256 dh-group=MODP_2048 child-sas "
        "{pc-tunnel-2 {name=pc-tunnel state=INSTALLED mode=TUNNEL protocol=ESP "
        "encr-alg=AES_CBC encr-keysize=128 integ-alg=HMAC_SHA2_256_128 "
        "bytes-in=252 bytes-out=252 packets-in=3 packets-out=3 "
        "local-ts=[172.20.0.2/32] remote-ts=[172.20.0.3/32]}}}}\n"
    )
    parsed = _parse_sas_output(raw)
    assert parsed["ike"]["dhGroup"] == 14
    assert parsed["child"]["pfsGroup"] is None
    assert parsed["pfs"] is False


def test_apply_failure_is_recorded_and_baseline_restore_attempted(monkeypatch, tmp_path):
    monkeypatch.setattr(vpn_testbed, "CAPTURE_ROOT", tmp_path / "captures")
    monkeypatch.setattr(vpn_testbed, "inspect_runtime_capabilities", lambda: {
        "containers": {"pc1": "running", "pc2": "running"},
        "supported_dh_groups": [14, 15],
        "ipv6": False,
    })
    monkeypatch.setattr(vpn_testbed, "_terminate_test_connection", lambda: None)
    calls = {"apply": 0, "establish": 0}

    def apply(configs):
        calls["apply"] += 1
        if calls["apply"] == 1:
            raise StrongSwanExperimentError("test config-load failure")
        return {"pc1": "in-memory", "pc2": "in-memory"}

    def establish():
        calls["establish"] += 1
        return {
            "established": True,
            "child": {"state": "INSTALLED"},
            "raw": "test",
        }

    monkeypatch.setattr(vpn_testbed, "_apply_swanctl_config", apply)
    monkeypatch.setattr(vpn_testbed, "_establish_sas", establish)
    result = run_experiment({
        "scenarioId": "mock-apply-failure",
        "mode": "tunnel",
        "cipher": "aes256gcm16",
        "dhGroup": 14,
        "pfs": True,
        "ipVersion": "IPv4",
        "trafficType": "icmpv4",
    })
    assert result["status"] == "FAIL"
    assert "test config-load failure" in result["errors"][0]
    assert result["baselineRestored"] is True
    assert calls == {"apply": 2, "establish": 1}
    assert "VISTA-SIH-2026-PSK" not in result["effectiveConfiguration"]["pc1"]


LIVE_MATRIX = [
    pytest.param("aes128gcm16", 14, True, id="aes128-gcm"),
    pytest.param("aes256gcm16", 14, True, id="aes256-gcm-baseline"),
    pytest.param("aes128", 14, True, id="aes128-cbc-hmac"),
    pytest.param("aes256", 14, True, id="aes256-cbc-hmac"),
    pytest.param("aes256gcm16", 15, True, id="modp3072"),
    pytest.param("aes256gcm16", 14, False, id="pfs-disabled"),
]


@pytest.mark.skipif(os.environ.get("VISTA_LIVE_VPN_TEST", "0") != "1", reason="Live StrongSwan matrix is opt-in; run explicitly in a controlled Docker testbed.")
@pytest.mark.parametrize(("cipher", "dh_group", "pfs"), LIVE_MATRIX)
def test_live_crypto_matrix(cipher, dh_group, pfs):
    result = run_experiment({
        "mode": "tunnel",
        "cipher": cipher,
        "dhGroup": dh_group,
        "pfs": pfs,
        "ipVersion": "IPv4",
        "trafficType": "icmpv4",
    })
    assert result["status"] == "PASS", result
    assert result["baselineRestored"] is True


@pytest.mark.skipif(os.environ.get("VISTA_LIVE_VPN_TEST", "0") != "1", reason="Live StrongSwan runtime check is disabled outside the integration environment.")
def test_live_runtime_experiment_baseline():
    result = run_experiment({
        "mode": "tunnel",
        "cipher": "aes256gcm16",
        "dhGroup": 14,
        "pfs": True,
        "ipVersion": "IPv4",
        "trafficType": "icmpv4",
    })
    assert result["status"] == "PASS"
    assert result["negotiatedSa"]["established"] is True
