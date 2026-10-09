from __future__ import annotations

import os

import pytest

from backend.services.vpn_testbed import generate_configuration, run_experiment, validate_configuration


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
    assert result["status"] == "verified"
    assert result["negotiatedSa"]["established"] is True
