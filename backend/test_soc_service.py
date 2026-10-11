from backend.services.soc_service import SocService


def test_unknown_attack_label_is_not_assigned_a_fallback_mitre_technique():
    service = SocService()
    service._cached_flows = [{
        "flowId": "fixture-unknown",
        "trafficType": "Attack",
        "isAttack": 1,
        "attackType": "UNREGISTERED_LABEL",
    }]

    assert service.get_threat_matrix() == []


def test_registered_synthetic_label_keeps_synthetic_provenance():
    service = SocService()
    service._cached_flows = [{
        "flowId": "fixture-port-scan",
        "trafficType": "Attack",
        "isAttack": 1,
        "attackType": "PORT_SCAN",
    }]

    [threat] = service.get_threat_matrix()

    assert threat["mitreId"] == "T1046"
    assert threat["classificationSource"] == "Synthetic dataset label"
    assert "not an observed attack" in threat["verificationStatus"]
