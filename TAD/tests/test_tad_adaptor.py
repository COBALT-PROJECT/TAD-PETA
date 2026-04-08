import sys
import os
import pytest

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import tad_adaptor

def test_ditto_to_peta():
    mock_ditto = [
        {
            "thingId": "test-device-1",
            "attributes": {
                "role": "frontend_web",
                "type": "VM",
                "criticality": 8
            },
            "features": {
                "network": {
                    "properties": {
                        "ip_address": "10.0.0.1"
                    }
                },
                "connections": {
                    "properties": {
                        "connected_to": ["test-device-2"]
                    }
                }
            }
        }
    ]
    
    result = tad_adaptor.ditto_to_peta(mock_ditto)
    nodes = result["topology"]["nodes"]
    links = result["topology"]["links"]
    
    assert len(nodes) == 1
    assert nodes[0]["id"] == "test-device-1"
    assert nodes[0]["type"] == "Frontend"
    assert nodes[0]["ip"] == "10.0.0.1"
    assert nodes[0]["criticality"] == 8
    
    assert len(links) == 1
    assert links[0]["source"] == "test-device-1"
    assert links[0]["target"] == "test-device-2"


def test_build_sdt_mitigation_patch():
    peta_result = {
        "threat_model": {
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z"
            },
            "control_action": {
                "mitigation_action": {
                    "selected_mitigation": {
                        "action": "block_ip",
                        "mitigation_id": "M01",
                        "description": "Block source IP"
                    }
                }
            }
        }
    }
    
    existing_thing = {
        "attributes": {
            "role": "database"
        },
        "features": {
            "network": {
                "properties": {"ip_address": "10.0.0.2"}
            }
        }
    }
    
    patch = tad_adaptor.build_sdt_mitigation_patch(peta_result, existing_thing)
    
    # Must preserve attributes
    assert patch["attributes"]["role"] == "database"
    
    # Must preserve existing features and add security_controls
    assert "network" in patch["features"]
    assert "security_controls" in patch["features"]
    
    sec_ctrl = patch["features"]["security_controls"]["desiredProperties"]["enforced_mitigation"]
    assert sec_ctrl["action"] == "block_ip"
    assert sec_ctrl["mitigation_id"] == "M01"
    assert sec_ctrl["timestamp"] == "2024-01-01T00:00:00Z"
