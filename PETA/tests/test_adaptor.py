import sys
import os
import pytest

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from adaptor import peta_to_ditto_patch

def test_peta_to_ditto_patch_valid():
    mock_threat_model = {
        "threat_model": {
            "metadata": {
                "targeted_asset": "device-123",
                "timestamp": "2024-01-01T00:00:00Z"
            },
            "control_action": {
                "mitigation_action": {
                    "selected_mitigation": {
                        "mitigation_id": "M100",
                        "description": "Block IP",
                        "action": "iptables -DROP"
                    }
                }
            }
        }
    }
    
    patches = peta_to_ditto_patch(mock_threat_model)
    assert len(patches) == 1
    assert patches[0]["targetThingId"] == "device-123"
    
    ops = patches[0]["patch"]
    assert len(ops) == 1
    assert ops[0]["op"] == "add"
    assert ops[0]["path"] == "/features/security_controls/desiredProperties/enforced_mitigation"
    
    val = ops[0]["value"]
    assert val["mitigation_id"] == "M100"
    assert val["description"] == "Block IP"
    assert val["implementation_command"] == "iptables -DROP"
    assert val["timestamp"] == "2024-01-01T00:00:00Z"

def test_peta_to_ditto_patch_no_mitigation():
    mock_threat_model = {
         "threat_model": {
              "metadata": {"targeted_asset": "device-123"}
         }
    }
    patches = peta_to_ditto_patch(mock_threat_model)
    assert len(patches) == 0

def test_peta_to_ditto_patch_no_target():
    mock_threat_model = {
        "threat_model": {
            "control_action": {
                "mitigation_action": {
                    "selected_mitigation": {
                        "action": "test"
                    }
                }
            }
        }
    }
    patches = peta_to_ditto_patch(mock_threat_model)
    assert len(patches) == 0
