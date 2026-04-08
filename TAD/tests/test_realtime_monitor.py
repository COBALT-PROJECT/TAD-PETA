import sys
import os
import pytest
from unittest.mock import patch, MagicMock

# Ensure scripts directory is in path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'scripts')))
import realtime_monitor

# We need to mock requests to avoid hitting actual endpoints during tests
@patch('realtime_monitor.requests.post')
@patch('realtime_monitor.requests.put')
@patch('realtime_monitor.get_topology_from_sdt')
def test_trigger_peta_success(mock_get_topo, mock_put, mock_post):
    # Mocking topology return
    mock_get_topo.return_value = [
        {
            "thingId": "upc.craax.resource:postgres-db-pod-01",
            "attributes": {"role": "database", "type": "pod", "criticality": 10},
            "features": {
                "network": {"properties": {"ip_address": "10.0.0.10"}},
                "connections": {"properties": {"connected_to": []}}
            }
        }
    ]
    
    # Mocking PETA post response
    mock_post_response = MagicMock()
    mock_post_response.status_code = 200
    mock_post_response.json.return_value = {
        "threat_model": {
            "metadata": {"timestamp": "2024-01-01T00:00:00Z"},
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
    mock_post.return_value = mock_post_response
    
    # Mocking SDT put response
    mock_put_response = MagicMock()
    mock_put_response.status_code = 200
    mock_put.return_value = mock_put_response
    
    # Run the function
    result = realtime_monitor.trigger_peta("Denial_of_Service", "10.0.0.10", "http://fake-peta/sdt-topo/")
    
    # Validate it didn't return None
    assert result is not None
    
    # Validate the resulting patch payload format
    assert "security_controls" in result["features"]
    assert result["features"]["security_controls"]["desiredProperties"]["enforced_mitigation"]["action"] == "block_ip"

@patch('realtime_monitor.requests.post')
def test_trigger_peta_peta_failure(mock_post):
    # Mocking PETA post to fail
    mock_post_response = MagicMock()
    mock_post_response.status_code = 500
    mock_post.return_value = mock_post_response
    
    # If PETA fails, trigger_peta should return None
    result = realtime_monitor.trigger_peta("Denial_of_Service", "10.0.0.10", "http://fake-peta/")
    assert result is None
