import sys
import os
import pytest

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from threat_model import generate_threat_model

def test_generate_threat_model_valid():
    nodes = [{"id": "n1", "type": "Frontend", "criticality": 5}]
    links = []
    
    # We use DoS here since we know it exists in attack_mapping.json
    result = generate_threat_model(
        nodes=nodes,
        links=links,
        attack_type="Denial_of_Service",
        attack_location="Internet",
        attack_timestamp="2026-01-01T00:00:00Z",
        mitigation_list=["base_mitigation"],
        target_node_id="n1"
    )
    
    model = result.get("threat_model", {})
    assert model.get("cyber_attack", {}).get("type") == "Denial_of_Service"
    
    # The output should have selected a mitigation from attack_mapping.json (since it exists locally)
    mit_action = model.get("control_action", {}).get("mitigation_action", {})
    assert "selected_mitigation" in mit_action
    assert mit_action["selected_mitigation"]["_target_node_id"] == "n1"
