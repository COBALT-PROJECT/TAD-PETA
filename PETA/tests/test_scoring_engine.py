import sys
import os
import pytest

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scoring_engine import score_mitigations

@pytest.fixture
def mock_mapping():
    return {
        "DoS": {
            "contexts": {
                "Frontend": [
                    {"mitigation_id": "M1", "effectiveness": "High", "impact_level": "Low"}
                ],
                "Database": [
                    {"mitigation_id": "M2", "effectiveness": "High", "impact_level": "Critical"}
                ]
            }
        }
    }

def test_score_mitigations_target_node(mock_mapping):
    target_node = {"id": "n1", "type": "Frontend", "criticality": 5}
    nodes = [target_node]
    links = []
    
    best = score_mitigations(mock_mapping, "DoS", target_node, nodes, links)
    
    assert best["mitigation_id"] == "M1"
    assert best["_target_node_id"] == "n1"
    # base effectiveness High (90) + impact base Low (80) = 170
    assert best["_calculated_score"] == 170

def test_score_mitigations_upstream_traversal(mock_mapping):
    target_node = {"id": "target", "type": "Database", "criticality": 10}
    upstream_node = {"id": "upstream", "type": "Frontend", "criticality": 5}
    nodes = [target_node, upstream_node]
    links = [{"source": "upstream", "target": "target"}]
    
    best = score_mitigations(mock_mapping, "DoS", target_node, nodes, links)
    
    # Target node would get score: High effect (90) + [Critical impact (-50) * criticality 10 / 5.0] = 90 - 100 = -10
    # Upstream node would get score: High effect (90) + Low impact (80) = 170
    assert best["mitigation_id"] == "M1"
    assert best["_target_node_id"] == "upstream"
    assert best["_calculated_score"] == 170

def test_score_mitigations_no_valid_mitigation(mock_mapping):
    target_node = {"id": "n1", "type": "UnknownType", "criticality": 5}
    nodes = [target_node]
    links = []
    
    best = score_mitigations(mock_mapping, "DoS", target_node, nodes, links)
    assert best == {}
