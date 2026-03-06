import json
import os

from scoring_engine import score_mitigations

def load_mapping():
    mapping_path = os.path.join(os.path.dirname(__file__), 'attack_mapping.json')
    if os.path.exists(mapping_path):
        with open(mapping_path, 'r') as f:
            return json.load(f)
    return {}

def generate_threat_model(nodes, links, attack_type, attack_location, attack_timestamp, mitigation_list, target_node_id=None):
    mapping = load_mapping().get(attack_type, {})
    
    # Find the target node details for context
    target_node = next((n for n in nodes if n.get('id') == target_node_id), {})
    asset_type = target_node.get('type')
    # Evaluate with Scoring Engine - Pass full graph and mapping
    best_mitigation = score_mitigations(load_mapping(), attack_type, target_node, nodes, links)
    
    # The scoring engine may have shifted the mitigation to an upstream node!
    final_target_id = best_mitigation.get("_target_node_id", target_node_id) if best_mitigation else target_node_id
    final_asset_type = next((n.get('type') for n in nodes if n.get('id') == final_target_id), asset_type)
    
    mitre_id = best_mitigation.get("mitigation_id", mapping.get("default_mitigation_id", "M1037"))
    
    if best_mitigation.get("description") and best_mitigation.get("description") not in mitigation_list:
         mitigation_list.insert(0, best_mitigation.get("description"))

    threat_model = {
        "threat_model": {
            "id": "tm_8b2c65n3dr87345s54gd746b7h83t82k",
            "metadata": {
                "timestamp": attack_timestamp,
                "source": attack_location,
                "targeted_asset": final_target_id # Use the potentially shifted upstream target!
            },
            "cyber_attack": {
                "type": attack_type,
                "mitre": {
                    "name": mapping.get("att_ck_name", "Unknown"),
                    "id": mapping.get("att_id", "Unknown")
                }
            },
            "organization_assets": {
                "nodes": nodes,
                "links": links
            },
            "control_action": {
                "mitigation_action": {
                    "methods": mitigation_list, # legacy list 
                    "mitre_id": mitre_id,
                    "context_applied": final_asset_type if best_mitigation else "None",
                    "selected_mitigation": best_mitigation # New structured format
                }
            }
        }
    }
    
    with open('threat_model.json', 'w') as f:
        json.dump(threat_model, f, indent=4)
        
    return threat_model
