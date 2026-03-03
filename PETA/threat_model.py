import json
import os

def load_mapping():
    mapping_path = os.path.join(os.path.dirname(__file__), 'attack_mapping.json')
    if os.path.exists(mapping_path):
        with open(mapping_path, 'r') as f:
            return json.load(f)
    return {}

def generate_threat_model(nodes, links, attack_type, attack_location, attack_timestamp, mitigation_list, target_node_id=None):
    mapping = load_mapping().get(attack_type, {})
    
    # Find the target node details for context
    target_node = next((n for n in nodes if n.get('Id') == target_node_id), {})
    asset_type = target_node.get('Type')
    
    # Context-aware mitigation lookup
    context_mapping = mapping.get("Contexts", {}).get(asset_type, {})
    mitre_id = context_mapping.get("Mitigation_ID", mapping.get("Default_Mitigation_ID", "M1037"))
    
    # If we have a specific contextual action, append it to the mitigation list
    context_action = context_mapping.get("Action")
    if context_action and context_action not in mitigation_list:
        mitigation_list.insert(0, context_action) # Prioritize context-aware action

    threat_model = {
        "ThreatModel": {
            "Id": "tm_8b2c65n3dr87345s54gd746b7h83t82k",
            "Metadata": {
                "Timestamp": attack_timestamp,
                "Source": attack_location,
                "Targeted_Asset": target_node_id
            },
            "CyberAttack": {
                "Type": attack_type,
                "MITRE": {
                    "Name": mapping.get("ATT_CK_Name", "Unknown"),
                    "ID": mapping.get("ATT_ID", "Unknown")
                }
            },
            "OrganizationAssets": {
                "Nodes": nodes,
                "Links": links
            },
            "ControlAction": {
                "MitigationAction": {
                    "Methods": mitigation_list,
                    "MITRE_ID": mitre_id,
                    "Context_Applied": asset_type if context_action else "None"
                }
            }
        }
    }
    
    with open('threat_model.json', 'w') as f:
        json.dump(threat_model, f, indent=4)
        
    return threat_model
