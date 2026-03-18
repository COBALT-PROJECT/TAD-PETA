import json

def peta_to_ditto_patch(threat_model_json):
    """
    Takes the generated Threat Model and returns a JSON Patch 
    to enforce the mitigation on the target asset in Eclipse Ditto.
    """
    patches = []
    
    control_action = threat_model_json.get("threat_model", {}).get("control_action", {})
    mitigation_action = control_action.get("mitigation_action", {})
    
    # In the new architecture, the selected mitigation is a structured object
    selected = mitigation_action.get("selected_mitigation", {})
    
    if not selected:
        return patches
        
    target_id = threat_model_json.get("threat_model", {}).get("metadata", {}).get("targeted_asset")
    
    if target_id and selected.get("action"):
        # Create a patch to update the desiredProperties of the security_controls feature
        patches.append({
            "targetThingId": target_id,
            "patch": [
                {
                    "op": "add",
                    "path": "/features/security_controls/desiredProperties/enforced_mitigation",
                    "value": {
                        "mitigation_id": selected.get("mitigation_id"),
                        "description": selected.get("description"),
                        "implementation_command": selected.get("action"),
                        "timestamp": threat_model_json.get("threat_model", {}).get("metadata", {}).get("timestamp")
                    }
                }
            ]
        })
        
    return patches

