import json

def ditto_to_peta(ditto_json):
    """
    Converts a list of Eclipse Ditto Things into PETA's Nodes and Links topology graph.
    """
    nodes = []
    links = [] 
    
    for thing in ditto_json:
        # Extract ID
        node_id = thing.get("thingId", "")
        
        # Extract Attributes
        attributes = thing.get("attributes", {})
        platform_type = attributes.get("type", "Unknown") # e.g. Pod, VM
        node_role = attributes.get("role", "Unknown")
        criticality = attributes.get("criticality", 5)
        
        # Determine logical PETA Type for mapping Contexts (e.g. Frontend, Database)
        peta_type = "Unknown"
        if "frontend" in node_role.lower() or "web" in node_role.lower():
            peta_type = "Frontend"
        elif "database" in node_role.lower() or "db" in node_role.lower():
            peta_type = "Database"
            
        # Extract Features (Network IP)
        features = thing.get("features", {})
        network_props = features.get("network", {}).get("properties", {})
        ip_addr = network_props.get("ip_address", "0.0.0.0")
        
        # Extract Connections
        connections = features.get("connections", {}).get("properties", {}).get("connected_to", [])
        for target_id in connections:
            links.append({
                "source": node_id,
                "target": target_id,
                "type": "Network"
            })
        
        nodes.append({
            "id": node_id,
            "name": f"{node_role} ({platform_type})",
            "type": peta_type,
            "ip": ip_addr,
            "criticality": criticality
        })
        
    return {
        "topology": {
            "nodes": nodes,
            "links": links
        }
    }

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

# Quick local test if run directly
if __name__ == "__main__":
    try:
        with open("mock_ditto_topology.json", "r") as f:
            ditto_data = json.load(f)
            
        peta_topology = ditto_to_peta(ditto_data)
        print("Converted topology:")
        print(json.dumps(peta_topology, indent=2))
        
    except FileNotFoundError:
        pass
