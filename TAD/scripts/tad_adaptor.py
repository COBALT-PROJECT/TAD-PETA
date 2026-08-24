import json
import time

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

def build_sdt_mitigation_patch(peta_result, existing_thing):
    """
    Constructs a full SDT Update payload (features + attributes) 
    to enforce a mitigation returned by PETA.
    """
    threat_model = peta_result.get("threat_model", {})
    control_action = threat_model.get("control_action", {})
    mitigation = control_action.get("mitigation_action", {})
    selected = mitigation.get("selected_mitigation", {})
    
    # Consolidate existing features
    merged_features = existing_thing.get("features", {}).copy()
    
    # Standardized 'security_controls' property structure
    merged_features["security_controls"] = {
        "desiredProperties": {
            "enforced_mitigation": {
                "action": selected.get("action", "No command provided"),
                "timestamp": threat_model.get("metadata", {}).get("timestamp"),
                "mitigation_id": selected.get("mitigation_id"),
                "description": selected.get("description")
            }
        }
    }
    
    update_payload = {
        "features": merged_features
    }
    
    # Preserve existing attributes
    if "attributes" in existing_thing:
        update_payload["attributes"] = existing_thing["attributes"]
        
    return update_payload
