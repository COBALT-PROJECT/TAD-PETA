from fastapi import FastAPI, Response
from threat_model import generate_threat_model
import requests
from requests.exceptions import RequestException
import json
import os
import uvicorn


# Placeholder asset metadata
Asset_ID = "1"
Asset_Name = "Server"
Asset_Type = "DNS Server"

def load_config(filename):
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            return json.load(f)
    return {}

def mitigation_knowledge_based(attack_type):
    config = load_config('config.json')
    mitigation_url = config.get('KB_mitigation_url', 'http://localhost')
    mitigation_port = config.get('KB_mitigation_port', 8080)

    url = f"{mitigation_url}:{mitigation_port}/mitigations"
    payload = {
        "threat": {"type": attack_type}
    }
    
    mitigation_actions = ['filter_network_traffic']
    try:
        response = requests.post(url, json=payload, timeout=5)
        if response.status_code == 200:
            mitigation_actions = response.json().get("mitigation", mitigation_actions)
    except RequestException as e:
        print(f"KB Connection Error: {e}. Using default mitigations.")
    
    return mitigation_actions

def send_output(json_schema):
    config = load_config('config.json')
    sandbox_url = config.get('sandbox_output_url', 'http://localhost')
    sandbox_port = config.get('sandbox_output_port', 5000)
    sandbox_endpoint = config.get('sandbox_endpoint', 'fetch_json')
    
    api_url = f"{sandbox_url}:{sandbox_port}/{sandbox_endpoint}"
    try:    
        requests.post(api_url, json=json_schema, timeout=5)
    except RequestException as e:
        print(f"Sandbox Connection Error: {e}")

app = FastAPI()

@app.post("/json-scheme/")
def create_threat_model(cyber_attack: dict): 
    # Extract Attack Info
    attack_data = cyber_attack.get("CyberAttack", {})
    attack_type = attack_data.get("Type", "Unknown")
    target_asset_id = attack_data.get("Target_Asset_Id") # New: Extract the pointer
    
    vector = attack_data.get("Vector", {})
    timestamp = vector.get("attack_timestamp")
    location = vector.get("attack_location")
    
    # Extract Topology Info
    assets_data = cyber_attack.get("OrganizationAssets", {})
    topology = assets_data.get("Topology")
    
    if topology:
        nodes = topology.get("Nodes", [])
        links = topology.get("Links", [])
    else:
        # Fallback to single asset
        nodes = [{"Id": Asset_ID, "Name": Asset_Name, "Type": Asset_Type, "IP": vector.get("Asset_IPAddress", "0.0.0.0")}]
        links = []
        target_asset_id = Asset_ID

    # Get Mitigations
    mitigations = mitigation_knowledge_based(attack_type)
    
    # Generate JSON Threat Model with Context
    model = generate_threat_model(nodes, links, attack_type, location, timestamp, mitigations, target_asset_id)
    
    # Send to Sandbox
    send_output(model)
    
    return model

@app.get("/fetch-json-schema")
def fetch_json_schema():
    if os.path.exists("threat_model.json"):
        with open("threat_model.json", 'r') as f:
            return json.load(f)
    return {"error": "No model found"}

# Keep legacy endpoint for compatibility but return JSON
@app.post("/xml-scheme/")
def legacy_endpoint(cyber_attack: dict):
    return create_threat_model(cyber_attack)

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)