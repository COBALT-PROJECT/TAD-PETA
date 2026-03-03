import json
import requests
from pprint import pprint

def test_contextual_mitigation():
    url = "http://127.0.0.1:8000/json-scheme/"
    
    topology = {
        "Nodes": [
            {"Id": "web-1", "Name": "Web Frontend", "Type": "Frontend", "IP": "10.0.0.1"},
            {"Id": "db-1", "Name": "SQL Database", "Type": "Database", "IP": "10.0.0.2"}
        ],
        "Links": [
            {"Source": "web-1", "Target": "db-1", "Type": "VLAN"}
        ]
    }
    
    # Scenario A: Attack on Frontend
    print("--- Scenario A: SQL Injection on Frontend ---")
    payload_a = {
        "CyberAttack": {
            "Type": "SQL_Injection",
            "Target_Asset_Id": "web-1",
            "Vector": {"attack_timestamp": "2024-06-01T12:00:00Z", "attack_location": "Internet"}
        },
        "OrganizationAssets": { "Topology": topology }
    }
    
    resp_a = requests.post(url, json=payload_a).json()
    action_a = resp_a["ThreatModel"]["ControlAction"]["MitigationAction"]["Methods"][0]
    print(f"Target: Frontend | Mitigation: {action_a}")
    
    # Scenario B: Attack on Database
    print("\n--- Scenario B: SQL Injection on Database ---")
    payload_b = {
        "CyberAttack": {
            "Type": "SQL_Injection",
            "Target_Asset_Id": "db-1",
            "Vector": {"attack_timestamp": "2024-06-01T12:00:00Z", "attack_location": "Internal"}
        },
        "OrganizationAssets": { "Topology": topology }
    }
    
    resp_b = requests.post(url, json=payload_b).json()
    action_b = resp_b["ThreatModel"]["ControlAction"]["MitigationAction"]["Methods"][0]
    print(f"Target: Database | Mitigation: {action_b}")

    if action_a != action_b:
        print("\nSUCCESS: System provided different, context-aware mitigations!")
    else:
        print("\nFAILURE: System provided the same mitigation for both contexts.")

if __name__ == "__main__":
    test_contextual_mitigation()
