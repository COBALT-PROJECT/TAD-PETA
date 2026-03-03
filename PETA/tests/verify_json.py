import json
import requests
from pprint import pprint

def test_json_pipeline():
    url = "http://127.0.0.1:8000/json-scheme/"
    
    payload = {
        "CyberAttack": {
            "Type": "SQL_Injection",
            "Vector": {
                "attack_timestamp": "2024-06-01T12:00:00Z",
                "attack_location": "Internet"
            }
        },
        "OrganizationAssets": {
            "Topology": {
                "Nodes": [
                    {"Id": "n1", "Name": "App", "Type": "VM", "IP": "10.1.1.1"},
                    {"Id": "n2", "Name": "Data", "Type": "DB", "IP": "10.1.1.2"}
                ],
                "Links": [
                    {"Source": "n1", "Target": "n2", "Type": "Internal"}
                ]
            }
        }
    }
    
    print("Testing JSON-only pipeline...")
    try:
        response = requests.post(url, json=payload, timeout=5)
        print(f"Status: {response.status_code}")
        result = response.json()
        
        # Verify JSON structure
        if "ThreatModel" in result and "OrganizationAssets" in result["ThreatModel"]:
            print("SUCCESS: JSON structure is correct.")
            pprint(result["ThreatModel"]["CyberAttack"])
            pprint(result["ThreatModel"]["OrganizationAssets"])
            pprint(result["ThreatModel"]["ControlAction"])
        else:
            print("FAILURE: Invalid JSON response structure.")

    except Exception as e:
        print(f"Error during testing: {e}")

if __name__ == "__main__":
    test_json_pipeline()
