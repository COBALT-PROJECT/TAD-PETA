import requests
import json
import os

def test_sdt_topo():
    url = "http://127.0.0.1:8000/sdt-topo/"
    payload = {
        "cyber_attack": {
            "type": "SQL_Injection",
            "targeted_asset": "upc.craax.resource:postgres-db-pod-01",
            "vector": {
                "attack_timestamp": "2024-06-01T12:00:00Z",
                "attack_location": "Internet"
            }
        },
        "organization_assets": {
            "topology": {
                "nodes": [
                    {"id": "upc.craax.resource:web-frontend-pod-01", "name": "Frontend Web Server (Container)", "type": "Frontend", "ip": "10.244.1.5", "criticality": 8},
                    {"id": "upc.craax.resource:postgres-db-pod-01", "name": "Primary Database (Pod)", "type": "Database", "ip": "10.244.2.10", "criticality": 10}
                ],
                "links": []
            }
        }
    }
    
    print(f"--- Testing SDT-Topo (Online) at {url} ---")
    try:
        response = requests.post(url, json=payload)
        if response.status_code == 200:
            print("SDT-Topo Success")
        else:
            print(f"SDT-Topo Error: {response.status_code}")
    except Exception as e:
        print(f"SDT-Topo Exception: {e}")

def test_cobalt_topo():
    url = "http://127.0.0.1:8000/cobalt-topo/"
    payload = {
        "cyber_attack": {
            "type": "SQL_Injection",
            "targeted_asset": "nc-pod-ditto",
            "vector": {
                "attack_timestamp": "2024-06-01T12:00:00Z",
                "attack_location": "Internet"
            }
        }
    }
    
    print(f"\n--- Testing Cobalt-Topo (Offline) at {url} ---")
    try:
        response = requests.post(url, json=payload)
        if response.status_code == 200:
            print("Cobalt-Topo Success")
            
            print("\n--- Verifying Log Entries ---")
            if os.path.exists("log"):
                with open("log", "r") as f:
                    lines = f.readlines()
                    print("Last 2 log lines:")
                    for line in lines[-2:]:
                        print(line.strip())
            else:
                print("Log file not found")
        else:
            print(f"Cobalt-Topo Error: {response.status_code}")
            print(response.text)
    except Exception as e:
        print(f"Cobalt-Topo Exception: {e}")

if __name__ == "__main__":
    test_sdt_topo()
    test_cobalt_topo()
