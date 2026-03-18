import requests
import json
import os

def test_offline_analysis():
    url = "http://127.0.0.1:8000/offline-analysis/"
    payload = {
        "type": "SQL_Injection",
        "target_asset_id": "upc.craax.resource:postgres-db-pod-01"
    }
    
    print(f"--- Triggering Offline Analysis at {url} ---")
    try:
        response = requests.post(url, json=payload)
        if response.status_code == 200:
            print("Response Received Successfully:")
            # print(json.dumps(response.json(), indent=2))
            
            print("\n--- Checking Log File ---")
            if os.path.exists("log"):
                with open("log", "r") as f:
                    logs = f.readlines()
                    print("Last 5 log entries:")
                    for line in logs[-5:]:
                        print(line.strip())
            else:
                print("Error: 'log' file not found.")
        else:
            print(f"Error: Status Code {response.status_code}")
            print(response.text)
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_offline_analysis()
