import argparse
import json
import logging
import time
import requests

import joblib

import tad_adaptor

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

SDT_SERVICE_URL = "http://localhost:8001/api/SDT/update/"

def get_topology_from_sdt():
    """Mock implementation to fetch dynamic digital twin topology."""
    # In a real environment, this would hit Eclipse Ditto or the SDT Service directly
    return [
        {
            "thingId": "upc.craax.resource:postgres-db-pod-01",
            "attributes": {"role": "database", "type": "pod", "criticality": 10},
            "features": {
                "network": {"properties": {"ip_address": "10.0.0.10"}},
                "connections": {"properties": {"connected_to": []}}
            }
        }
    ]

def trigger_peta(attack_type, target_ip, peta_url, mock_target_id=None):
    """
    Triggers the PETA mitigation API and pushes the result to the Digital Twin.
    """
    logging.info(f"Triggering remediation for {attack_type} on {target_ip}...")
    
    # 1. Fetch live system topology from Digital Twin
    ditto_topology = get_topology_from_sdt()
    
    # 2. Use the local tad_adaptor to translate to PETA's simplified format
    peta_friendly_topology = tad_adaptor.ditto_to_peta(ditto_topology)
    
    # Find matching target by IP (or use hardcoded for demo)
    target_id = mock_target_id or "upc.craax.resource:postgres-db-pod-01"
    
    payload = {
        "cyber_attack": {
            "type": attack_type,
            "targeted_asset": target_id,
            "vector": {
                "attack_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "attack_location": "Internet"
            }
        },
        "organization_assets": peta_friendly_topology
    }
    
    try:
        # 3. Call PETA endpoint
        response = requests.post(peta_url, json=payload)
        if response.status_code == 200:
            peta_result = response.json()
            logging.info("PETA Mitigation Plan received successfully.")
            
            # 4. Enforce Patch
            source_thing = next((t for t in ditto_topology if t.get("thingId") == target_id), {})
            sdt_patch_payload = tad_adaptor.build_sdt_mitigation_patch(peta_result, source_thing)
            
            # 5. Send to SDT
            sdt_response = requests.put(f"{SDT_SERVICE_URL}?toeid={target_id}&category=security", json=sdt_patch_payload)
            if sdt_response.status_code == 200:
                 logging.info(f"Successfully enforced patch on {target_id} in the Digital Twin.")
            else:
                 logging.error(f"Failed to apply patch to SDT: {sdt_response.text}")
                 
            return sdt_patch_payload
        else:
            logging.error(f"PETA Error {response.status_code}: {response.text}")
    except Exception as e:
        logging.error(f"Failed to trigger PETA: {e}")
    return None

import os
import glob
import pandas as pd

def main():
    parser = argparse.ArgumentParser(description="TAD Realtime Monitor")
    parser.add_argument("--model", required=False, help="Path to RandomForest .joblib model")
    parser.add_argument("--peta-url", default="http://localhost:8000/sdt-topo/", help="PETA Endpoint")
    parser.add_argument("--simulate", action="store_true", help="Run a manual simulation without Kafka")
    args = parser.parse_args()

    if args.simulate:
        logging.info("Running manual simulation...")
        trigger_peta("Denial_of_Service", "10.0.0.10", args.peta_url)
        return

    logging.info(f"Loading Model: {args.model}")
    try:
        model = joblib.load(args.model) if args.model else None
    except Exception as e:
         logging.warning(f"Could not load model: {e}. Inference will be disabled.")
         model = None
         
    # NFS / CSV Integration
    logging.info("Starting NFS CSV Monitor on TAD/data/...")
    data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data')
    
    while True:
        csv_files = glob.glob(os.path.join(data_dir, "*.csv"))
        for csv_file in csv_files:
            try:
                # In production, handle state/offsets to not re-process rows
                df = pd.read_csv(csv_file)
                for index, row in df.iterrows():
                    # Simulated Inference logic here using `model.predict([features])`
                    # target_ip = row.get("dst_ip", "10.0.0.10")
                    # if attack detected:
                    #    trigger_peta("Port_Scan", target_ip, args.peta_url)
                    pass
            except Exception as e:
                logging.error(f"Failed to read {csv_file}: {e}")
        
        # Polling delay
        time.sleep(10)

if __name__ == "__main__":
    main()
