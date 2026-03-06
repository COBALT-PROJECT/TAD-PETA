import json
import sys
import os

# Add parent directory to path to import local modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from adaptor import ditto_to_peta, peta_to_ditto_patch
from threat_model import generate_threat_model

def run_ditto_flow():
    print("--- 1. Loading Eclipse Ditto Topology ---")
    try:
        with open("mock_ditto_topology.json", "r") as f:
            ditto_data = json.load(f)
    except Exception as e:
        print(f"Failed to load mock topology: {e}")
        return

    print("--- 2. Converting Ditto to PETA Nodes ---")
    peta_topology = ditto_to_peta(ditto_data)
    nodes = peta_topology.get("topology", {}).get("nodes", [])
    print(f"Extracted {len(nodes)} nodes. Validating...")
    
    print("\n--- 3. Simulating 'SQL_Injection' on Critical Database Pod ---")
    # Using upc.craax.resource:postgres-db-pod-01
    target_id = "upc.craax.resource:postgres-db-pod-01"
    
    # Generate the threat model directly to test core logic isolated from web server
    model = generate_threat_model(
        nodes=nodes,
        links=[],
        attack_type="SQL_Injection",
        attack_location="Internet",
        attack_timestamp="2024-06-01T12:00:00Z",
        mitigation_list=["default_fw_rule"],
        target_node_id=target_id
    )
    
    print("\n[Selected Mitigation via Scoring Engine]:")
    selected = model["threat_model"]["control_action"]["mitigation_action"].get("selected_mitigation", {})
    print(json.dumps(selected, indent=2))
    
    print("\n--- 4. Translating Mitigation back to Eclipse Ditto Patch ---")
    patches = peta_to_ditto_patch(model)
    print(json.dumps(patches, indent=2))
    
    if patches and "patch" in patches[0]:
        print("\nSUCCESS: End-to-end Ditto integration and scoring flow complete!")
    else:
        print("\nFAILURE: Did not generate a valid patch.")

if __name__ == "__main__":
    run_ditto_flow()
