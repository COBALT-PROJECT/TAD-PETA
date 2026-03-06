# PETA (JSON-Only Prototype)

The PETA prototype has been modernized from an XML-centric script into a pure JSON-based threat modeling service. It now supports multiple attack types and complex network topologies natively.

## Core Features

- **Pure JSON Pipeline**: All inputs and outputs are now JSON. XML generation logic and legacy files have been completely removed.
- **Dynamic Attack Mapping**: Uses `attack_mapping.json` to lookup MITRE ATT&CK IDs (e.g., SQL Injection -> T1190) and mitigation IDs.
- **Context-Aware Mitigations & Scoring**: PETA evaluates multiple mitigation options based on target context (e.g. Criticality). A dedicated `scoring_engine.py` selects the most effective, least disruptive action.
- **Eclipse Ditto Integration**: Integrates directly with Eclipse Ditto Digital Twin formats using an `adaptor.py` to ingest "Things" and export Desired State patches.
- **KB Integration**: Queries the Knowledge Base for mitigations based on the detected attack type.

## Supported Attack Types

PETA currently supports mapping and contextual mitigations for the following attack types:

1.  **Denial of Service (DoS)**: Specialized for Network Denial of Service (T1498.002).
2.  **SQL Injection**: Specialized for Exploit Public-Facing Application (T1190).

## Architecture and Flow

The application uses an expanded JSON flow incorporating Eclipse Ditto integration:

```mermaid
graph TD
    A[Eclipse Ditto JSON] -->|GET Thing JSON| B[adaptor.py: Ditto to PETA]
    B -->|Standard JSON Topology| C[main.py: API Input]
    C -->|Alert Info & Node Graph| E[threat_model.py: Context]
    E -->|Look up mapped mitigations| F[attack_mapping.json]
    F -.->|2-3 Technical Options per Attack| E
    E -->|Context & Options| S[scoring_engine.py]
    S -->|Evaluate Options against Criticality| S
    S -->|Selected Mitigation| E
    E -->|Generate Model| G[PETA JSON Threat Model]
    G --> H[adaptor.py: PETA to Ditto]
    H -->|Desired State PATCH| I[Eclipse Ditto Target Thing]
```

### Key Components

| File | Responsibility |
| :--- | :--- |
| [adaptor.py](file:///home/abdul/DigitalTwin/TAD-PETA/PETA/adaptor.py) | **Digital Twin Bridge**: Converts Ditto Things to PETA Topologies and Threat Models back to Ditto Patches. |
| [scoring_engine.py](file:///home/abdul/DigitalTwin/TAD-PETA/PETA/scoring_engine.py) | **Evaluation Logic**: Weighs mitigation `Effectiveness` vs `ImpactLevel` against node `Criticality`. |
| [main.py](file:///home/abdul/DigitalTwin/TAD-PETA/PETA/main.py) | **API Layer**: Exposes `/json-scheme/` and `/fetch-json-schema`. Excludes all XML dependencies. |
| [threat_model.py](file:///home/abdul/DigitalTwin/TAD-PETA/PETA/threat_model.py) | **Modeling Layer**: Replaces `dos_scheme.py`. Builds the threat model as a standard dictionary. |
| [attack_mapping.json](file:///home/abdul/DigitalTwin/TAD-PETA/PETA/attack_mapping.json) | **Mapping**: Stores the relationship between attack names, MITRE standards, and multiple mitigation options with actionable implementations. |

## Scoring Engine Upstream Analysis

The scoring engine dynamically evaluates mitigation options and traverses the network graph to find upstream targets if the target node is highly critical:

```mermaid
graph TD
    Start[Receive Target Node & Attack Type] --> EvalTarget[Evaluate Options on Target Node]
    EvalTarget --> IsCritical{Is Best Score Penalized?}
    IsCritical -->|No| SelectTarget[Select Target Node Mitigation]
    IsCritical -->|Yes| FindUpstream[Find Upstream Nodes via Links]
    FindUpstream --> EvalUpstream[Evaluate Options on Upstream Node]
    EvalUpstream --> Compare{Is Upstream Score > Target Score?}
    Compare -->|Yes| SelectUpstream[Select Upstream Mitigation]
    Compare -->|No| SelectTarget
    SelectTarget --> End[Return Selected Mitigation]
    SelectUpstream --> End
```

### How the Upstream Graph Traversal Works:
1. **Target Evaluation**: The engine first scores mitigations for the direct **Target Node** identified in the alert.
2. **Criticality Check**: It checks the target node's `Criticality`. If the node is highly critical (e.g., a core production database) and the best mitigation has a high disruptive `ImpactLevel` (like terminating all sessions), the overall score is heavily penalized.
3. **Link Traversal**: If the score is penalized, the engine parses the `Links` array in the topology to find **Upstream Nodes** (nodes where traffic flows *from* them *to* the target node).
4. **Upstream Evaluation**: It evaluates mitigation options for those upstream nodes (e.g., applying a WAF block rule on an upstream Frontend container instead of dropping the database).
5. **Score Comparison**: If mitigating on the less critical upstream node yields a higher overall safety score, the engine selects the upstream mitigation and automatically shifts the `Targeted_Asset` ID in the final output so the Digital Twin patch is applied to the correct upstream location.


## Project Structure

```text
PETA/
├── main.py              # API Layer (FastAPI)
├── threat_model.py      # Modeling Logic (JSON builder)
├── attack_mapping.json  # MITRE & Mitigation Mappings
├── config.json          # Service configurations
├── tests/               # Verification & test scripts
├── Dockerfile           # Deployment
└── docker-compose.yaml  # Deployment
```

## Usage Example

### Triggering the API

Submit a JSON payload representing a cyber attack and your network topology:

```bash
curl --location 'http://127.0.0.1:8000/json-scheme/' \
--header 'Content-Type: application/json' \
--data '{
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
}'
```

The system will generate a JSON threat model evaluated by the scoring engine. You can fetch the latest build:
```json
{
  "threat_model": {
    "id": "tm_8b2c65n3dr87345s54gd746b7h83t82k",
    "metadata": {
      "timestamp": "2024-06-01T12:00:00Z",
      "source": "Internet",
      "targeted_asset": "upc.craax.resource:postgres-db-pod-01"
    },
    "cyber_attack": {
      "type": "SQL_Injection",
      "mitre": {
        "name": "Exploit Public-Facing Application",
        "id": "T1190"
      }
    },
    "organization_assets": {
      "nodes": [...],
      "links": []
    },
    "control_action": {
      "mitigation_action": {
        "methods": [
          "Terminate Active DB Sessions from Affected Pod",
          "filter_network_traffic"
        ],
        "mitre_id": "M1050.3",
        "context_applied": "Database",
        "selected_mitigation": {
          "mitigation_id": "M1050.3",
          "description": "Terminate Active DB Sessions from Affected Pod",
          "action": "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE client_addr = '\''$POD_IP'\'';",
          "impact_level": "High",
          "effectiveness": "Medium",
          "_calculated_score": 90.0
        }
      }
    }
  }
}
```

This resulting JSON Threat Model can then be passed to `adaptor.py`'s `peta_to_ditto_patch()` function to generate a payload to update the Eclipse Ditto Digital Twin desired state automatically:
```json
[
  {
    "targetThingId": "upc.craax.resource:postgres-db-pod-01",
    "patch": [
      {
        "op": "add",
        "path": "/features/security_controls/desiredProperties/enforced_mitigation",
        "value": {
          "mitigation_id": "M1050.3",
          "description": "Terminate Active DB Sessions from Affected Pod",
          "implementation_command": "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE client_addr = '$POD_IP';",
          "timestamp": "2024-06-01T12:00:00Z"
        }
      }
    ]
  }
]
```

### Fetching the Schema
The system will generate a JSON threat model. You can fetch the latest build:
```bash
curl --location --request GET 'http://127.0.0.1:8000/fetch-json-schema'
```
