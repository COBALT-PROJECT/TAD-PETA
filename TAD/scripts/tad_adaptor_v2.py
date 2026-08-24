"""
tad_adaptor_v2.py
=================
Copy of tad_adaptor.py with ONE fix. The original is unchanged.

THE BUG IT FIXES
----------------
`tad_adaptor.ditto_to_peta()` derived PETA's asset context purely from a role
substring match, and could only ever emit Frontend / Database / Unknown:

    if "frontend" in role or "web" in role:  -> Frontend
    elif "database" in role or "db" in role: -> Database
    else:                                    -> Unknown

The NCSRD topology uses five contexts (Frontend, Database, Compute, Identity,
Security). Through the live SDT path 17 of 18 VMs collapsed to "Unknown", and
scoring_engine returns [] for an unknown context -> those hosts silently got NO
mitigation, even though the topology file itself validates 108/108.

FIX: honour an explicit `attributes.peta_type` (what register_vms.py should set)
and fall back to a WIDER role heuristic. Fully backwards compatible — with no
`peta_type` attribute and an old role string the result is identical to before.
"""

VALID_CONTEXTS = {"Frontend", "Database", "Compute", "Identity", "Security"}

# checked in order; first hit wins
_ROLE_HINTS = [
    ("Database", ("database", "db", "sql", "mysql", "postgres", "data-lake",
                  "datalake", "ledger", "dlt", "store")),
    ("Identity", ("iam", "identity", "keycloak", "ldap", "auth", "sso")),
    ("Security", ("security", "sdt", "tad", "peta", "watchtower", "clouditor",
                  "monitor", "siem", "ids")),
    ("Compute",  ("k3s", "k8s", "kubernetes", "worker", "node", "master",
                  "control plane", "compute")),
    ("Frontend", ("frontend", "web", "ui", "portal", "api", "gateway", "app")),
]


def resolve_peta_type(attributes: dict, node_role: str) -> str:
    """Explicit attribute wins; otherwise infer from the role string."""
    explicit = attributes.get("peta_type") or attributes.get("context")
    if explicit in VALID_CONTEXTS:
        return explicit
    role = (node_role or "").lower()
    for ctx, hints in _ROLE_HINTS:
        if any(h in role for h in hints):
            return ctx
    return "Unknown"


def ditto_to_peta(ditto_json):
    """Eclipse Ditto Things -> PETA nodes/links topology graph."""
    nodes, links = [], []

    for thing in ditto_json:
        node_id = thing.get("thingId", "")
        attributes = thing.get("attributes", {})
        platform_type = attributes.get("type", "Unknown")
        node_role = attributes.get("role", "Unknown")
        criticality = attributes.get("criticality", 5)

        peta_type = resolve_peta_type(attributes, node_role)

        features = thing.get("features", {})
        network_props = features.get("network", {}).get("properties", {})
        ip_addr = network_props.get("ip_address", "0.0.0.0")

        connections = (features.get("connections", {})
                               .get("properties", {}).get("connected_to", []))
        for target_id in connections:
            links.append({"source": node_id, "target": target_id, "type": "Network"})

        nodes.append({
            "id": node_id,
            "name": f"{node_role} ({platform_type})",
            "type": peta_type,
            "ip": ip_addr,
            "criticality": criticality,
        })

    return {"topology": {"nodes": nodes, "links": links}}


# unchanged from the original
def build_sdt_mitigation_patch(peta_result, existing_thing):
    """Build an SDT update payload enforcing the mitigation PETA returned."""
    threat_model = peta_result.get("threat_model", {})
    control_action = threat_model.get("control_action", {})
    mitigation = control_action.get("mitigation_action", {})
    selected = mitigation.get("selected_mitigation", {})

    merged_features = existing_thing.get("features", {}).copy()
    merged_features["security_controls"] = {
        "desiredProperties": {
            "enforced_mitigation": {
                "action": selected.get("action", "No command provided"),
                "timestamp": threat_model.get("metadata", {}).get("timestamp"),
                "mitigation_id": selected.get("mitigation_id"),
                "description": selected.get("description"),
            }
        }
    }
    update_payload = {"features": merged_features}
    if "attributes" in existing_thing:
        update_payload["attributes"] = existing_thing["attributes"]
    return update_payload
