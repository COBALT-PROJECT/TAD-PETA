import argparse
import logging
import time
from collections import defaultdict

import joblib
import requests

import tad_adaptor
import feature_utils

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

SDT_SERVICE_URL = "http://localhost:8001/api/SDT/update/"
SDT_TOPOLOGY_URL = "http://localhost:8001/api/SDT/topology/"

DITTO_BASE_URL = "http://localhost:8080/api/2"
DITTO_AUTH = ("ditto", "ditto")


def get_topology_from_sdt():
    """Fetch live digital twin topology via SDT's topology endpoint."""
    logging.info(f"[SDT] GET {SDT_TOPOLOGY_URL}  namespace=cobalt.sdt")
    try:
        resp = requests.get(SDT_TOPOLOGY_URL, params=[("toeid", "00000000-0000-0000-0000-000000000000")], timeout=5)
        logging.info(f"[SDT] Response {resp.status_code}")
        if resp.status_code == 200:
            items = resp.json().get("items", [])
            logging.info(f"[SDT] Found {len(items)} thing(s):")
            for t in items:
                ip = (
                    t.get("features", {})
                    .get("network", {})
                    .get("properties", {})
                    .get("ip_address", "?")
                )
                logging.info(f"[SDT]   {t['thingId']}  ip={ip}")
            if items:
                return items
            logging.warning("[SDT] 0 things returned — are VMs registered?")
        else:
            logging.warning(f"[SDT] Topology returned {resp.status_code}: {resp.text[:200]}")
    except Exception as exc:
        logging.warning(f"[SDT] Unreachable ({exc}). Falling back to static topology.")

    # Fallback: static representation matching cobalt.sdt namespace (SDT controller's namespace)
    return [
        {
            "thingId": "cobalt.sdt:toe-00000000-0000-0000-0000-000000000000-RESOURCE-static-1",
            "attributes": {"toe_id": "00000000-0000-0000-0000-000000000000", "category": "RESOURCE", "role": "database", "type": "vm", "criticality": 9},
            "features": {"network": {"properties": {"ip_address": "10.0.0.41"}}},
        },
        {
            "thingId": "cobalt.sdt:toe-00000000-0000-0000-0000-000000000000-RESOURCE-static-2",
            "attributes": {"toe_id": "00000000-0000-0000-0000-000000000000", "category": "RESOURCE", "role": "webserver", "type": "vm", "criticality": 7},
            "features": {"network": {"properties": {"ip_address": "10.0.0.40"}}},
        },
    ]

def trigger_peta(attack_type, target_ip, peta_url, mock_target_id=None, cached_topology=None):
    """
    Triggers the PETA mitigation API and pushes the result to the Digital Twin.
    """
    logging.info(f"Triggering remediation for {attack_type} on {target_ip}...")
    
    # 1. Use cached topology if provided, otherwise fetch live
    ditto_topology = cached_topology if cached_topology is not None else get_topology_from_sdt()
    
    # 2. Use the local tad_adaptor to translate to PETA's simplified format
    peta_friendly_topology = tad_adaptor.ditto_to_peta(ditto_topology)
    
    # Resolve target IP to a thingId by looking up the network.ip_address feature
    target_id = mock_target_id
    if not target_id:
        logging.info(f"[Ditto] Resolving IP {target_ip} → thingId ...")
        for thing in ditto_topology:
            ip = (
                thing.get("features", {})
                .get("network", {})
                .get("properties", {})
                .get("ip_address")
            )
            logging.info(f"[Ditto]   checking {thing['thingId']}  ip={ip}")
            if ip == target_ip:
                target_id = thing["thingId"]
                logging.info(f"[Ditto] Matched: {target_ip} → {target_id}")
                break
        if not target_id:
            logging.warning(
                f"[Ditto] No thingId found for IP {target_ip} — defaulting to first fallback thing"
            )
            target_id = "cobalt.sdt:toe-00000000-0000-0000-0000-000000000000-RESOURCE-static-1"
    
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
            
            # 5. Send patch to SDT

            # Extract toe_id from thing attributes (most reliable) or from thingId
            source_attrs = source_thing.get("attributes", {})
            sdt_toe_id = source_attrs.get("toe_id", "00000000-0000-0000-0000-000000000000")
            sdt_category = source_attrs.get("category", "RESOURCE")
            try:
                sdt_response = requests.put(
                    f"{SDT_SERVICE_URL}?toe_id={sdt_toe_id}&category={sdt_category}",
                    json=sdt_patch_payload, timeout=5
                )
                if sdt_response.status_code == 200:
                    logging.info(f"[SDT] Patch enforced on {target_id}.")
                else:
                    logging.warning(f"[SDT] Returned {sdt_response.status_code}: {sdt_response.text[:100]}")
            except Exception as sdt_exc:
                logging.error(f"[SDT] Service unreachable: {sdt_exc}")

            return sdt_patch_payload
        else:
            logging.error(f"PETA Error {response.status_code}: {response.text}")
    except Exception as e:
        logging.error(f"Failed to trigger PETA: {e}")
    return None

import os
import glob
import pandas as pd

import flow_buffer as fb

LABEL_TO_PETA = {
    "dos":        "Denial_of_Service",
    "scan":       "Port_Scan",
    "bruteforce": "Brute_Force",
    1:            "Denial_of_Service",  # fallback for legacy binary models
}


def _resolve_target_ip(src_ip, dst_ip, topology_cache):
    """Return the victim-side IP from src/dst using topology role hints."""
    if topology_cache:
        for candidate in [src_ip, dst_ip]:
            for thing in topology_cache:
                ip = (
                    thing.get("features", {})
                    .get("network", {})
                    .get("properties", {})
                    .get("ip_address")
                )
                role = thing.get("attributes", {}).get("role", "")
                if ip == candidate and role not in ("workstation", "attacker"):
                    return candidate
    # Fallback: prefer the internal (10.x.x.x) IP
    return next(
        (ip for ip in [src_ip, dst_ip] if ip.startswith("10.")),
        src_ip or dst_ip or "10.0.0.10",
    )


def _predict_and_dispatch(feat_vec, src_ip, model, label_encoder, peta_url, topology_cache):
    """Run inference on a flow feature vector and trigger PETA if an attack is detected."""
    try:
        raw_pred = model.predict([feat_vec])[0]
        if label_encoder is not None:
            try:
                prediction = label_encoder.inverse_transform([raw_pred])[0]
            except Exception:
                prediction = str(raw_pred)
        else:
            prediction = str(raw_pred)

        peta_attack = LABEL_TO_PETA.get(prediction)
        logging.info(f"[TAD/flow] predicted={prediction} | src={src_ip} | peta={peta_attack}")

        if peta_attack:
            target_ip = _resolve_target_ip(src_ip, src_ip, topology_cache)
            logging.warning(
                f"ATTACK DETECTED [{prediction}] | src={src_ip} | target={target_ip} "
                f"| Triggering PETA ({peta_attack})..."
            )
            trigger_peta(peta_attack, target_ip, peta_url, cached_topology=topology_cache)
    except Exception as e:
        logging.debug(f"Flow inference error: {e}")


def main():
    parser = argparse.ArgumentParser(description="TAD Realtime Monitor")
    parser.add_argument("--model", required=False, help="Path to RandomForest .joblib model")
    parser.add_argument("--peta-url", default="http://localhost:8000/PETA/sdt/impact", help="PETA Endpoint")
    parser.add_argument("--simulate", action="store_true", help="Run a manual simulation without Kafka")
    parser.add_argument("--csv", default=None, help="Process a specific CSV file instead of scanning TAD/data/")
    parser.add_argument("--flow-timeout", type=float, default=60.0,
                        help="Flow idle timeout in seconds for flow-level models (default: 60)")
    args = parser.parse_args()

    if args.simulate:
        logging.info("Running manual simulation...")
        trigger_peta("Denial_of_Service", "10.0.0.10", args.peta_url)
        return

    logging.info(f"Loading Model: {args.model}")
    model = None
    label_encoder = None
    cross_flow_stats = None
    use_flow_model = False
    try:
        if args.model:
            artifact = joblib.load(args.model)
            if isinstance(artifact, dict):
                model = artifact["model"]
                label_encoder = artifact.get("label_encoder")
                cross_flow_stats = artifact.get("cross_flow_stats")  # present in flow models
                use_flow_model = cross_flow_stats is not None
            else:
                model = artifact
    except Exception as e:
        logging.warning(f"Could not load model: {e}. Inference will be disabled.")

    if use_flow_model:
        logging.info(f"[TAD] Flow-level model detected (timeout={args.flow_timeout}s). "
                     "Buffering packets into flows before inference.")
        flow_buf = fb.FlowBuffer(timeout=args.flow_timeout, cross_flow_stats=cross_flow_stats)
    else:
        logging.info("[TAD] Per-packet model detected.")
        flow_buf = None

    # NFS / CSV Integration
    if args.csv:
        data_dir = os.path.dirname(os.path.abspath(args.csv))
        logging.info(f"Single-CSV mode: {args.csv}")
    else:
        data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data')
        logging.info("Starting NFS CSV Monitor on TAD/data/...")

    # Offset tracking: remembers how many rows were already processed per CSV
    processed_offsets: dict = {}

    # Fetch topology once at startup — no need to re-query Ditto on every attack row
    logging.info("[Ditto] Fetching topology once at startup...")
    topology_cache = get_topology_from_sdt()
    logging.info(f"[Ditto] Topology cached: {len(topology_cache)} thing(s).")

    while True:
        if args.csv:
            csv_files = [os.path.abspath(args.csv)]
        else:
            csv_files = glob.glob(os.path.join(data_dir, "*.csv"))
        for csv_file in csv_files:
            try:
                df = pd.read_csv(csv_file)
                last_offset = processed_offsets.get(csv_file, 0)
                new_rows = df.iloc[last_offset:]

                if new_rows.empty:
                    continue

                logging.info(f"Processing {len(new_rows)} new row(s) from {os.path.basename(csv_file)}")

                for index, row in new_rows.iterrows():
                    if model is None:
                        continue

                    if use_flow_model:
                        # ── Flow-level path ───────────────────────────────
                        row_dict = row.to_dict()
                        completed = flow_buf.add(row_dict)
                        for feat_vec, src_ip in completed:
                            _predict_and_dispatch(
                                feat_vec, src_ip, model, label_encoder,
                                args.peta_url, topology_cache,
                            )
                    else:
                        # ── Per-packet path (legacy) ───────────────────────
                        try:
                            row_features = feature_utils.extract_features_from_row(row)
                            raw_pred = model.predict([row_features])[0]

                            if label_encoder is not None:
                                try:
                                    prediction = label_encoder.inverse_transform([raw_pred])[0]
                                except Exception:
                                    prediction = str(raw_pred)
                            else:
                                prediction = str(raw_pred)

                            peta_attack = LABEL_TO_PETA.get(prediction)
                            actual_label = row.get("label", "unknown")
                            logging.info(f"[TAD] actual={actual_label} | predicted={prediction} | peta_attack={peta_attack}")

                            if peta_attack:
                                src_ip = str(row.get("src_ip", ""))
                                dst_ip = str(row.get("dst_ip", ""))
                                target_ip = _resolve_target_ip(src_ip, dst_ip, topology_cache)
                                logging.warning(
                                    f"ATTACK DETECTED [{prediction}] | src={src_ip} "
                                    f"dst={dst_ip} | target={target_ip} | Triggering PETA ({peta_attack})..."
                                )
                                trigger_peta(peta_attack, target_ip, args.peta_url, cached_topology=topology_cache)

                        except Exception as row_err:
                            logging.debug(f"Skipping row {index}: {row_err}")

                # Advance offset to avoid reprocessing
                processed_offsets[csv_file] = last_offset + len(new_rows)

            except Exception as e:
                if args.csv:
                    break
                logging.error(f"Failed to read {csv_file}: {e}")

        # Drain idle flows at end of each polling cycle
        if use_flow_model and flow_buf and model is not None:
            for feat_vec, src_ip in flow_buf.drain():
                _predict_and_dispatch(
                    feat_vec, src_ip, model, label_encoder,
                    args.peta_url, topology_cache,
                )

        # Single-CSV mode: one pass only — no need to keep polling
        if args.csv:
            break

        # Polling delay
        time.sleep(10)

if __name__ == "__main__":
    main()
