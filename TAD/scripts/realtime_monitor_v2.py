"""
realtime_monitor_v2.py
======================
Copy of realtime_monitor.py, extended to run the 30-feature per-packet
NewDataset models. The original realtime_monitor.py is UNCHANGED.

Adds vs the original:
  * routes 30-feature artifacts (taxonomy key) through newdataset_inference
    .PacketClassifier -- the stateful per-src_ip ring buffer the rolling
    ctx_* features require. The legacy path only builds 10 features and would
    raise ValueError (silently swallowed) with these models.
  * LABEL_TO_PETA extended with the new labels.
  * per-row failures log at WARNING, not DEBUG (they used to vanish).

    python3 TAD/scripts/realtime_monitor_v2.py \
        --model TAD/models/multiclass/hgb_newdataset_4class.joblib \
        --csv TAD/data/NewDataset15062026/labeled_packets_deep.csv
"""

import argparse
import json
import logging
import os
import time
from collections import defaultdict

import joblib
import requests

import tad_adaptor_v2 as tad_adaptor
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

# ── topology: loaded from the local PETA file (SDT is NOT in this workflow) ──
TOPOLOGY_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", "PETA",
    "ncsrd_topology_peta.json")

# Where the finished threat model + selected mitigation is delivered.
# Empty = no consumer deployed, skip delivery. Set to the real endpoint to enable;
# see send_threat_model() for why a dead URL here stalls /ingest/raw.
OUTPUT_URL = os.environ.get("TAD_OUTPUT_URL", "")

# Kept short on purpose: this runs inline per detection, so it is charged
# against the caller's read timeout on every attack in the batch.
OUTPUT_TIMEOUT = float(os.environ.get("TAD_OUTPUT_TIMEOUT", "2"))

_topology_file_cache = None


def load_peta_topology(path=None):
    """Load `{"topology": {"nodes": [...], "links": [...]}}` from disk.

    Already in PETA's format, so no Ditto conversion (tad_adaptor.ditto_to_peta)
    is needed at all in this workflow.
    """
    global _topology_file_cache
    if _topology_file_cache is None:
        p = path or TOPOLOGY_FILE
        with open(p) as f:
            _topology_file_cache = json.load(f)
        n = _topology_file_cache.get("topology", {}).get("nodes", [])
        logging.info(f"[TOPO] loaded {len(n)} assets from {os.path.basename(p)}")
    return _topology_file_cache


def _resolve_target_id(target_ip, topology):
    """victim IP -> node id, straight from the PETA topology file."""
    for n in topology.get("topology", {}).get("nodes", []):
        if n.get("ip") == target_ip:
            return n.get("id")
    return None


def send_threat_model(threat_model, output_url=None):
    """POST the threat model (incl. the selected mitigation) to the consumer.

    This REPLACES the old SDT/Ditto enforcement patch — see the commented-out
    block in trigger_peta().

    No consumer deployed? Set the URL to "" / "none" / "off". Otherwise every
    detection blocks the ingest request for the full connect timeout, which
    stalls /ingest/raw for minutes on an attack-heavy batch.
    """
    url = output_url if output_url is not None else OUTPUT_URL
    if not url or str(url).lower() in ("none", "off", "disabled"):
        return False
    try:
        r = requests.post(url, json=threat_model, timeout=OUTPUT_TIMEOUT)
        if r.status_code < 300:
            logging.info(f"[OUT] threat model delivered -> {url} ({r.status_code})")
            return True
        logging.warning(f"[OUT] {url} returned {r.status_code}: {r.text[:120]}")
    except Exception as e:
        logging.warning(f"[OUT] endpoint unreachable ({url}): {e}")
    return False


def trigger_peta(attack_type, target_ip, peta_url, mock_target_id=None,
                 cached_topology=None, output_url=None):
    """Call PETA for a mitigation, then deliver the threat model to OUTPUT_URL.

    SDT/Ditto are NOT part of this workflow: topology comes from the local PETA
    topology file and the result is POSTed to an output endpoint instead of
    being patched into the Digital Twin.
    """
    logging.info(f"Triggering remediation for {attack_type} on {target_ip}...")

    # 1. Topology straight from the PETA file (already PETA-format)
    topology = cached_topology if cached_topology is not None else load_peta_topology()

    # 2. Resolve the victim IP to a topology node id. If it's not a managed
    # asset, name it honestly (unmanaged:<ip>) rather than silently blaming the
    # first node in the file — that misattributed every unplaceable victim.
    target_id = mock_target_id or _resolve_target_id(target_ip, topology)
    if not target_id:
        target_id = f"unmanaged:{target_ip}"
        logging.warning(f"[TOPO] {target_ip} not a managed asset — target={target_id}")

    payload = {
        "cyber_attack": {
            "type": attack_type,
            "targeted_asset": target_id,
            "vector": {
                "attack_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "attack_location": "Internal",
            },
        },
        "organization_assets": topology,
    }

    try:
        # 3. Ask PETA for the best mitigation
        response = requests.post(peta_url, json=payload, timeout=10)
        if response.status_code == 200:
            peta_result = response.json()
            sel = (peta_result.get("threat_model", {}).get("control_action", {})
                              .get("mitigation_action", {}).get("selected_mitigation", {}))
            logging.info(f"PETA mitigation for {target_id}: "
                         f"{sel.get('mitigation_id')} — {sel.get('description')}")

            # 4. Deliver the threat model + mitigation to the output endpoint
            send_threat_model(peta_result, output_url)
            return peta_result

        logging.error(f"PETA Error {response.status_code}: {response.text[:200]}")
    except Exception as e:
        logging.error(f"Failed to trigger PETA: {e}")
    return None


# ─────────────────────────────────────────────────────────────────────────────
# SDT / Ditto enforcement — DISABLED: SDT is not part of this workflow.
# Re-enable by restoring this block (and get_topology_from_sdt above) if the
# Digital Twin is put back in the loop.
#
#     source_thing = next((t for t in ditto_topology
#                          if t.get("thingId") == target_id), {})
#     sdt_patch_payload = tad_adaptor.build_sdt_mitigation_patch(
#         peta_result, source_thing)
#     source_attrs = source_thing.get("attributes", {})
#     sdt_toe_id   = source_attrs.get("toe_id", "00000000-0000-0000-0000-000000000000")
#     sdt_category = source_attrs.get("category", "RESOURCE")
#     try:
#         sdt_response = requests.put(
#             f"{SDT_SERVICE_URL}?toe_id={sdt_toe_id}&category={sdt_category}",
#             json=sdt_patch_payload, timeout=5)
#         if sdt_response.status_code == 200:
#             logging.info(f"[SDT] Patch enforced on {target_id}.")
#         else:
#             logging.warning(f"[SDT] Returned {sdt_response.status_code}")
#     except Exception as sdt_exc:
#         logging.error(f"[SDT] Service unreachable: {sdt_exc}")
# ─────────────────────────────────────────────────────────────────────────────

import os
import glob
import pandas as pd

import flow_buffer as fb

import newdataset_inference as ndi

LABEL_TO_PETA = {
    # legacy 4-class labels
    "dos":        "Denial_of_Service",
    "scan":       "Port_Scan",
    "bruteforce": "Brute_Force",
    1:            "Denial_of_Service",  # fallback for legacy binary models
    # NewDataset 5-class labels (single source of truth: newdataset_inference)
    **ndi.LABEL_TO_PETA,
}

# PETA only knows these; post_exploitation -> Host_Compromise is NOT among them
# yet, so it is detected but alert-only (no dispatch) until attack_mapping.json
# gains the entry.
KNOWN_PETA_TYPES = ndi.KNOWN_PETA_TYPES


def _row_to_packet(row) -> dict:
    """CSV row -> canonical packet dict for PacketClassifier.

    Accepts either the NewDataset schema (packet_time_utc/packet_length/letter
    flags) or the v2 schema (timestamp/frame_len/hex flags).

    tcp_window_size and tcp_ack are FORCED to 0 and tcp_len is IGNORED on
    purpose: the model was trained on a capture without those columns, so
    payload_len is always the frame_len-54 estimate. Feeding the real v2 values
    here would be train/serve skew.
    """
    if "packet_time_utc" in row:
        return ndi.normalize_newdataset_row(dict(row))
    return {
        "timestamp":       ndi._num(row.get("timestamp")),
        "src_ip":          row.get("src_ip", ""),
        "dst_ip":          row.get("dst_ip", ""),
        "src_port":        ndi._num(row.get("src_port")),
        "dst_port":        ndi._num(row.get("dst_port")),
        "protocol":        str(row.get("protocol", "")).upper(),
        "tcp_flags":       ndi._parse_flags_any(row.get("tcp_flags")),
        "frame_len":       ndi._num(row.get("frame_len")),
        "ip_ttl":          ndi._num(row.get("ip_ttl")),
        "tcp_window_size": 0.0,
        "tcp_ack":         0.0,
    }


def _dispatch(res, peta_url, topology_cache, output_url=None):
    """Route one wrapper result to PETA (or alert-only)."""
    if res["label"] == "benign":
        return
    if res["dispatch"]:
        target_ip, _ = _resolve_target_ip(res["src_ip"], res["dst_ip"],
                                          topology_cache, res.get("peta_type"))
        logging.warning(
            f"ATTACK DETECTED [{res['label']}] conf={res['confidence']:.2f} | "
            f"src={res['src_ip']} dst={res['dst_ip']} | target={target_ip} | "
            f"Triggering PETA ({res['peta_type']})..."
        )
        trigger_peta(res["peta_type"], target_ip, peta_url,
                     cached_topology=topology_cache, output_url=output_url)
    elif res["peta_type"]:
        logging.warning(
            f"ALERT-ONLY [{res['label']}] src={res['src_ip']} -> PETA type "
            f"'{res['peta_type']}' not in attack_mapping.json; no mitigation dispatched."
        )


def _resolve_target_ip(src_ip, dst_ip, topology_cache, peta_type=None):
    """Return (victim_ip, is_managed) using the PETA-format topology.

    Which side is the victim depends on the attack DIRECTION:
      * Host_Compromise (reverse shell / post-exploitation) usually runs
        victim -> attacker, so the compromised internal host is the SOURCE.
        If the source isn't managed (attacker -> victim command flow), fall
        back to the destination.
      * Everything else (scan / brute-force / DoS) targets the DESTINATION;
        the source is the attacker, so we do NOT fall back to it — an outbound
        scan to an external IP must resolve to that external (unmanaged) IP,
        not to the internal scanner.

    is_managed is False when the victim isn't one of our topology assets
    (external or unlisted). Callers alert-only on those instead of mitigating a
    machine we don't own.
    """
    nodes = (topology_cache or {}).get("topology", {}).get("nodes", [])
    known = {n.get("ip") for n in nodes if n.get("ip")}

    if peta_type == "Host_Compromise":
        primary, secondary = src_ip, dst_ip
    else:
        primary, secondary = dst_ip, src_ip

    if primary and primary in known:
        return primary, True
    # For a compromise, the victim may be the other side (attacker -> victim).
    if peta_type == "Host_Compromise" and secondary and secondary in known:
        return secondary, True
    # Victim side isn't a managed asset -> report it honestly (no nodes[0] guess).
    return (primary or secondary or "unknown"), False


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
            target_ip, _ = _resolve_target_ip(src_ip, src_ip, topology_cache, peta_attack)
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
    parser.add_argument("--window", type=int, default=20,
                        help="Rolling context window k per src_ip (must match training: 20)")
    parser.add_argument("--max-sources", type=int, default=50000,
                        help="LRU cap on per-src state (spoofed-flood protection)")
    parser.add_argument("--idle-timeout", type=float, default=300.0,
                        help="Evict per-src state idle for this many seconds")
    parser.add_argument("--topology-file", default=TOPOLOGY_FILE,
                        help="PETA-format topology (SDT is not used in this workflow)")
    parser.add_argument("--output-url", default=OUTPUT_URL,
                        help="where the threat model + mitigation is POSTed (DUMMY by default)")
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
    packet_clf = None          # NewDataset 30-feature wrapper
    try:
        if args.model:
            artifact = joblib.load(args.model)
            if isinstance(artifact, dict):
                model = artifact["model"]
                label_encoder = artifact.get("label_encoder")
                cross_flow_stats = artifact.get("cross_flow_stats")  # present in flow models
                use_flow_model = cross_flow_stats is not None
                # NewDataset artifacts carry a `taxonomy` key and need the
                # stateful per-src wrapper (rolling ctx_* features).
                if not use_flow_model and artifact.get("taxonomy"):
                    packet_clf = ndi.PacketClassifier(
                        args.model, k=args.window,
                        max_sources=args.max_sources,
                        idle_timeout=args.idle_timeout,
                    )
            else:
                model = artifact
    except Exception as e:
        logging.warning(f"Could not load model: {e}. Inference will be disabled.")

    if packet_clf is not None:
        logging.info(f"[TAD] NewDataset per-packet model detected "
                     f"(taxonomy={packet_clf.taxonomy}, {len(packet_clf.feature_names)} feats). "
                     "Using stateful wrapper + batched predict.")
        flow_buf = None
    elif use_flow_model:
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
    # SDT is not in this workflow — topology comes from the local PETA file
    topology_cache = load_peta_topology(args.topology_file)
    logging.info(f"[TOPO] {len(topology_cache['topology']['nodes'])} assets cached.")

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

                # ── NewDataset wrapper path: build features per row (stateful,
                # in order) then ONE batched predict for the whole chunk.
                if packet_clf is not None:
                    try:
                        pkts = [_row_to_packet(r) for _, r in new_rows.iterrows()]
                        results = packet_clf.classify_batch(pkts)
                        for res, (_, row) in zip(results, new_rows.iterrows()):
                            actual = row.get("label", "unknown")
                            logging.info(f"[TAD] actual={actual} | predicted={res['label']} "
                                         f"| conf={res['confidence']:.2f} | peta={res['peta_type']}")
                            _dispatch(res, args.peta_url, topology_cache, args.output_url)
                    except Exception as batch_err:
                        logging.warning(f"Wrapper batch failed: {batch_err}", exc_info=True)
                    processed_offsets[csv_file] = last_offset + len(new_rows)
                    continue

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
                                target_ip, _ = _resolve_target_ip(src_ip, dst_ip,
                                                                  topology_cache, peta_attack)
                                logging.warning(
                                    f"ATTACK DETECTED [{prediction}] | src={src_ip} "
                                    f"dst={dst_ip} | target={target_ip} | Triggering PETA ({peta_attack})..."
                                )
                                trigger_peta(peta_attack, target_ip, args.peta_url, cached_topology=topology_cache)

                        except Exception as row_err:
                            # was logging.debug -> a feature/shape mismatch silently
                            # skipped EVERY row and the monitor looked healthy.
                            logging.warning(f"Skipping row {index}: {row_err}")

                # Advance offset to avoid reprocessing
                processed_offsets[csv_file] = last_offset + len(new_rows)

            except Exception as e:
                if args.csv:
                    break
                logging.error(f"Failed to read {csv_file}: {e}")

        # Drain idle flows at end of each polling cycle
        if use_flow_model and flow_buf is not None and model is not None:
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
