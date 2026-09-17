"""
tad_api.py
==========
TAD ingest endpoint — push traffic to TAD instead of tailing CSVs.

Ports:  Ditto 8080 · PETA 8000 · SDT 8001 · **TAD 8002**

    PYTHONPATH=$(pwd)/TAD/scripts uvicorn tad_api:app --port 8002
    # or: python3 TAD/scripts/tad_api.py --port 8002

Endpoints
---------
  POST /ingest        one or many packets -> predictions (+ PETA dispatch)
  POST /ingest/csv    a v2 / NewDataset CSV chunk as rows
  GET  /health        model + state info
  GET  /stats         counters
  GET  /active        attacks happening right now (deduped, real-time view)
  POST /reset         clear per-source state

Why batch: features MUST be built per packet in arrival order (rolling per-src
state), but the sklearn call should be made once — ~7,400 pkt/s batched vs
~11 pkt/s one-at-a-time. Always POST a list.

ORDER MATTERS: packets are stateful. Send them in arrival/timestamp order, and
send a given src_ip's packets to ONE replica (this service is not horizontally
shardable without partitioning by src_ip).

PETA dispatch is OFF by default (--dispatch to enable) so you can ingest without
mutating the Digital Twin.
"""

import argparse
import json
import logging
import logging.handlers
import os
import sys
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)
import newdataset_inference as ndi

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")

DEFAULT_MODEL = os.path.join(SCRIPT_DIR, "..", "models", "multiclass",
                             "hgb_newdataset_4class.joblib")
DEFAULT_GNN_MODEL = os.path.join(SCRIPT_DIR, "..", "models", "gnn", "victim_sage.pt")

app = FastAPI(title="TAD Ingest API", version="1.0")

# ── runtime state ────────────────────────────────────────────────────────────
_clf: "ndi.PacketClassifier | None" = None
_lock = threading.Lock()          # classifier state is mutable -> serialise

# GNN victim-ID: a CONFIRMING signal alongside _resolve_target_ip, never a
# dependency. _graph is always created (cheap, no torch); _gnn_scorer stays
# None if the artifact is missing/disabled/fails to load, and every call site
# checks for that -- the pipeline must keep dispatching correctly with it off.
_graph = None
_gnn_scorer = None

_cfg: dict[str, Any] = {"dispatch": False, "peta_url": None, "model": DEFAULT_MODEL,
        "gnn_model": DEFAULT_GNN_MODEL,
        # hard cap on rows per request. Without it an unbounded `rows` array is
        # itself a DoS vector (one huge POST -> OOM). 413 tells the client to split.
        "max_batch": 10_000, "output_url": None, "topology_file": None,
        # dispatch de-dup: call PETA at most once per (attack_type, target) every
        # `dispatch_cooldown` s. Without this a scan/DDoS fires ONE PETA call per
        # packet (24k calls for one nmap scan) and TAD falls minutes behind.
        "dispatch_cooldown": 30.0, "active_timeout": 60.0,
        # confidence gate: below this the prediction is too uncertain to fire a
        # real (IP-banning / traffic-dropping) mitigation -> logged alert-only.
        "dispatch_min_confidence": 0.7,
        # SUSTAINED-ATTACK gate: a real attack is a flood (hundreds of packets
        # per window); a false positive on benign traffic is a few scattered
        # packets. Require >= sustain_min attack packets for one (attack_type,
        # victim) within the last sustain_window seconds before EVER dispatching.
        # Measured on a real capture: real attacks peaked 140-1471 pkts/30s per
        # class, every false positive stayed <= 82 -- so 100/30s cleanly
        # separates them. Set sustain_min=0 to disable (revert to per-packet).
        "sustain_min": 100, "sustain_window": 30.0,
        # GNN VETO gate: the victim-ID GNN is normally confirming-only, but when
        # it has enough evidence (>= MIN_RELIABLE_ATTACK_PKTS) and is highly
        # confident the resolved target is NOT a victim (score < this), suppress
        # the dispatch instead of firing a mitigation on it. Catches the case
        # where HGB mislabels benign traffic to a non-victim host. Set to 0 to
        # disable (pure confirming-only behaviour).
        "gnn_veto_threshold": 0.1,
        # detection logging
        "log_format": "text", "log_benign": False, "console_detections": True}
_topology_cache = None
_detect_log: "logging.Logger | None" = None
_stats = {"packets": 0, "attacks": 0, "dispatched": 0, "suppressed": 0,
          "low_confidence": 0, "external": 0, "alert_only": 0, "benign": 0,
          "unconfirmed": 0, "gnn_vetoed": 0}

# Live attacks: (peta_type, target_ip) -> aggregate. Bounded by #assets x #types
# (~72), so the dict itself can't blow up; the per-entry source set is capped.
_active: dict = {}
_active_lock = threading.Lock()


# ── schemas ──────────────────────────────────────────────────────────────────
class Packet(BaseModel):
    timestamp: float = Field(..., description="epoch seconds (float)")
    src_ip: str
    dst_ip: str = ""
    src_port: float = 0
    dst_port: float = 0
    protocol: str = "TCP"                  # upper-cased server-side
    tcp_flags: Any = 0                     # int bitmask | "0x02" | "PA"
    frame_len: float = 0
    ip_ttl: float = 0
    # tcp_window_size / tcp_ack / tcp_len are intentionally NOT accepted:
    # the model was trained on a capture without them. See _to_canonical().


class IngestRequest(BaseModel):
    packets: list[Packet]
    dispatch: bool | None = Field(
        None, description="override server default for this call")


class Prediction(BaseModel):
    label: str
    peta_type: str | None
    confidence: float | None
    dispatch: bool
    src_ip: str
    dst_ip: str
    pkt_time: float | None = None      # packet capture time (epoch seconds)


class IngestResponse(BaseModel):
    count: int
    predictions: list[Prediction]
    attacks: int
    dispatched: int                 # PETA calls actually made
    suppressed: int = 0             # attack packets folded into an active attack
    low_confidence: int = 0         # attacks below the confidence gate (not dispatched)
    external: int = 0               # victim not a managed asset -> alerted, not mitigated
    alert_only: int


class CsvRow(BaseModel):
    rows: list[dict]
    schema_hint: Literal["auto", "v2", "newdataset"] = "auto"
    dispatch: bool | None = None


# ── helpers ──────────────────────────────────────────────────────────────────
def _to_canonical(p: Packet) -> dict:
    """Pydantic packet -> the dict PacketClassifier expects.

    tcp_window_size/tcp_ack forced to 0 and tcp_len ignored: training saw only
    zeros for those, so payload_len is always the frame_len-54 estimate.
    Supplying real values here would be train/serve skew.
    """
    return {
        "timestamp": p.timestamp,
        "src_ip": p.src_ip, "dst_ip": p.dst_ip,
        "src_port": p.src_port, "dst_port": p.dst_port,
        "protocol": str(p.protocol).upper(),
        "tcp_flags": ndi._parse_flags_any(p.tcp_flags),
        "frame_len": p.frame_len, "ip_ttl": p.ip_ttl,
        "tcp_window_size": 0.0, "tcp_ack": 0.0,
    }


def _get_clf() -> "ndi.PacketClassifier":
    global _clf
    if _clf is None:
        _clf = ndi.PacketClassifier(_cfg["model"])
    return _clf


def _get_graph():
    """Streaming host graph for the GNN victim scorer. Always created (cheap,
    no torch import) so /victims and the dispatch log can check it even if
    the GNN model itself never loaded."""
    global _graph
    if _graph is None:
        import gnn_victim_id as gvi
        _graph = gvi.HostGraphState()
    return _graph


def _try_load_gnn(model_path: str):
    """Best-effort GNN load. Any failure here (missing file, bad artifact,
    torch/torch_geometric not installed) must NOT stop the API from serving
    HGB detections -- logs a warning and leaves _gnn_scorer as None."""
    global _gnn_scorer
    if not model_path or not os.path.exists(model_path):
        logging.info(f"[TAD-API] no GNN model at {model_path} -- victim "
                     f"confirmation disabled (HGB detection/dispatch unaffected)")
        return
    try:
        import gnn_victim_id as gvi
        _gnn_scorer = gvi.GNNVictimScorer(model_path)
        logging.info(f"[TAD-API] GNN victim scorer loaded from {model_path}")
    except Exception as e:
        logging.warning(f"[TAD-API] GNN scorer failed to load ({e}) -- victim "
                        f"confirmation disabled, HGB detection/dispatch unaffected")


def _log_detection(res: dict, action: str):
    """Write ONE detection to the detection log (file), if configured.

    Two formats:
      jsonl -> one JSON object per line, for analysis/SIEM ingest
      text  -> human-readable
    """
    log = _detect_log
    if log is None:
        return
    now = datetime.now(timezone.utc)
    ts = now.isoformat(timespec="milliseconds")
    # when the packet was actually captured (vs `ts` = when TAD processed it).
    pt = res.get("pkt_time")
    if pt:
        pkt_dt = datetime.fromtimestamp(pt, timezone.utc)
        pkt_iso = pkt_dt.isoformat(timespec="milliseconds")
        lag = round((now - pkt_dt).total_seconds(), 1)     # processing lag, seconds
    else:
        pkt_iso, lag = None, None
    gnn_conf = res.get("gnn_victim_confidence")
    if _cfg["log_format"] == "jsonl":
        log.info(json.dumps({
            "ts": ts, "pkt_time": pkt_iso, "lag_s": lag,
            "label": res["label"], "peta_type": res["peta_type"],
            "confidence": round(res["confidence"], 4) if res["confidence"] is not None else None,
            "src_ip": res["src_ip"], "dst_ip": res["dst_ip"], "action": action,
            "gnn_victim_confidence": round(gnn_conf, 4) if gnn_conf is not None else None,
        }))
    else:
        conf = f"{res['confidence']:.3f}" if res["confidence"] is not None else "n/a"
        pkt_field = f"pkt={pkt_iso} lag={lag}s " if pkt_iso else ""
        gnn_field = f" gnn_victim={gnn_conf:.3f}" if gnn_conf is not None else ""
        log.info(f"{ts} {action:<11} {res['label']:<18} conf={conf} "
                 f"src={res['src_ip']:<15} dst={res['dst_ip']:<15} "
                 f"{pkt_field}peta={res['peta_type']}{gnn_field}")


def _dispatch_one(res: dict) -> str:
    """Resolve the victim, then act. Returns one of:
      "dispatched"  - a PETA call was made for this (attack_type, victim)
      "suppressed"  - folded into an already-active attack (cooldown)
      "unconfirmed" - detected but below the sustained-attack volume gate
                      (a few scattered packets, not a flood) -> not dispatched
      "gnn_vetoed"  - GNN has evidence and is confident this is NOT a victim
                      -> suppressed (HGB likely mislabeled benign traffic)
      "external"    - victim isn't a managed asset -> alerted, not mitigated

    Collapsing floods (suppressed) keeps /ingest real-time; the external path
    keeps PETA acting only on assets we own; the unconfirmed path stops a
    single misclassified benign packet from firing a real mitigation; the
    gnn_vetoed path lets the victim-ID GNN overrule a confident-but-wrong HGB
    attack label on a host it can see is not actually under attack.
    """
    import realtime_monitor_v2 as rm
    src, dst = res["src_ip"], res["dst_ip"]
    target_ip, is_managed = rm._resolve_target_ip(src, dst, _topology_cache,
                                                  res["peta_type"])

    # GNN victim confirmation -- CONFIRMING signal only, never gates dispatch.
    # Scored here (not per-packet): _dispatch_one is already cooldown-rate-
    # limited, so this stays cheap even under a flood.
    gnn_conf = None
    if _gnn_scorer is not None:
        import gnn_victim_id as gvi
        graph = _get_graph()
        if graph.attack_pkt_count(target_ip) >= gvi.MIN_RELIABLE_ATTACK_PKTS:
            try:
                scores = _gnn_scorer.score(graph)
                gnn_conf = scores.get(target_ip)
            except Exception as e:
                logging.warning(f"[gnn] scoring failed ({e}); continuing without it")

    # Q2: victim isn't one of our assets (external / unlisted) -> alert, no PETA.
    if not is_managed:
        _log_detection({**res, "dst_ip": target_ip}, "ALERT_EXTERNAL")
        return "external"

    # GNN VETO: gnn_conf is not None only when the GNN had enough evidence
    # (>= MIN_RELIABLE_ATTACK_PKTS). If it is then confident this host is NOT a
    # victim, overrule HGB and suppress -- this is HGB mislabeling benign
    # traffic to a non-victim host (e.g. monitoring chatter scored as a flood).
    if (_cfg["gnn_veto_threshold"] > 0 and gnn_conf is not None
            and gnn_conf < _cfg["gnn_veto_threshold"]):
        _log_detection({**res, "dst_ip": target_ip,
                        "gnn_victim_confidence": round(gnn_conf, 4)}, "GNN_VETO")
        return "gnn_vetoed"

    key = (res["peta_type"], target_ip)
    now = time.time()

    with _active_lock:
        e = _active.get(key)
        if e is None:
            e = _active[key] = {
                "peta_type": res["peta_type"], "target_ip": target_ip,
                "label": res["label"], "first_seen": now, "last_seen": now,
                "last_dispatch": 0.0, "packets": 0, "sources": set(),
                "mitigation": None, "gnn_victim_confidence": None,
                # sliding window of recent attack-packet timestamps for this
                # (type, victim), for the sustained-volume gate below.
                "recent": deque(), "recent_count": 0,
            }
        e["packets"] += 1
        e["last_seen"] = now
        e["label"] = res["label"]
        if gnn_conf is not None:
            e["gnn_victim_confidence"] = round(gnn_conf, 4)
        if len(e["sources"]) < 1024:        # cap: a spoofed DDoS must not OOM here
            e["sources"].add(src)

        # Sustained-attack gate: prune the window, then require enough recent
        # attack packets before this (type, victim) may dispatch at all. Blocks
        # scattered false positives; a real flood crosses instantly. Once
        # crossed it stays dispatchable (cooldown then governs rate).
        win = _cfg["sustain_window"]
        recent = e["recent"]
        recent.append(now)
        while recent and now - recent[0] > win:
            recent.popleft()
        e["recent_count"] = len(recent)
        if _cfg["sustain_min"] > 0 and len(recent) < _cfg["sustain_min"] \
                and e["last_dispatch"] == 0.0:
            return "unconfirmed"            # not enough volume yet -> don't mitigate

        due = (now - e["last_dispatch"]) >= _cfg["dispatch_cooldown"]
        if not due:
            return "suppressed"             # fold into the active attack, no call

    if _cfg["console_detections"] and gnn_conf is not None:
        logging.warning(f"GNN victim confirmation: {target_ip} p(victim)={gnn_conf:.3f}")

    # Network I/O outside the lock. trigger_peta swallows its own errors -> None.
    result = rm.trigger_peta(res["peta_type"], target_ip, _cfg["peta_url"],
                             cached_topology=_topology_cache,
                             output_url=_cfg["output_url"])
    with _active_lock:
        e = _active.get(key)
        if e is not None:
            e["last_dispatch"] = now
            if result:
                sel = (result.get("threat_model", {}).get("control_action", {})
                             .get("mitigation_action", {}).get("selected_mitigation", {}))
                if sel:
                    e["mitigation"] = f"{sel.get('mitigation_id')} — {sel.get('description')}"
    _log_detection({**res, "gnn_victim_confidence": gnn_conf},
                   "DISPATCHED" if result else "DISPATCH_ERR")
    return "dispatched"


def _dispatch_results(results: list[dict], do_dispatch: bool) -> tuple[int, int, int, int, int, int]:
    attacks = dispatched = alert_only = suppressed = low_conf = external = 0
    min_conf = _cfg["dispatch_min_confidence"]
    for res in results:
        if res["label"] == "benign":
            _stats["benign"] += 1
            if _cfg["log_benign"]:
                _log_detection(res, "BENIGN")
            continue
        attacks += 1
        _stats["attacks"] += 1
        if res["dispatch"]:
            conf = res.get("confidence")
            # Too uncertain to fire a real mitigation? Detect + log, but don't act.
            # conf is None only if predict_proba failed -> fail open (dispatch).
            if do_dispatch and conf is not None and conf < min_conf:
                low_conf += 1
                _stats["low_confidence"] += 1
                _log_detection(res, "LOW_CONF")
                if _cfg["console_detections"]:
                    logging.warning(f"LOW-CONF [{res['label']}] conf={conf:.2f}"
                                    f"<{min_conf} src={res['src_ip']} -> not dispatched")
            elif do_dispatch:
                outcome = _dispatch_one(res)
                if outcome == "dispatched":
                    dispatched += 1
                    _stats["dispatched"] += 1
                elif outcome == "suppressed":
                    suppressed += 1
                    _stats["suppressed"] += 1
                elif outcome == "unconfirmed":
                    # detected but below the sustained-volume gate -> not a
                    # confirmed attack yet. Counted separately, not dispatched.
                    _stats["unconfirmed"] += 1
                elif outcome == "gnn_vetoed":
                    # GNN overruled a confident-but-wrong HGB label -> suppressed.
                    _stats["gnn_vetoed"] += 1
                else:                        # "external" -> alerted, not mitigated
                    external += 1
                    _stats["external"] += 1
            else:
                _log_detection(res, "ATTACK")
                if _cfg["console_detections"]:
                    logging.warning(f"ATTACK [{res['label']}] src={res['src_ip']} "
                                    f"-> PETA {res['peta_type']} (dispatch disabled)")
        elif res["peta_type"]:
            alert_only += 1
            _stats["alert_only"] += 1
            _log_detection(res, "ALERT_ONLY")
            if _cfg["console_detections"]:
                logging.warning(f"ALERT-ONLY [{res['label']}] src={res['src_ip']} -> "
                                f"'{res['peta_type']}' not in attack_mapping.json")
    return attacks, dispatched, alert_only, suppressed, low_conf, external


def _check_batch(n: int):
    limit = _cfg["max_batch"]
    if n > limit:
        raise HTTPException(
            413, f"batch too large: {n} rows > max_batch={limit}. "
                 f"Split into smaller requests (200-500 rows is optimal).")


def setup_detection_log(path: str, fmt: str = "text",
                        max_mb: int = 100, backups: int = 5):
    """Route detections to their own rotating file, separate from server logs."""
    global _detect_log
    lg = logging.getLogger("tad.detections")
    lg.setLevel(logging.INFO)
    lg.propagate = False                      # don't duplicate into the console
    for h in list(lg.handlers):
        lg.removeHandler(h)
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    h = logging.handlers.RotatingFileHandler(
        path, maxBytes=max_mb * 1024 * 1024, backupCount=backups)
    h.setFormatter(logging.Formatter("%(message)s"))   # we format the line ourselves
    lg.addHandler(h)
    _detect_log = lg
    _cfg["log_format"] = fmt
    logging.info(f"[TAD-API] detections -> {path} "
                 f"(format={fmt}, rotate at {max_mb}MB x{backups})")
    return lg


def _run(packets: list[dict], do_dispatch: bool) -> IngestResponse:
    if not packets:
        return IngestResponse(count=0, predictions=[], attacks=0,
                              dispatched=0, alert_only=0)
    with _lock:                                   # rolling state is not thread-safe
        results = _get_clf().classify_batch(packets)
        _stats["packets"] += len(packets)
        if _gnn_scorer is not None:
            graph = _get_graph()
            for pkt, res in zip(packets, results):
                graph.update(pkt, res["label"])
    _unconf_before = _stats["unconfirmed"]
    attacks, dispatched, alert_only, suppressed, low_conf, external = \
        _dispatch_results(results, do_dispatch)
    unconfirmed = _stats["unconfirmed"] - _unconf_before
    if not _cfg["console_detections"]:
        logging.info(f"[batch] {len(results)} pkts | attacks={attacks} "
                     f"alert_only={alert_only} dispatched={dispatched} "
                     f"suppressed={suppressed} unconfirmed={unconfirmed} "
                     f"low_conf={low_conf} external={external}")
    return IngestResponse(
        count=len(results), predictions=[Prediction(**r) for r in results],
        attacks=attacks, dispatched=dispatched, suppressed=suppressed,
        low_confidence=low_conf, external=external, alert_only=alert_only)


# ── routes ───────────────────────────────────────────────────────────────────
@app.post("/ingest", response_model=IngestResponse)
def ingest(req: IngestRequest):
    """Score packets. Send them in arrival order — features are stateful."""
    _check_batch(len(req.packets))
    do = _cfg["dispatch"] if req.dispatch is None else req.dispatch
    return _run([_to_canonical(p) for p in req.packets], do)


@app.post("/ingest/raw", response_model=IngestResponse)
def ingest_raw(req: CsvRow):
    """Score records in the RAW capture schema — live stream or file, same thing.

    This is the route for a realtime sensor: send records using the dataset's own
    field names and we normalise on our side. Nothing here is file-specific.

        {"rows": [{"packet_time_utc": "2026-06-15T18:36:46.495822",
                   "src_ip": "10.163.1.105", "src_port": 33796,
                   "dst_ip": "10.163.1.204", "dst_port": 111,
                   "protocol": "tcp", "tcp_flags": "S",
                   "packet_length": 60, "ip_ttl": 38}, ...]}

    Accepts either schema, auto-detected:
      * NewDataset : packet_time_utc / packet_length / letter flags ("PA")
      * v2/tshark  : timestamp / frame_len / hex flags ("0x02")
    A `label` field, if present, is ignored.
    """
    _check_batch(len(req.rows))
    do = _cfg["dispatch"] if req.dispatch is None else req.dispatch
    pkts = []
    for row in req.rows:
        if req.schema_hint == "newdataset" or (
                req.schema_hint == "auto" and "packet_time_utc" in row):
            pkts.append(ndi.normalize_newdataset_row(row))
        else:
            pkts.append({
                "timestamp": ndi._num(row.get("timestamp")),
                "src_ip": row.get("src_ip", ""), "dst_ip": row.get("dst_ip", ""),
                "src_port": ndi._num(row.get("src_port")),
                "dst_port": ndi._num(row.get("dst_port")),
                "protocol": str(row.get("protocol", "")).upper(),
                "tcp_flags": ndi._parse_flags_any(row.get("tcp_flags")),
                "frame_len": ndi._num(row.get("frame_len")),
                "ip_ttl": ndi._num(row.get("ip_ttl")),
                "tcp_window_size": 0.0, "tcp_ack": 0.0,
            })
    return _run(pkts, do)


@app.get("/ingest/raw", include_in_schema=False)
def ingest_raw_probe():
    """Liveness probe. Ingest is POST-only; a GET here used to 405 in the logs."""
    return {
        "status": "ok",
        "endpoint": "/ingest/raw",
        "method": "POST",
        "hint": "POST {\"rows\": [...]} to score packets; GET /health for model status",
    }


@app.post("/ingest/csv", response_model=IngestResponse, include_in_schema=False)
def ingest_csv(req: CsvRow):
    """Deprecated alias for /ingest/raw — the name wrongly implied files."""
    return ingest_raw(req)


@app.get("/health")
def health():
    try:
        clf = _get_clf()
    except Exception as e:
        raise HTTPException(503, f"model not loaded: {e}")
    return {
        "status": "ok",
        "model": os.path.basename(_cfg["model"]),
        "taxonomy": clf.taxonomy,
        "features": len(clf.feature_names),
        "classes": [str(c) for c in clf.le.classes_],
        "active_sources": clf.active_sources,
        "max_sources": clf.max_sources,
        "dispatch_enabled": _cfg["dispatch"],
        "dispatch_cooldown_s": _cfg["dispatch_cooldown"],
        "dispatch_min_confidence": _cfg["dispatch_min_confidence"],
        "sustain_min_packets": _cfg["sustain_min"],
        "sustain_window_s": _cfg["sustain_window"],
        "gnn_veto_threshold": _cfg["gnn_veto_threshold"],
        "active_timeout_s": _cfg["active_timeout"],
        "max_batch": _cfg["max_batch"],
        "detection_log": getattr(_detect_log, "name", None) if _detect_log else None,
        "recommended_batch": "200-500 rows per request",
        "gnn_victim_id": {
            "loaded": _gnn_scorer is not None,
            "model": os.path.basename(_cfg["gnn_model"]) if _cfg.get("gnn_model") else None,
            "trained_on_hosts": getattr(_gnn_scorer, "trained_on_hosts", None),
        },
    }


@app.get("/stats")
def stats():
    clf = _get_clf()
    return {**_stats, "active_sources": clf.active_sources,
            "evicted_sources": clf.evicted}


@app.get("/active")
def active():
    """Attacks happening right now — one row per (attack_type, target), not per
    packet. An entry drops off once no packet has matched it for active_timeout
    seconds (that gap is the attack's end). This is the real-time view.
    """
    now = time.time()
    tout = _cfg["active_timeout"]
    out = []
    with _active_lock:
        for key in list(_active):                 # list(): we delete while iterating
            e = _active[key]
            if now - e["last_seen"] > tout:
                del _active[key]                  # attack ended -> forget it
                continue
            out.append({
                "peta_type": e["peta_type"],
                "label": e["label"],
                "target_ip": e["target_ip"],
                "started": datetime.fromtimestamp(
                    e["first_seen"], timezone.utc).isoformat(timespec="seconds"),
                "ongoing_seconds": round(now - e["first_seen"], 1),
                "idle_seconds": round(now - e["last_seen"], 1),
                "packets": e["packets"],
                "recent_packets": e.get("recent_count", 0),   # in sustain window
                "confirmed": e["last_dispatch"] > 0.0,         # crossed the volume gate
                "sources": len(e["sources"]),
                "mitigation": e["mitigation"],
                "gnn_victim_confidence": e.get("gnn_victim_confidence"),
            })
    out.sort(key=lambda a: a["ongoing_seconds"], reverse=True)
    return {"as_of": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "sustain_min_packets": _cfg["sustain_min"],
            "sustain_window_s": _cfg["sustain_window"],
            "count": len(out), "active_attacks": out}


@app.get("/victims")
def victims():
    """GNN victim-confidence ranking over every host with any predicted-attack
    traffic so far this run -- the live 'pinpoint the victim' view. This is a
    CONFIRMING signal alongside /active's deterministic target_ip resolution,
    not a replacement for it; 503 if the GNN model never loaded (HGB
    detection/dispatch keep working either way).
    """
    if _gnn_scorer is None:
        raise HTTPException(503, "GNN victim scorer not loaded -- see /health "
                                 "for why (gnn_victim_id.loaded=false)")
    import gnn_victim_id as gvi
    graph = _get_graph()
    scores = _gnn_scorer.score(graph)
    reliable = set(graph.attack_hosts(gvi.MIN_RELIABLE_ATTACK_PKTS))
    watching = set(graph.attack_hosts(1)) - reliable

    # Same known-managed-asset gate _resolve_target_ip uses for real dispatch:
    # without it, the attacker box itself ranks as a "victim" -- it's the
    # destination of its own targets' reply traffic within the same
    # attack-labelled window, so its features look victim-shaped too. This
    # was observed live (10.163.1.105 scored 0.95 with 942 attack packets
    # seen -- plenty of evidence, just structurally ambiguous without this
    # gate). Falls back to no gate (with a flag in the response) only if
    # topology wasn't loaded, e.g. --dispatch wasn't passed.
    known_assets = None
    if _topology_cache:
        known_assets = {n.get("ip") for n in
                        _topology_cache.get("topology", {}).get("nodes", []) if n.get("ip")}
        reliable &= known_assets
        watching &= known_assets

    ranked = sorted(
        ({"ip": ip, "victim_probability": round(p, 4),
          "attack_packets_seen": graph.attack_pkt_count(ip)}
         for ip, p in scores.items() if ip in reliable),
        key=lambda r: r["victim_probability"], reverse=True)
    return {"as_of": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "trained_on_hosts": _gnn_scorer.trained_on_hosts,
            "min_reliable_attack_packets": gvi.MIN_RELIABLE_ATTACK_PKTS,
            "known_asset_gate_applied": known_assets is not None,
            "count": len(ranked), "victims": ranked,
            "insufficient_data_yet": sorted(watching)}


@app.post("/reset")
def reset():
    global _clf, _graph
    with _lock:
        _clf = None
        _graph = None          # GNN scorer itself stays loaded; only the accumulated graph resets
        for k in _stats:
            _stats[k] = 0
    with _active_lock:
        _active.clear()
    return {"status": "reset"}


def main():
    global _topology_cache
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--port", type=int, default=8002)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--dispatch", action="store_true",
                    help="actually call PETA on detection (needs SDT/PETA/Ditto up)")
    ap.add_argument("--peta-url", default="http://localhost:8000/PETA/sdt/impact")
    ap.add_argument("--dispatch-cooldown", type=float, default=30.0,
                    help="min seconds between PETA calls for the same "
                         "(attack_type, target); collapses scan/DDoS floods")
    ap.add_argument("--active-timeout", type=float, default=60.0,
                    help="seconds of silence before an attack drops off /active")
    ap.add_argument("--dispatch-min-confidence", type=float, default=0.7,
                    help="don't fire a mitigation below this confidence (0..1); "
                         "the detection is still logged as LOW_CONF (alert-only)")
    ap.add_argument("--sustain-min", type=int, default=100,
                    help="SUSTAINED-ATTACK gate: require this many attack packets "
                         "for one (attack_type, victim) within --sustain-window "
                         "seconds before dispatching. Blocks scattered false "
                         "positives on benign traffic; a real flood crosses "
                         "instantly. 0 disables (revert to per-packet dispatch).")
    ap.add_argument("--sustain-window", type=float, default=30.0,
                    help="rolling window (seconds) for the --sustain-min count")
    ap.add_argument("--gnn-veto-threshold", type=float, default=0.1,
                    help="GNN VETO: when the victim-ID GNN has enough evidence "
                         "and scores the resolved target below this (i.e. is "
                         "confident it is NOT a victim), suppress the dispatch "
                         "instead of firing a mitigation. Catches HGB mislabeling "
                         "benign traffic to a non-victim host. 0 disables "
                         "(GNN stays confirming-only).")
    ap.add_argument("--max-batch", type=int, default=10_000,
                    help="reject requests with more rows than this (HTTP 413)")
    ap.add_argument("--log-file", default=None,
                    help="write every detection to this file (rotating)")
    ap.add_argument("--log-format", choices=["text", "jsonl"], default="text",
                    help="detection log format (jsonl = machine-readable)")
    ap.add_argument("--log-max-mb", type=int, default=100,
                    help="rotate the detection log at this size (MB)")
    ap.add_argument("--log-backups", type=int, default=5,
                    help="how many rotated detection logs to keep")
    ap.add_argument("--log-benign", action="store_true",
                    help="also log benign packets (very large)")
    ap.add_argument("--quiet-console", action="store_true",
                    help="no per-detection console lines; one summary per batch")
    ap.add_argument("--output-url", default=None,
                    help="where the threat model + mitigation is POSTed (DUMMY default in monitor)")
    ap.add_argument("--topology-file", default=None,
                    help="PETA-format topology file (SDT is not used)")
    ap.add_argument("--server-log", default=None,
                    help="also mirror server/console logs to this file")
    ap.add_argument("--gnn-model", default=DEFAULT_GNN_MODEL,
                    help="victim-ID GNN artifact from train_gnn_victim.py "
                         "(default: TAD/models/gnn/victim_sage.pt if present). "
                         "A confirming signal only -- HGB detection/dispatch work "
                         "identically whether or not this loads.")
    ap.add_argument("--no-gnn", action="store_true",
                    help="disable the victim-ID GNN even if --gnn-model exists")
    args = ap.parse_args()

    _cfg.update(model=args.model, dispatch=args.dispatch, peta_url=args.peta_url,
                max_batch=args.max_batch, log_benign=args.log_benign,
                output_url=args.output_url, topology_file=args.topology_file,
                dispatch_cooldown=args.dispatch_cooldown,
                active_timeout=args.active_timeout,
                dispatch_min_confidence=args.dispatch_min_confidence,
                sustain_min=args.sustain_min, sustain_window=args.sustain_window,
                gnn_veto_threshold=args.gnn_veto_threshold,
                console_detections=not args.quiet_console,
                gnn_model=None if args.no_gnn else args.gnn_model)
    if args.server_log:
        fh = logging.handlers.RotatingFileHandler(
            args.server_log, maxBytes=args.log_max_mb * 1024 * 1024,
            backupCount=args.log_backups)
        fh.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
        logging.getLogger().addHandler(fh)
    if args.log_file:
        setup_detection_log(args.log_file, args.log_format,
                            args.log_max_mb, args.log_backups)
    else:
        logging.warning("[TAD-API] no --log-file: detections are console-only")
    _get_clf()
    if _cfg["gnn_model"]:
        _try_load_gnn(_cfg["gnn_model"])
    if args.dispatch:
        import realtime_monitor_v2 as rm
        # SDT not used: topology comes from the local PETA file
        _topology_cache = rm.load_peta_topology(args.topology_file)
        sustain_desc = (f"{args.sustain_min} pkts/{args.sustain_window}s"
                        if args.sustain_min > 0 else "DISABLED (per-packet)")
        logging.info(f"[TAD-API] PETA dispatch ENABLED -> {args.peta_url} "
                     f"(cooldown={args.dispatch_cooldown}s, "
                     f"active_timeout={args.active_timeout}s, "
                     f"min_confidence={args.dispatch_min_confidence}, "
                     f"sustained-attack gate={sustain_desc})")
    else:
        logging.info("[TAD-API] dispatch disabled (detections logged only)")

    import uvicorn
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
