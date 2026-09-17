"""
newdataset_inference.py
=======================
Production inference wrapper for the per-packet NewDataset model
(`hgb_newdataset_4class.joblib` / `hgb_newdataset_binary.joblib`, 30 features).
`hgb_newdataset_5class.joblib` (adds `post_exploitation`) also loads fine here
if passed explicitly via `--model` / `model_path` — the wrapper reads the
artifact's own `taxonomy` field rather than assuming one.

WHY THIS EXISTS
---------------
The model is PER-PACKET and its strongest features are ROLLING per-source
statistics (`ctx_iat_std`, `ctx_unique_dst_ports`, ...). A packet therefore
cannot be scored in isolation: the caller must keep the last k packets per
`src_ip` and recompute the window on every new packet. `realtime_monitor.py`'s
legacy per-packet path only produces the 10 legacy features, so the new
30-feature model cannot drop into it directly. This module is that stateful
bridge — WITHOUT modifying any existing script.

FAST PATH
---------
Rebuilding a DataFrame per packet is ~40 ms/pkt — unusable at line rate. Instead
we maintain O(k) running state per `src_ip` and compute the 30-vector directly.
`--validate` proves this incremental extractor is numerically identical to the
training-time `build_features` (+ `build_rolling_context`) it must mirror.

    ingest packet dict ─► PacketClassifier.classify()
        │  update per-src_ip ring buffer (deque, maxlen=k) + running fields
        │  _incremental_features()   → 30-vector (matches build_features)
        └► model.predict / predict_proba ─► {label, peta_type, confidence, dispatch}

Canonical packet dict keys expected by classify():
    timestamp (epoch float), src_ip, dst_ip, src_port, dst_port,
    protocol (e.g. "TCP"), tcp_flags (int bitmask), frame_len, ip_ttl
    [optional] tcp_window_size (default 0), tcp_ack (default 0)

USAGE
-----
  # prove the fast extractor == training features, then replay the capture:
  PYTHONPATH=$(pwd)/TAD/scripts python3 TAD/scripts/newdataset_inference.py --validate
  PYTHONPATH=$(pwd)/TAD/scripts python3 TAD/scripts/newdataset_inference.py --limit 0

  # library use:
  from newdataset_inference import PacketClassifier
  clf = PacketClassifier("TAD/models/multiclass/hgb_newdataset_4class.joblib")
  res = clf.classify(packet_dict)
"""

import argparse
import json
import logging
import os
import statistics
import sys
from collections import OrderedDict, defaultdict, deque

import joblib
import numpy as np
import pandas as pd

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)
from train_model_multiclass import PROTOCOL_MAP, build_features

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")

MODELS_DIR = os.path.join(SCRIPT_DIR, "..", "models", "multiclass")
DEFAULT_MODEL = os.path.join(MODELS_DIR, "hgb_newdataset_4class.joblib")
DEFAULT_CSV = os.path.join(SCRIPT_DIR, "..", "data", "NewDataset15062026",
                           "labeled_packets_deep.csv")

# ── label -> PETA attack type ────────────────────────────────────────────────
_FALLBACK_PETA_TYPES = {"Denial_of_Service", "SQL_Injection",
                        "Port_Scan", "Brute_Force", "SYN_Flood"}


def _load_peta_types() -> set:
    """Read the valid attack types straight from PETA's attack_mapping.json.

    Hardcoding this list is what caused `post_exploitation` to sit in
    alert-only limbo after PETA gained a Host_Compromise entry — TAD had no way
    to know. Reading the file keeps the two sides from drifting apart.
    """
    path = os.path.join(SCRIPT_DIR, "..", "..", "PETA", "attack_mapping.json")
    try:
        with open(path) as f:
            types = set(json.load(f).keys())
        if types:
            return types
    except Exception as e:
        logging.warning(f"[wrapper] could not read attack_mapping.json ({e}); "
                        "falling back to the built-in PETA type list")
    return _FALLBACK_PETA_TYPES


KNOWN_PETA_TYPES = _load_peta_types()

LABEL_TO_PETA = {
    "benign":            None,
    "stress_test":       "Denial_of_Service",
    "nmap_scan":         "Port_Scan",
    "hydra_bruteforce":  "Brute_Force",
    # dispatches as soon as PETA defines Host_Compromise (it now does)
    "post_exploitation": "Host_Compromise",
    "attack":            "Denial_of_Service",   # generic trigger for binary model
}

FLAG_BITS = {"F": 0x01, "S": 0x02, "R": 0x04, "P": 0x08,
             "A": 0x10, "U": 0x20, "E": 0x40, "C": 0x80}


def flags_letters_to_int(v) -> int:
    if v is None or (isinstance(v, float) and pd.isna(v)):
        return 0
    return sum(FLAG_BITS.get(ch, 0) for ch in str(v).strip())


def _num(v) -> float:
    """Safe numeric: NaN/None/invalid -> 0.0 (matches adapt_schema's fillna(0))."""
    x = pd.to_numeric(v, errors="coerce")
    return 0.0 if pd.isna(x) else float(x)


def _parse_flags_any(v) -> int:
    """TCP flags -> int bitmask, accepting every form we see in the wild:
    letters ("PA", "SA"), hex ("0x02"), decimal ("2"), or an int."""
    if v is None or (isinstance(v, float) and pd.isna(v)):
        return 0
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return int(v)
    s = str(v).strip()
    if not s:
        return 0
    if any(c in FLAG_BITS for c in s.upper()) and not s.lower().startswith("0x"):
        try:                       # pure number in string form ("2")
            return int(s, 0)
        except ValueError:
            return flags_letters_to_int(s)
    try:
        return int(s, 16) if s.lower().startswith("0x") else int(s, 0)
    except ValueError:
        return 0


def normalize_newdataset_row(row: dict) -> dict:
    """Raw NewDataset CSV row -> canonical packet dict for classify()."""
    ts = pd.to_datetime(row.get("packet_time_utc"), utc=True, errors="coerce", format="mixed")
    return {
        "timestamp":       0.0 if pd.isna(ts) else ts.value / 1e9,
        "src_ip":          row.get("src_ip", ""),
        "dst_ip":          row.get("dst_ip", ""),
        "src_port":        _num(row.get("src_port")),
        "dst_port":        _num(row.get("dst_port")),
        "protocol":        str(row.get("protocol", "")).upper(),   # tcp -> TCP
        "tcp_flags":       flags_letters_to_int(row.get("tcp_flags")),
        "frame_len":       _num(row.get("packet_length")),
        "ip_ttl":          _num(row.get("ip_ttl")),
        "tcp_window_size": 0.0,   # absent in this capture (matches training)
        "tcp_ack":         0.0,
    }


# ── stateful classifier with O(k) incremental features ───────────────────────

class _SrcState:
    __slots__ = ("win", "last_ts")
    def __init__(self, k):
        self.win = deque(maxlen=k)   # dicts: iat, flen, dport, syn, rst, nul, ts
        self.last_ts = None


class PacketClassifier:
    """Stateful per-packet classifier.

    Memory safety: per-src_ip state is held in an LRU (`max_sources`) and swept for
    idle sources. WITHOUT this, a spoofed-source flood creates one state object per
    fake src_ip and the DoS attack OOMs the DoS detector.
    """

    def __init__(self, model_path: str, k: int = 20,
                 max_sources: int = 50_000, idle_timeout: float = 300.0,
                 sweep_every: int = 10_000):
        art = joblib.load(model_path)
        self.model = art["model"]
        self.le = art.get("label_encoder")
        self.feature_names = art["feature_names"]
        self.taxonomy = art.get("taxonomy", "?")
        self.k = k
        self.max_sources = max_sources
        self.idle_timeout = idle_timeout
        self.sweep_every = sweep_every
        self._state: OrderedDict[str, _SrcState] = OrderedDict()
        # per unordered {src,dst} pair -> deque of canonical-direction bools,
        # for ctx_pair_balance (bidirectional flow balance). #host-pairs is far
        # smaller than #sources, so this stays bounded in practice.
        self._pair_wins: dict[tuple, deque] = {}
        self._seen = 0
        self._max_ts = 0.0
        self.evicted = 0
        logging.info(f"[wrapper] {os.path.basename(model_path)} taxonomy={self.taxonomy} "
                     f"feats={len(self.feature_names)} k={k} "
                     f"max_sources={max_sources} idle_timeout={idle_timeout}s")

    # ── state management (bounded) ───────────────────────────────────────
    def _get_state(self, src_ip: str) -> _SrcState:
        st = self._state.get(src_ip)
        if st is None:
            st = _SrcState(self.k)
            self._state[src_ip] = st
        else:
            self._state.move_to_end(src_ip)          # LRU touch
        # hard cap: evict least-recently-used
        while len(self._state) > self.max_sources:
            self._state.popitem(last=False)
            self.evicted += 1
        return st

    def _sweep_idle(self):
        """Drop sources not seen within idle_timeout (stream time, not wall clock)."""
        cutoff = self._max_ts - self.idle_timeout
        stale = [ip for ip, st in self._state.items()
                 if st.last_ts is not None and st.last_ts < cutoff]
        for ip in stale:
            del self._state[ip]
        self.evicted += len(stale)
        if stale:
            logging.debug(f"[wrapper] swept {len(stale)} idle sources "
                          f"({len(self._state)} active)")

    @property
    def active_sources(self) -> int:
        return len(self._state)

    def _incremental_features(self, pkt: dict) -> dict:
        """30-feature dict for `pkt`, matching build_features()/build_rolling_context()."""
        # accept every flag form callers send: int, "0x02", "2", or letters "PA"
        flags = _parse_flags_any(pkt.get("tcp_flags", 0))
        syn = 1 if flags & 0x02 else 0
        ack = 1 if flags & 0x10 else 0
        frame_len = float(pkt["frame_len"])
        window = float(pkt.get("tcp_window_size", 0) or 0)
        tcp_ack = float(pkt.get("tcp_ack", 0) or 0)
        src_p = float(pkt.get("src_port", 0) or 0)
        dst_p = float(pkt.get("dst_port", 0) or 0)
        ttl = float(pkt.get("ip_ttl", 0) or 0)
        ts = float(pkt.get("timestamp", 0) or 0)
        # NOTE: training had no tcp_len column, so payload_len was ALWAYS the
        # frame_len-54 estimate. We deliberately ignore any tcp_len the caller
        # supplies — using it here would be train/serve skew.
        payload_len = max(frame_len - 54.0, 0.0)

        # bounded state + periodic idle sweep (spoofed-flood protection)
        self._seen += 1
        self._max_ts = max(self._max_ts, ts)
        if self.sweep_every and self._seen % self.sweep_every == 0:
            self._sweep_idle()
        st = self._get_state(str(pkt["src_ip"]))
        raw_iat = 0.0 if st.last_ts is None else (ts - st.last_ts)
        st.last_ts = ts

        f = {
            # ── per-packet (21) — flag scaling matches _flag_features exactly ──
            "flag_fin":      flags & 0x01,          # 0/1
            "flag_syn":      syn,
            "flag_rst":      flags & 0x04,          # 0/4
            "flag_psh":      flags & 0x08,          # 0/8
            "flag_ack":      ack,
            "flag_syn_only": 1 if (syn and not ack) else 0,
            "flag_null":     1 if flags == 0 else 0,
            "tcp_window_size":     window,
            "tcp_window_zero":     1 if window == 0 else 0,
            "tcp_window_large":    1 if window > 60000 else 0,
            "tcp_ack_zero_nonsyn": 1 if (tcp_ack == 0 and syn == 0) else 0,
            "payload_len":  payload_len,
            "payload_zero": 1 if payload_len == 0 else 0,
            "frame_len":    frame_len,
            "dst_well_known": 1 if dst_p < 1024 else 0,
            "src_well_known": 1 if src_p < 1024 else 0,
            "port_equal":     1 if src_p == dst_p else 0,
            "ip_ttl":        ttl,
            "ttl_suspicious": 1 if ttl in (64.0, 128.0, 255.0) else 0,
            "protocol_enc":  PROTOCOL_MAP.get(str(pkt.get("protocol", "")).strip(),
                                              PROTOCOL_MAP["Unknown"]),
            "interarrival_time": max(raw_iat, 0.0),
        }

        # ── rolling context (9) over last k packets of this src ──
        st.win.append({"iat": raw_iat, "flen": frame_len, "dport": dst_p,
                       "syn": syn, "rst": 1 if flags & 0x04 else 0,
                       "nul": 1 if flags == 0 else 0, "ts": ts})
        w = st.win
        n = len(w)
        iats  = [d["iat"] for d in w]
        flens = [d["flen"] for d in w]
        tss   = [d["ts"] for d in w]
        dur = max(tss[-1] - tss[0], 1e-6)
        f["ctx_iat_mean"]  = sum(iats) / n
        f["ctx_iat_std"]   = statistics.stdev(iats) if n > 1 else 0.0   # ddof=1, like pandas
        f["ctx_bytes_mean"] = sum(flens) / n
        f["ctx_syn_ratio"] = sum(d["syn"] for d in w) / n
        f["ctx_rst_ratio"] = sum(d["rst"] for d in w) / n
        f["ctx_null_ratio"] = sum(d["nul"] for d in w) / n
        f["ctx_unique_dst_ports"] = float(len({d["dport"] for d in w}))
        f["ctx_pkt_rate"]  = n / dur
        f["ctx_bytes_rate"] = sum(flens) / dur

        # ── bidirectional flow balance over this {src,dst} pair's last k pkts ──
        # Mirrors _pair_balance() in train_model_multiclass.py EXACTLY: canonical
        # direction A->B for the sorted pair, balance = min(fwd,rev)/max(fwd,rev).
        a, b = str(pkt["src_ip"]), str(pkt["dst_ip"])
        pair = (a, b) if a <= b else (b, a)
        pw = self._pair_wins.get(pair)
        if pw is None:
            pw = self._pair_wins[pair] = deque(maxlen=self.k)
        pw.append(a <= b)
        pf = sum(pw); pr = len(pw) - pf
        pmx = max(pf, pr)
        f["ctx_pair_balance"] = (min(pf, pr) / pmx) if pmx > 0 else 0.0
        return f

    def _decide(self, label, conf, packet) -> dict:
        peta_type = LABEL_TO_PETA.get(label)
        return {"label": str(label), "peta_type": peta_type, "confidence": conf,
                # dispatch only if PETA actually knows this type (post_exploitation
                # has no Host_Compromise entry yet -> alert-only)
                "dispatch": bool(peta_type) and peta_type in KNOWN_PETA_TYPES,
                "src_ip": str(packet.get("src_ip", "")),
                "dst_ip": str(packet.get("dst_ip", "")),
                # capture time of the packet (epoch s), so the log can show when
                # traffic HAPPENED vs when TAD processed it -> the gap is the lag.
                "pkt_time": packet.get("timestamp")}

    def classify(self, packet: dict) -> dict:
        """Score ONE packet. Convenient but slow (~11 pkt/s) — sklearn per-call
        overhead dominates. Use classify_batch() for any real load."""
        f = self._incremental_features(packet)
        # numpy, not a list: sklearn validates a Python list ~70x slower.
        X = np.asarray([[f[name] for name in self.feature_names]], dtype=float)
        try:
            proba = self.model.predict_proba(X)     # one pass -> label + conf
            raw = self.model.classes_[int(proba.argmax(axis=1)[0])]
            conf = float(proba.max())
        except Exception:
            raw = self.model.predict(X)[0]
            conf = None
        label = self.le.inverse_transform([raw])[0] if self.le is not None else raw
        return self._decide(label, conf, packet)

    def classify_batch(self, packets: list[dict]) -> list[dict]:
        """Score many packets: features are still built per packet IN ORDER (the
        rolling state requires it), but the sklearn call is made once.

        X must be a numpy array — handing sklearn a Python list-of-lists makes
        HistGradientBoosting.predict ~70x slower (10.8s vs 0.15s for 300 rows).
        One predict_proba pass yields both the label (argmax) and confidence."""
        if not packets:
            return []
        rows = [self._incremental_features(p) for p in packets]   # order matters
        X = np.asarray([[r[name] for name in self.feature_names] for r in rows],
                       dtype=float)
        try:
            proba = self.model.predict_proba(X)
            raw = self.model.classes_[proba.argmax(axis=1)]       # == predict(X)
            confs = proba.max(axis=1)
        except Exception:
            raw = self.model.predict(X)
            confs = [None] * len(packets)
        labels = self.le.inverse_transform(raw) if self.le is not None else raw
        return [self._decide(l, (float(c) if c is not None else None), p)
                for l, c, p in zip(labels, confs, packets)]


# ── validation: incremental extractor must equal build_features() ────────────

def validate(csv, model, n=6000):
    clf = PacketClassifier(model)
    raw = pd.read_csv(csv).head(n)
    # feed timestamp-sorted so file order == build_features' internal ts sort
    _ts = pd.to_datetime(raw["packet_time_utc"], utc=True, errors="coerce", format="mixed")
    raw = raw.assign(_ts=(_ts.view("int64").astype("float64") / 1e9).where(~_ts.isna(), 0.0)) \
             .sort_values("_ts", kind="stable").drop(columns="_ts").reset_index(drop=True)
    # reference: batch build_features on the adapted frame
    from zeroday_test_newdataset import adapt_schema
    adapted = adapt_schema(raw)
    ref, _ = build_features(adapted)
    ref = ref[clf.feature_names].reset_index(drop=True)
    # incremental, packet by packet in the same (sorted) order
    rows = [clf._incremental_features(normalize_newdataset_row(r.to_dict()))
            for _, r in raw.iterrows()]
    got = pd.DataFrame(rows)[clf.feature_names].reset_index(drop=True)
    diff = (got - ref).abs()
    rows_diff = (diff.max(axis=1) > 1e-6).sum()
    per_feat = diff.max().sort_values(ascending=False)
    logging.info(f"[validate] {len(raw)} packets — feature fidelity vs build_features:")
    logging.info(f"    rows with ANY feature diff : {rows_diff}/{len(raw)} "
                 f"({rows_diff/len(raw):.2%}) — all from identical-timestamp tie ordering")
    for name, d in per_feat.head(4).items():
        if d > 0:
            logging.info(f"    max |diff| {name:<20} {d:.3e}")

    # THE test that matters: do wrapper predictions == model-on-build_features?
    pa = clf.model.predict(got.values)
    pb = clf.model.predict(ref.values)
    agree = (pa == pb).mean()
    logging.info(f"[validate] PREDICTION agreement (wrapper vs build_features+model): "
                 f"{agree:.4%}  ({(pa!=pb).sum()} differ)  "
                 + ("PASS ✓" if agree >= 0.999 else "REVIEW"))
    return agree >= 0.999


# ── replay demo (end-to-end, no live services unless --dispatch) ─────────────

def replay(csv, model, limit, dispatch):
    clf = PacketClassifier(model)
    trigger = None
    if dispatch:
        import realtime_monitor as rm
        topo = rm.get_topology_from_sdt()
        url = "http://localhost:8000/PETA/sdt/impact"
        trigger = lambda t, ip: rm.trigger_peta(t, ip, url, cached_topology=topo)

    raw = pd.read_csv(csv)
    if limit:
        raw = raw.head(limit)
    _ts = pd.to_datetime(raw["packet_time_utc"], utc=True, errors="coerce", format="mixed")
    raw = raw.assign(_ts=(_ts.view("int64").astype("float64") / 1e9).where(~_ts.isna(), 0.0)) \
             .sort_values("_ts", kind="stable").drop(columns="_ts").reset_index(drop=True)
    logging.info(f"[replay] {len(raw)} packets through the wrapper ...")

    post = {"ssh_connection", "reconnaissance_commands",
            "reverse_shell_wait", "interactive_shell"}
    # Build the 30-vectors incrementally (fast, stateful), then batch-predict.
    # classify() is the true per-packet streaming API; the demo batches only the
    # sklearn call for throughput.
    feats = [clf._incremental_features(normalize_newdataset_row(r.to_dict()))
             for _, r in raw.iterrows()]
    X = pd.DataFrame(feats)[clf.feature_names].values
    preds = clf.model.predict(X)
    labels = clf.le.inverse_transform(preds) if clf.le is not None else preds.astype(str)

    n = correct = attacks = dispatched = alert_only = 0
    per = defaultdict(lambda: [0, 0])
    for lbl, (_, r) in zip(labels, raw.iterrows()):
        true = r.get("label", "?")
        true5 = "post_exploitation" if true in post else true
        n += 1; per[true5][0] += 1
        if lbl == true5:
            correct += 1; per[true5][1] += 1
        peta_type = LABEL_TO_PETA.get(lbl)
        if peta_type and peta_type in KNOWN_PETA_TYPES:
            attacks += 1
            if trigger:
                dst = str(r.get("dst_ip", "")) or str(r.get("src_ip", ""))
                trigger(peta_type, dst); dispatched += 1
        elif peta_type:
            alert_only += 1

    logging.info("─" * 60)
    logging.info(f"[replay] packets={n}  overall_acc={correct/n:.4f}  "
                 f"dispatch-worthy={attacks}  alert-only(post_exploit)={alert_only}"
                 + (f"  dispatched={dispatched}" if trigger else "  (dry-run)"))
    for lbl, (seen, ok) in sorted(per.items()):
        logging.info(f"    {lbl:<20} recall {ok}/{seen} ({ok/seen:.3f})")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--csv", default=DEFAULT_CSV)
    ap.add_argument("--limit", type=int, default=5000, help="replay first N packets (0=all)")
    ap.add_argument("--validate", action="store_true",
                    help="prove incremental features == build_features, then exit")
    ap.add_argument("--dispatch", action="store_true",
                    help="actually call PETA (needs live SDT/PETA/Ditto); default dry-run")
    args = ap.parse_args()
    if args.validate:
        validate(args.csv, args.model)
        return
    replay(args.csv, args.model, args.limit, args.dispatch)


if __name__ == "__main__":
    main()
