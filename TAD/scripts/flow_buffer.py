"""
flow_buffer.py
==============
Real-time flow accumulator for TAD.

Buffers per-packet CSV rows by 5-tuple and emits a completed flow (as a
feature vector) once the flow has been idle for `timeout` seconds.

The emitted feature vector matches FEATURE_COLS in flow_aggregation.py so
the rf_flows.joblib / hgb_flows.joblib models can run inference directly.

Usage:
    buf = FlowBuffer(timeout=60.0, cross_flow_stats=df_from_model)
    for each new csv row (dict):
        completed = buf.add(row)
        for flow_features, label_hint in completed:
            pred = model.predict([flow_features])

    # At end of polling cycle, also drain idle flows:
    for flow_features, label_hint in buf.drain():
        pred = model.predict([flow_features])
"""

import time
from collections import defaultdict
from typing import Iterator

import numpy as np
import pandas as pd

# Mirror FEATURE_COLS from flow_aggregation.py — single source of truth
FEATURE_COLS = [
    "flow_duration", "flow_rate",
    "packet_count",
    "iat_mean", "iat_std", "iat_min", "iat_max",
    "bytes_total", "bytes_mean", "bytes_std", "bytes_rate",
    "payload_mean", "payload_zero_ratio",
    "syn_count", "ack_count", "rst_count", "fin_count", "psh_count",
    "syn_ratio", "rst_ratio", "syn_only_ratio", "null_ratio",
    "window_mean", "window_std", "window_zero_ratio",
    "ttl_mean", "ttl_std",
    "src_unique_dst_ports", "src_unique_dst_ips", "src_total_flows",
]


def _to_int(v) -> int:
    try:
        s = str(v).strip()
        return int(s, 16) if s.startswith(("0x", "0X")) else int(s, 0)
    except (ValueError, TypeError):
        return 0


def _compute_flow_features(packets: list[dict], cross_flow_stats: pd.DataFrame | None) -> list[float]:
    """
    Given a list of packet dicts (same schema as CSV rows), return a feature
    vector in FEATURE_COLS order.  cross_flow_stats is the per-src_ip table
    saved inside the model artifact.
    """
    n = len(packets)
    if n == 0:
        return [0.0] * len(FEATURE_COLS)

    ts = np.array([float(p.get("timestamp", 0) or 0) for p in packets])
    ts.sort()

    duration = float(ts[-1] - ts[0])
    safe_dur  = max(duration, 1e-6)

    if n > 1:
        iats     = np.diff(ts)
        iat_mean = float(np.mean(iats))
        iat_std  = float(np.std(iats))
        iat_min  = float(np.min(iats))
        iat_max  = float(np.max(iats))
    else:
        iat_mean = iat_std = iat_min = iat_max = 0.0

    flags_arr = np.array([_to_int(p.get("tcp_flags", 0)) for p in packets])
    syn_arr   = (flags_arr & 0x02).astype(bool)
    ack_arr   = (flags_arr & 0x10).astype(bool)
    syn_c     = int(syn_arr.sum())
    ack_c     = int(ack_arr.sum())
    rst_c     = int(((flags_arr & 0x04) > 0).sum())
    fin_c     = int(((flags_arr & 0x01) > 0).sum())
    psh_c     = int(((flags_arr & 0x08) > 0).sum())
    syn_only  = (syn_arr & ~ack_arr)
    null_c    = int((flags_arr == 0).sum())

    flen_arr = np.array([float(p.get("frame_len", 0) or 0) for p in packets])
    if "tcp_len" in packets[0]:
        pay_arr = np.array([float(p.get("tcp_len", 0) or 0) for p in packets]).clip(min=0)
    else:
        pay_arr = (flen_arr - 54).clip(min=0)
    win_arr  = np.array([float(p.get("tcp_window_size", 0) or 0) for p in packets])
    ttl_arr  = np.array([float(p.get("ip_ttl", 0) or 0) for p in packets])

    bytes_total = float(flen_arr.sum())

    src_ip = str(packets[0].get("src_ip", ""))

    # Cross-flow stats from model training data (conservative fallback = 0)
    src_unique_dst_ports = 0
    src_unique_dst_ips   = 0
    src_total_flows      = 0
    if cross_flow_stats is not None and not cross_flow_stats.empty:
        row = cross_flow_stats[cross_flow_stats["src_ip"] == src_ip]
        if not row.empty:
            src_unique_dst_ports = int(row["src_unique_dst_ports"].iloc[0])
            src_unique_dst_ips   = int(row["src_unique_dst_ips"].iloc[0])
            src_total_flows      = int(row["src_total_flows"].iloc[0])

    feat = [
        duration,
        n / safe_dur,                                          # flow_rate
        n,                                                     # packet_count
        iat_mean, iat_std, iat_min, iat_max,
        bytes_total,
        float(flen_arr.mean()),
        float(flen_arr.std() if n > 1 else 0.0),
        bytes_total / safe_dur,                                # bytes_rate
        float(pay_arr.mean()),
        float((pay_arr == 0).mean()),                          # payload_zero_ratio
        syn_c, ack_c, rst_c, fin_c, psh_c,
        syn_c / n,
        rst_c / n,
        float(syn_only.mean()),
        null_c / n,
        float(win_arr.mean()),
        float(win_arr.std() if n > 1 else 0.0),
        float((win_arr == 0).mean()),
        float(ttl_arr.mean()),
        float(ttl_arr.std() if n > 1 else 0.0),
        src_unique_dst_ports,
        src_unique_dst_ips,
        src_total_flows,
    ]
    return feat


class FlowBuffer:
    """
    Stateful per-5-tuple packet accumulator.

    After `timeout` seconds of idle time a flow is considered complete.
    FIN/RST packets also close a flow immediately.

    Parameters
    ----------
    timeout : float
        Seconds without a new packet before a flow is emitted (default 60 s).
    cross_flow_stats : pd.DataFrame | None
        Table with columns [src_ip, src_unique_dst_ports, src_unique_dst_ips,
        src_total_flows] — loaded from the model artifact.
    """

    def __init__(self, timeout: float = 60.0, cross_flow_stats=None):
        self._timeout   = timeout
        self._stats     = cross_flow_stats
        self._packets: dict[tuple, list[dict]] = defaultdict(list)
        self._last_ts:  dict[tuple, float]     = {}

    @staticmethod
    def _flow_key(row: dict) -> tuple:
        return (
            str(row.get("src_ip", "")),
            str(row.get("dst_ip", "")),
            int(float(row.get("src_port", 0) or 0)),
            int(float(row.get("dst_port", 0) or 0)),
            str(row.get("protocol", "")),
        )

    def add(self, row: dict) -> list[tuple[list[float], str]]:
        """
        Add a packet row.  Returns a (possibly empty) list of
        (feature_vector, src_ip) tuples for any flows closed by this packet
        (FIN/RST triggered).
        """
        key = self._flow_key(row)
        now = float(row.get("timestamp", time.time()) or time.time())

        self._packets[key].append(row)
        self._last_ts[key] = now

        # Emit immediately on FIN or RST — flow is finished
        flags = _to_int(row.get("tcp_flags", 0))
        if (flags & 0x01) or (flags & 0x04):   # FIN or RST
            return [self._close(key)]
        return []

    def drain(self) -> list[tuple[list[float], str]]:
        """
        Close and return all flows idle for >= timeout seconds.
        Call this at the end of each polling cycle.
        """
        now = time.time()
        completed = []
        expired = [k for k, last in self._last_ts.items()
                   if (now - last) >= self._timeout]
        for key in expired:
            completed.append(self._close(key))
        return completed

    def _close(self, key: tuple) -> tuple[list[float], str]:
        packets = self._packets.pop(key, [])
        self._last_ts.pop(key, None)
        src_ip = key[0]
        feats  = _compute_flow_features(packets, self._stats)
        return feats, src_ip
