"""
feature_utils.py
================
Shared feature engineering utilities for TAD.

Used by:
  - train_model.py        (training time — per-packet model)
  - flow_aggregation.py   (training time — flow model)
  - realtime_monitor.py   (inference time — both models)

Two feature sets are defined here:
  FEATURE_COLS      — per-packet features (legacy model)
  FLOW_FEATURE_COLS — per-flow behavioural features (current best model)
"""

import numpy as np
import pandas as pd

# ── Per-packet feature columns (legacy) ─────────────────────────────────────
FEATURE_COLS = [
    "frame_len",
    "tcp_flags_enc",
    "ip_ttl",
    "tcp_window_size",
    "protocol_enc",
    "interarrival_time",
    "dst_well_known",
    "src_well_known",
    "port_equal",
    "tcp_ack_zero_nonsyn",
]

# ── Flow-level feature columns — must match flow_aggregation.FEATURE_COLS ───
FLOW_FEATURE_COLS = [
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

PROTOCOL_MAP = {
    "TCP": 0, "UDP": 1, "ICMP": 2, "ARP": 3, "DNS": 4,
    "HTTP": 5, "HTTPS": 6, "SSH": 7, "SSHv2": 7,
    "TLSv1.2": 8, "TLSv1.3": 9, "Unknown": 10,
}


# ── Helpers ──────────────────────────────────────────────────────────────────

def _flags_to_int(val) -> int:
    try:
        s = str(val).strip()
        return int(s, 16) if s.startswith(("0x", "0X")) else int(s, 0)
    except (ValueError, TypeError):
        return 0


def encode_tcp_flags(flag_val) -> float:
    return float(_flags_to_int(flag_val))


def encode_protocol(proto_val) -> int:
    return PROTOCOL_MAP.get(str(proto_val).strip(), PROTOCOL_MAP["Unknown"])


# ── Per-packet inference (legacy) ────────────────────────────────────────────

def extract_features_from_row(row) -> list:
    """Return per-packet feature vector matching FEATURE_COLS."""
    flags = _flags_to_int(row.get("tcp_flags", 0))
    syn   = bool(flags & 0x02)
    ack   = bool(flags & 0x10)
    src_p = float(row.get("src_port", 0) or 0)
    dst_p = float(row.get("dst_port", 0) or 0)
    return [
        float(row.get("frame_len", 0) or 0),
        float(flags),
        float(row.get("ip_ttl", 0) or 0),
        float(row.get("tcp_window_size", 0) or 0),
        float(encode_protocol(row.get("protocol", "Unknown"))),
        float(row.get("interarrival_time", 0) or 0),
        float(dst_p < 1024),
        float(src_p < 1024),
        float(src_p == dst_p),
        float(float(row.get("tcp_ack", 0) or 0) == 0 and not syn),
    ]


# ── Flow-level inference ─────────────────────────────────────────────────────

def extract_flow_features(
    packets: list[dict],
    cross_flow_stats: dict | None = None,
) -> list:
    """
    Compute a flow feature vector from a list of raw packet dicts.

    packets          : list of dicts with keys matching the v2 CSV schema
                       (timestamp, frame_len, tcp_len, tcp_flags, tcp_window_size,
                        ip_ttl, src_port, dst_port, tcp_ack)
    cross_flow_stats : optional dict {src_ip: {src_unique_dst_ports, src_unique_dst_ips,
                       src_total_flows}} loaded from the saved model artifact.
                       If None, those three features default to 0.

    Returns a list of floats in FLOW_FEATURE_COLS order.
    """
    if not packets:
        return [0.0] * len(FLOW_FEATURE_COLS)

    packets = sorted(packets, key=lambda p: float(p.get("timestamp", 0) or 0))
    n = len(packets)

    ts       = np.array([float(p.get("timestamp", 0) or 0) for p in packets])
    flen     = np.array([float(p.get("frame_len", 0) or 0) for p in packets])
    window   = np.array([float(p.get("tcp_window_size", 0) or 0) for p in packets])
    ttl      = np.array([float(p.get("ip_ttl", 0) or 0) for p in packets])

    # payload
    if "tcp_len" in packets[0]:
        payload = np.array([max(0.0, float(p.get("tcp_len", 0) or 0)) for p in packets])
    else:
        payload = np.clip(flen - 54, 0, None)

    # flags
    flags_arr  = np.array([_flags_to_int(p.get("tcp_flags", 0)) for p in packets])
    syn_arr    = (flags_arr & 0x02).astype(bool)
    ack_arr    = (flags_arr & 0x10).astype(bool)
    syn_c      = int(syn_arr.sum())
    ack_c      = int(ack_arr.sum())
    rst_c      = int(((flags_arr & 0x04) > 0).sum())
    fin_c      = int(((flags_arr & 0x01) > 0).sum())
    psh_c      = int(((flags_arr & 0x08) > 0).sum())
    syn_only_c = int((syn_arr & ~ack_arr).sum())
    null_c     = int((flags_arr == 0).sum())

    duration  = float(ts[-1] - ts[0])
    safe_dur  = max(duration, 1e-6)
    bytes_tot = float(flen.sum())

    if n > 1:
        iats     = np.diff(ts)
        iat_mean = float(iats.mean())
        iat_std  = float(iats.std())
        iat_min  = float(iats.min())
        iat_max  = float(iats.max())
        bytes_std = float(flen.std())
        win_std   = float(window.std())
        ttl_std   = float(ttl.std())
    else:
        iat_mean = iat_std = iat_min = iat_max = 0.0
        bytes_std = win_std = ttl_std = 0.0

    # cross-flow features from saved stats table
    src_ip = packets[0].get("src_ip", "")
    if cross_flow_stats and src_ip in cross_flow_stats:
        s = cross_flow_stats[src_ip]
        udp = s.get("src_unique_dst_ports", 0)
        udi = s.get("src_unique_dst_ips",   0)
        tfl = s.get("src_total_flows",      0)
    else:
        udp = udi = tfl = 0

    return [
        duration,              # flow_duration
        n / safe_dur,          # flow_rate
        n,                     # packet_count
        iat_mean, iat_std, iat_min, iat_max,
        bytes_tot,             # bytes_total
        float(flen.mean()),    # bytes_mean
        bytes_std,             # bytes_std
        bytes_tot / safe_dur,  # bytes_rate
        float(payload.mean()), # payload_mean
        float((payload == 0).mean()),  # payload_zero_ratio
        syn_c, ack_c, rst_c, fin_c, psh_c,
        syn_c / n,             # syn_ratio
        rst_c / n,             # rst_ratio
        syn_only_c / n,        # syn_only_ratio
        null_c / n,            # null_ratio
        float(window.mean()),  # window_mean
        win_std,               # window_std
        float((window == 0).mean()),  # window_zero_ratio
        float(ttl.mean()),     # ttl_mean
        ttl_std,               # ttl_std
        float(udp),            # src_unique_dst_ports
        float(udi),            # src_unique_dst_ips
        float(tfl),            # src_total_flows
    ]
