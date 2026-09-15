"""
gnn_features.py
================
Shared graph/feature construction for the victim-identification GNN, used by
BOTH training (train_gnn_victim.py, batch over a labelled CSV) and live
serving (gnn_victim_id.py, streaming from tad_api.py) so the two paths can
never drift apart -- a mismatch here would silently corrupt inference.

Node = an IP seen in traffic. Edge = an observed flow between two IPs
(undirected, for message passing). See TAD_PETA conversation history /
gnn_victim_feasibility.py for the feasibility study this was promoted from:
- (a) standard split: victim F1 0.90, balanced-acc 0.97
- (b) leave-one-host-out: 5/6 held-out victims correctly identified
- Caveat that still applies: only 6 victim hosts exist in the training data,
  all on one subnet behind one attacker box. This model is accurate on THOSE
  hosts and not yet validated to generalize past them -- see the training
  script's docstring before trusting it on a genuinely new topology.

COUNT_COLS are log1p-transformed before scaling (heavy-tailed: packet counts
range from ~4 to ~400k). OTHER_COLS are already bounded 0..1 or near-constant
(TTL) and are scaled as-is.
"""
import numpy as np
import pandas as pd

SCAN_STYLE = {"nmap_scan", "hydra_bruteforce", "stress_test"}
COMPROMISE_STYLE = {"ssh_connection", "reconnaissance_commands", "reverse_shell_wait",
                     "interactive_shell", "post_exploitation"}
ATTACK_LABELS = SCAN_STYLE | COMPROMISE_STYLE

COUNT_COLS = ["total_pkts", "total_bytes", "in_degree", "out_degree", "pkt_rate",
              "count_nmap", "count_hydra", "count_stress", "count_compromise"]
OTHER_COLS = ["frac_attack", "frac_attack_as_dst", "avg_ttl", "syn_ratio"]
FEATURE_COLS = COUNT_COLS + OTHER_COLS

FLAG_SYN = {"S", "SA"}   # letter-form tcp_flags, matches the NewDataset schema


def resolve_victims(df: pd.DataFrame, known_assets: set) -> set:
    """Ground-truth victim set for TRAINING: mirrors realtime_monitor_v2.py's
    _resolve_target_ip, including the known-managed-asset gate. Without that
    gate the kali attacker box gets mislabeled a victim from its own
    reply-traffic packets (dst_ip == attacker on return packets within the
    same attack-labelled window)."""
    scan_rows = df[df["label"].isin(SCAN_STYLE)]
    compromise_rows = df[df["label"].isin(COMPROMISE_STYLE)]
    return (set(scan_rows.loc[scan_rows["dst_ip"].isin(known_assets), "dst_ip"]) |
            set(compromise_rows.loc[compromise_rows["src_ip"].isin(known_assets), "src_ip"]))


def build_training_graph(df: pd.DataFrame, known_assets: set):
    """Batch graph construction from a labelled CSV (ground-truth `label` col).

    Returns (all_ips, edge_index[2,E] np.ndarray, feat_df[FEATURE_COLS+'victim']).
    """
    df = df.copy()
    df["_ts"] = pd.to_datetime(df["packet_time_utc"], utc=True, errors="coerce", format="mixed")
    victims = resolve_victims(df, known_assets)

    all_ips = sorted(set(df["src_ip"]) | set(df["dst_ip"]))
    idx_of = {ip: i for i, ip in enumerate(all_ips)}

    pairs = df[["src_ip", "dst_ip"]].drop_duplicates()
    src_idx = pairs["src_ip"].map(idx_of).values
    dst_idx = pairs["dst_ip"].map(idx_of).values
    edge_index = np.concatenate([np.stack([src_idx, dst_idx]),
                                 np.stack([dst_idx, src_idx])], axis=1)

    as_src = df.groupby("src_ip")
    as_dst = df.groupby("dst_ip")

    rows = []
    for ip in all_ips:
        s = as_src.get_group(ip) if ip in as_src.groups else df.iloc[0:0]
        d = as_dst.get_group(ip) if ip in as_dst.groups else df.iloc[0:0]
        total_pkts = len(s) + len(d)
        total_bytes = s["packet_length"].sum() + d["packet_length"].sum()
        out_degree = s["dst_ip"].nunique()
        in_degree = d["src_ip"].nunique()
        ts_all = pd.concat([s["_ts"], d["_ts"]]).dropna()
        span_s = max((ts_all.max() - ts_all.min()).total_seconds(), 1.0) if len(ts_all) > 1 else 1.0
        pkt_rate = total_pkts / span_s

        def lab_count(rowset, labels):
            return int(rowset["label"].isin(labels).sum())

        count_nmap = lab_count(s, {"nmap_scan"}) + lab_count(d, {"nmap_scan"})
        count_hydra = lab_count(s, {"hydra_bruteforce"}) + lab_count(d, {"hydra_bruteforce"})
        count_stress = lab_count(s, {"stress_test"}) + lab_count(d, {"stress_test"})
        count_compromise = lab_count(s, COMPROMISE_STYLE) + lab_count(d, COMPROMISE_STYLE)

        attack_pkts = lab_count(s, ATTACK_LABELS) + lab_count(d, ATTACK_LABELS)
        frac_attack = attack_pkts / total_pkts if total_pkts else 0.0
        attack_as_dst = lab_count(d, ATTACK_LABELS)
        frac_attack_as_dst = attack_as_dst / attack_pkts if attack_pkts else 0.0

        avg_ttl = s["ip_ttl"].mean() if len(s) else 0.0
        syn_ratio = s["tcp_flags"].isin(FLAG_SYN).mean() if len(s) else 0.0

        rows.append(dict(ip=ip, total_pkts=total_pkts, total_bytes=total_bytes,
                         in_degree=in_degree, out_degree=out_degree, pkt_rate=pkt_rate,
                         count_nmap=count_nmap, count_hydra=count_hydra,
                         count_stress=count_stress, count_compromise=count_compromise,
                         frac_attack=frac_attack, frac_attack_as_dst=frac_attack_as_dst,
                         avg_ttl=avg_ttl, syn_ratio=syn_ratio, victim=int(ip in victims)))

    feat_df = pd.DataFrame(rows).set_index("ip").loc[all_ips]
    return all_ips, edge_index, feat_df


def to_model_matrix(feat_df: pd.DataFrame) -> np.ndarray:
    """FEATURE_COLS -> log1p(counts) + raw(other), UNSCALED. Caller applies the
    (persisted, training-time-fit) StandardScaler on top of this."""
    X = feat_df[COUNT_COLS].apply(lambda c: np.log1p(c)).join(feat_df[OTHER_COLS])
    return X[FEATURE_COLS].fillna(0.0).values
