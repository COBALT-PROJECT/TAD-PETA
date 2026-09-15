"""
gnn_victim_id.py
=================
Live victim-identification GNN, wired into tad_api.py as a CONFIRMING signal
alongside the existing deterministic _resolve_target_ip -- it does not
replace it. If this module fails to load or errors at inference time, the
pipeline logs a warning and keeps dispatching exactly as before; a demo (or
production run) never depends on the GNN being up.

HostGraphState mirrors gnn_features.build_training_graph's feature
definitions incrementally, from the SAME predicted labels PacketClassifier
already produces per packet (no ground truth at serving time -- same
train-on-truth / serve-on-predictions pattern as the HGB classifier itself).
Bounded by an LRU eviction so it can't grow unboundedly across a long-running
service, same rationale as PacketClassifier's per-src state cap.

    from gnn_victim_id import HostGraphState, GNNVictimScorer
    graph = HostGraphState()
    graph.update(packet_dict, predicted_label)     # per packet, in order
    scorer = GNNVictimScorer("TAD/models/gnn/victim_sage.pt")
    scorer.score(graph)   # -> {ip: victim_probability}, only for hosts with any attack traffic
"""
import logging
from collections import OrderedDict

import numpy as np
import torch
import torch.nn.functional as F
from torch_geometric.data import Data
from torch_geometric.nn import SAGEConv

from gnn_features import ATTACK_LABELS, COMPROMISE_STYLE, COUNT_COLS, FEATURE_COLS, OTHER_COLS

FLAG_SYN = {"S", "SA", 0x02, 0x12}   # letters (NewDataset) or int bitmask (v2) SYN/SYN-ACK


class SAGE(torch.nn.Module):
    def __init__(self, in_dim, hid=32, out_dim=2):
        super().__init__()
        self.conv1 = SAGEConv(in_dim, hid)
        self.conv2 = SAGEConv(hid, out_dim)

    def forward(self, x, edge_index):
        x = F.relu(self.conv1(x, edge_index))
        x = F.dropout(x, p=0.0, training=self.training)   # inference: no dropout
        return self.conv2(x, edge_index)


class _HostStats:
    __slots__ = ("pkts", "bytes", "first_ts", "last_ts", "out_peers", "in_peers",
                 "count_nmap", "count_hydra", "count_stress", "count_compromise",
                 "attack_pkts", "attack_as_dst", "ttl_sum", "ttl_n", "syn_n", "syn_total")

    def __init__(self):
        self.pkts = 0
        self.bytes = 0.0
        self.first_ts = None
        self.last_ts = None
        self.out_peers = set()
        self.in_peers = set()
        self.count_nmap = 0
        self.count_hydra = 0
        self.count_stress = 0
        self.count_compromise = 0
        self.attack_pkts = 0
        self.attack_as_dst = 0
        self.ttl_sum = 0.0
        self.ttl_n = 0
        self.syn_n = 0
        self.syn_total = 0


class HostGraphState:
    """Streaming host graph, updated one packet at a time from PacketClassifier's
    predictions. Bounded by max_hosts (LRU eviction) so a long-running service
    or a spoofed-source flood can't grow this unboundedly."""

    def __init__(self, max_hosts: int = 20_000):
        self.max_hosts = max_hosts
        self._stats: "OrderedDict[str, _HostStats]" = OrderedDict()
        self._edges: set = set()

    def _get(self, ip: str) -> _HostStats:
        st = self._stats.get(ip)
        if st is None:
            st = _HostStats()
            self._stats[ip] = st
        else:
            self._stats.move_to_end(ip)
        while len(self._stats) > self.max_hosts:
            self._stats.popitem(last=False)
        return st

    def update(self, packet: dict, predicted_label: str):
        src, dst = str(packet.get("src_ip", "")), str(packet.get("dst_ip", ""))
        if not src or not dst:
            return
        ts = float(packet.get("timestamp", 0) or 0)
        length = float(packet.get("frame_len", 0) or 0)
        ttl = float(packet.get("ip_ttl", 0) or 0)
        flags = packet.get("tcp_flags", 0)
        is_syn = flags in FLAG_SYN if isinstance(flags, str) else bool(int(flags) & 0x02) if flags else False

        s, d = self._get(src), self._get(dst)
        self._edges.add((src, dst))

        for st, is_src in ((s, True), (d, False)):
            st.pkts += 1
            st.bytes += length
            if st.first_ts is None or ts < st.first_ts:
                st.first_ts = ts
            if st.last_ts is None or ts > st.last_ts:
                st.last_ts = ts
            if is_src:
                st.out_peers.add(dst)
                st.ttl_sum += ttl
                st.ttl_n += 1
                st.syn_total += 1
                st.syn_n += int(is_syn)
            else:
                st.in_peers.add(src)

            if predicted_label == "nmap_scan":
                st.count_nmap += 1
            elif predicted_label == "hydra_bruteforce":
                st.count_hydra += 1
            elif predicted_label == "stress_test":
                st.count_stress += 1
            elif predicted_label in COMPROMISE_STYLE:
                st.count_compromise += 1
            if predicted_label in ATTACK_LABELS:
                st.attack_pkts += 1
                if not is_src:
                    st.attack_as_dst += 1

    def attack_hosts(self, min_attack_pkts: int = 1):
        """IPs with at least `min_attack_pkts` predicted-attack packets involving
        them. Default (1) is just 'any involvement at all' -- callers deciding
        whether to actually TRUST a score should raise this. Directional
        features like frac_attack_as_dst are a ratio over attack_pkts alone, so
        with only a handful of attack packets seen so far it can look
        victim-like from pure sampling noise (observed live: an attacker box
        with 16 attack-labelled packets, 15 of them inbound reply traffic,
        scored higher than the real victim). MIN_RELIABLE_ATTACK_PKTS below is
        the threshold used for anything actually surfaced/acted on.
        """
        return [ip for ip, st in self._stats.items() if st.attack_pkts >= min_attack_pkts]

    def attack_pkt_count(self, ip: str) -> int:
        st = self._stats.get(ip)
        return st.attack_pkts if st else 0

    def build_data(self):
        """Snapshot -> (ip_list, X_raw[N,F] unscaled, edge_index[2,E])."""
        ips = list(self._stats.keys())
        idx_of = {ip: i for i, ip in enumerate(ips)}
        rows = []
        for ip in ips:
            st = self._stats[ip]
            span = max((st.last_ts - st.first_ts), 1.0) if (st.first_ts is not None and st.last_ts is not None) else 1.0
            pkt_rate = st.pkts / span
            frac_attack = st.attack_pkts / st.pkts if st.pkts else 0.0
            frac_attack_as_dst = st.attack_as_dst / st.attack_pkts if st.attack_pkts else 0.0
            avg_ttl = st.ttl_sum / st.ttl_n if st.ttl_n else 0.0
            syn_ratio = st.syn_n / st.syn_total if st.syn_total else 0.0
            rows.append([st.pkts, st.bytes, len(st.in_peers), len(st.out_peers), pkt_rate,
                        st.count_nmap, st.count_hydra, st.count_stress, st.count_compromise,
                        frac_attack, frac_attack_as_dst, avg_ttl, syn_ratio])
        X_raw = np.array(rows, dtype=float) if rows else np.zeros((0, len(FEATURE_COLS)))

        edges = [(idx_of[a], idx_of[b]) for a, b in self._edges if a in idx_of and b in idx_of]
        if edges:
            e = np.array(edges).T
            edge_index = np.concatenate([e, e[::-1]], axis=1)
        else:
            edge_index = np.zeros((2, 0), dtype=int)
        return ips, X_raw, edge_index


# Below this many accumulated attack-labelled packets for a host, its
# direction-based features (frac_attack_as_dst especially) are too noisy to
# trust -- see HostGraphState.attack_hosts() docstring. Same role as
# PacketClassifier's rolling window needing k packets, or
# dispatch_min_confidence gating HGB.
MIN_RELIABLE_ATTACK_PKTS = 10


class GNNVictimScorer:
    """Loads a train_gnn_victim.py artifact and scores a HostGraphState snapshot."""

    def __init__(self, model_path: str):
        art = torch.load(model_path, map_location="cpu", weights_only=False)
        self.feature_cols = art["feature_cols"]
        self.scaler_mean = np.asarray(art["scaler_mean"])
        self.scaler_scale = np.asarray(art["scaler_scale"])
        self.model = SAGE(art["in_dim"], art.get("hidden_dim", 32))
        self.model.load_state_dict(art["model_state"])
        self.model.eval()
        self.trained_on_hosts = art.get("trained_on_hosts", [])
        logging.info(f"[gnn] loaded {model_path} (trained on hosts: {self.trained_on_hosts})")

    def _scale(self, X_raw: np.ndarray) -> np.ndarray:
        n_count = len(COUNT_COLS)
        X = X_raw.copy()
        X[:, :n_count] = np.log1p(X[:, :n_count])
        return (X - self.scaler_mean) / self.scaler_scale

    def score(self, graph: HostGraphState) -> dict:
        """{ip: victim_probability} for every host currently in the graph.
        Returns {} if the graph is empty or has no edges yet (nothing to
        message-pass over)."""
        ips, X_raw, edge_index = graph.build_data()
        if len(ips) == 0 or edge_index.shape[1] == 0:
            return {}
        X = self._scale(X_raw)
        x_t = torch.tensor(X, dtype=torch.float)
        ei_t = torch.tensor(edge_index, dtype=torch.long)
        with torch.no_grad():
            proba = F.softmax(self.model(x_t, ei_t), dim=1)[:, 1]
        return {ip: float(p) for ip, p in zip(ips, proba.numpy())}
