"""
train_gnn_victim.py
====================
Train and save the victim-identification GNN artifact used by tad_api.py /
gnn_victim_id.py in production.

Trains on ALL current labels (no held-out split) -- this is a deliberate,
demo-scoped choice: it maximizes accuracy on the 6 hosts we actually have
attack data for (118, 120, 123, 126, 204, 249), which is what a live demo
will exercise. It is NOT evidence this generalizes to a host outside that
set -- the feasibility study (gnn_victim_feasibility.py, same session this
was promoted from) found leave-one-host-out recall of 5/6 on this exact
data, with the 6th (120, by far the lowest packet volume) missed -- and
flagged that 6 total victim examples on one subnet behind one attacker is
too thin to claim real generalization either way. Retrain this (same
command) once more diverse capture data (more hosts, more topologies)
exists -- nothing else needs to change.

    PYTHONPATH=$(pwd)/TAD/scripts python3 TAD/scripts/train_gnn_victim.py
"""
import json
import os

import joblib
import numpy as np
import pandas as pd
import torch
import torch.nn.functional as F
from sklearn.preprocessing import StandardScaler
from torch_geometric.data import Data
from torch_geometric.nn import SAGEConv

from gnn_features import FEATURE_COLS, build_training_graph, to_model_matrix

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TAD_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
CSV = os.path.join(SCRIPT_DIR, "..", "..", "data_collection", "combined_dataset.csv")
TOPOLOGY = os.path.join(SCRIPT_DIR, "..", "..", "PETA", "ncsrd_topology_peta.json")
OUT_DIR = os.path.join(TAD_ROOT, "models", "gnn")
OUT_PATH = os.path.join(OUT_DIR, "victim_sage.pt")

torch.manual_seed(42)
np.random.seed(42)


class SAGE(torch.nn.Module):
    def __init__(self, in_dim, hid=32, out_dim=2):
        super().__init__()
        self.conv1 = SAGEConv(in_dim, hid)
        self.conv2 = SAGEConv(hid, out_dim)

    def forward(self, x, edge_index):
        x = F.relu(self.conv1(x, edge_index))
        x = F.dropout(x, p=0.3, training=self.training)
        return self.conv2(x, edge_index)


def main():
    print(f"[load] {CSV}")
    df = pd.read_csv(CSV)
    topo = json.load(open(TOPOLOGY))
    known_assets = {n.get("ip") for n in topo.get("topology", {}).get("nodes", []) if n.get("ip")}

    all_ips, edge_index, feat_df = build_training_graph(df, known_assets)
    n_victims = int(feat_df["victim"].sum())
    print(f"[graph] {len(all_ips)} nodes, {edge_index.shape[1]} directed edges, "
          f"{n_victims} victim hosts: {sorted(feat_df[feat_df['victim']==1].index)}")
    if n_victims < 6:
        print(f"[warn] only {n_victims} victim hosts in this data -- expected 6 "
              f"(118,120,123,126,204,249). Proceeding anyway, but double-check "
              f"combined_dataset.csv is the full runs 4-7 merge.")

    X_raw = to_model_matrix(feat_df)
    scaler = StandardScaler().fit(X_raw)
    X = scaler.transform(X_raw)
    y = feat_df["victim"].values

    X_t = torch.tensor(X, dtype=torch.float)
    y_t = torch.tensor(y, dtype=torch.long)
    ei_t = torch.tensor(edge_index, dtype=torch.long)
    data = Data(x=X_t, edge_index=ei_t, y=y_t)

    model = SAGE(X_t.shape[1])
    opt = torch.optim.Adam(model.parameters(), lr=0.01, weight_decay=5e-4)
    n_pos, n_neg = int(y.sum()), int((y == 0).sum())
    w = torch.tensor([1.0, n_neg / max(n_pos, 1)], dtype=torch.float)

    model.train()
    for epoch in range(200):
        opt.zero_grad()
        out = model(data.x, data.edge_index)
        loss = F.cross_entropy(out, y_t, weight=w)
        loss.backward()
        opt.step()
        if epoch % 50 == 0 or epoch == 199:
            print(f"  epoch {epoch:>3}  loss {loss.item():.4f}")

    model.eval()
    with torch.no_grad():
        proba = F.softmax(model(data.x, data.edge_index), dim=1)[:, 1]
    print("\n[fit check -- in-sample, NOT a held-out metric] victim probabilities for known victims:")
    for ip in sorted(feat_df[feat_df["victim"] == 1].index):
        i = all_ips.index(ip)
        print(f"    {ip:<16} p(victim)={proba[i]:.3f}")

    os.makedirs(OUT_DIR, exist_ok=True)
    torch.save({
        "model_state": model.state_dict(),
        "in_dim": X_t.shape[1],
        "hidden_dim": 32,
        "feature_cols": FEATURE_COLS,
        "scaler_mean": scaler.mean_,
        "scaler_scale": scaler.scale_,
        "trained_on_hosts": sorted(feat_df[feat_df["victim"] == 1].index),
        "trained_on_rows": len(df),
    }, OUT_PATH)
    print(f"\n[done] saved -> {OUT_PATH}")


if __name__ == "__main__":
    main()
