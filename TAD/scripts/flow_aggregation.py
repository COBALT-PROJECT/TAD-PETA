"""
flow_aggregation.py
===================
Groups per-packet CSV rows into 5-tuple flows and trains classifiers on
behavioural flow-level features — no raw port numbers used as features.

Flow identity key: (src_ip, dst_ip, src_port, dst_port, protocol)

Per-flow features (behavioural):
  Timing     : flow_duration, flow_rate, iat_mean, iat_std, iat_min, iat_max
  Volume     : packet_count, bytes_total, bytes_mean, bytes_std, bytes_rate
  Payload    : payload_mean, payload_zero_ratio
  TCP flags  : syn_count, ack_count, rst_count, fin_count, psh_count,
               syn_ratio, rst_ratio, syn_only_ratio, null_ratio
  Window     : window_mean, window_std, window_zero_ratio
  IP         : ttl_mean, ttl_std

Cross-flow src_ip features (expose scan / DoS behaviour across flows):
  src_unique_dst_ports  — high for port scanners
  src_unique_dst_ips    — high for horizontal scanners
  src_total_flows       — high for flood sources

  IMPORTANT: these are computed from the training split only and joined onto
  test flows (fallback = 0). The training cross-flow table is saved alongside
  the model for use during inference.

Usage:
    python3 TAD/scripts/flow_aggregation.py
    python3 TAD/scripts/flow_aggregation.py --dataset TAD/data/attack_traffic_multiclass.csv
    python3 TAD/scripts/flow_aggregation.py --no-cv
    python3 TAD/scripts/flow_aggregation.py --split-mode temporal

Outputs:
    TAD/data/attack_traffic_flows.csv          — aggregated flow CSV
    TAD/models/multiclass/rf_flows.joblib      — includes cross_flow_stats
    TAD/models/multiclass/hgb_flows.joblib     — includes cross_flow_stats
    TAD/models/multiclass/plots/confusion_matrix_rf_flows.png
    TAD/models/multiclass/plots/confusion_matrix_hgb_flows.png
    TAD/models/multiclass/plots/feature_importance_flows.png
    TAD/models/multiclass/classification_report_flows.txt
"""

import argparse
import os
import sys

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.preprocessing import LabelEncoder

# ── paths ────────────────────────────────────────────────────────────────────
SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
TAD_ROOT     = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
DEFAULT_CSV  = os.path.join(TAD_ROOT, "data", "attack_traffic_multiclass.csv")
FLOWS_CSV    = os.path.join(TAD_ROOT, "data", "attack_traffic_flows.csv")
MODELS_DIR   = os.path.join(TAD_ROOT, "models", "multiclass")
PLOTS_DIR    = os.path.join(MODELS_DIR, "plots")


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--dataset", default=DEFAULT_CSV)
    p.add_argument("--output-flows", default=None,
                   help="Path for the output flows CSV (default: same dir as --dataset)")
    p.add_argument("--test-size", type=float, default=0.2)
    p.add_argument("--no-cv", action="store_true")
    p.add_argument(
        "--split-mode",
        choices=["stratified", "temporal"],
        default="stratified",
        help="stratified: random stratified split (default); "
             "temporal: last --test-size fraction by flow start time",
    )
    p.add_argument(
        "--flow-timeout",
        type=float,
        default=60.0,
        help="Idle timeout in seconds: packets of the same 5-tuple separated by "
             "more than this are split into distinct flows (default: 60 s)",
    )
    return p.parse_args()


# ── TCP flag helpers ─────────────────────────────────────────────────────────

def _to_int(v) -> int:
    try:
        s = str(v).strip()
        return int(s, 16) if s.startswith(("0x", "0X")) else int(s, 0)
    except (ValueError, TypeError):
        return 0


# ── flow aggregation ─────────────────────────────────────────────────────────

def aggregate_flows(df: pd.DataFrame, flow_timeout: float = 60.0) -> pd.DataFrame:
    """
    Group packets by 5-tuple into flows, splitting when the idle gap between
    consecutive packets exceeds flow_timeout seconds.

    Returns one row per flow with behavioural features and a label.
    Cross-flow features are NOT added here — call add_cross_flow_features()
    separately after splitting to avoid leakage.
    """
    df = df.sort_values("timestamp").reset_index(drop=True)

    flags    = df["tcp_flags"].apply(_to_int)
    syn      = (flags & 0x02).astype(bool)
    ack      = (flags & 0x10).astype(bool)
    syn_only = (syn & ~ack)

    df["_flags"]    = flags
    df["_syn"]      = syn.astype(int)
    df["_ack"]      = ack.astype(int)
    df["_rst"]      = ((flags & 0x04) > 0).astype(int)
    df["_fin"]      = ((flags & 0x01) > 0).astype(int)
    df["_psh"]      = ((flags & 0x08) > 0).astype(int)
    df["_syn_only"] = syn_only.astype(int)
    df["_null"]     = (flags == 0).astype(int)

    if "tcp_len" in df.columns:
        df["_payload"] = pd.to_numeric(df["tcp_len"], errors="coerce").fillna(0).clip(lower=0)
    else:
        df["_payload"] = (pd.to_numeric(df["frame_len"], errors="coerce").fillna(0) - 54).clip(lower=0)

    df["_window"] = pd.to_numeric(df["tcp_window_size"], errors="coerce").fillna(0)
    df["_ttl"]    = pd.to_numeric(df["ip_ttl"], errors="coerce").fillna(0)
    df["_flen"]   = pd.to_numeric(df["frame_len"], errors="coerce").fillna(0)

    flow_key = ["src_ip", "dst_ip", "src_port", "dst_port", "protocol"]

    rows = []
    for key, grp in df.groupby(flow_key, sort=False):
        grp = grp.sort_values("timestamp")
        ts  = grp["timestamp"].values
        n   = len(grp)

        # Split the group into sub-flows wherever the idle gap > flow_timeout
        if n > 1 and flow_timeout > 0:
            gaps = np.diff(ts)
            split_points = np.where(gaps > flow_timeout)[0] + 1
            sub_groups = np.split(grp, split_points)
        else:
            sub_groups = [grp]

        for grp in sub_groups:
            grp = grp.reset_index(drop=True)
            ts  = grp["timestamp"].values
            n   = len(grp)

            duration = float(ts[-1] - ts[0])
            safe_dur = max(duration, 1e-6)

            if n > 1:
                iats = np.diff(ts)
                iat_mean = float(np.mean(iats))
                iat_std  = float(np.std(iats))
                iat_min  = float(np.min(iats))
                iat_max  = float(np.max(iats))
            else:
                iat_mean = iat_std = iat_min = iat_max = 0.0

            payload_vals = grp["_payload"].values
            window_vals  = grp["_window"].values
            flen_vals    = grp["_flen"].values
            bytes_total  = float(flen_vals.sum())

            syn_c = int(grp["_syn"].sum())
            rst_c = int(grp["_rst"].sum())

            row = {
                # identity (not ML features; kept for cross-flow computation)
                "src_ip":          key[0],
                "dst_port":        key[3],
                "dst_ip":          key[1],
                "flow_start_time": float(ts[0]),

                # timing
                "flow_duration":  duration,
                "flow_rate":      n / safe_dur,
                "packet_count":   n,
                "iat_mean":       iat_mean,
                "iat_std":        iat_std,
                "iat_min":        iat_min,
                "iat_max":        iat_max,

                # volume
                "bytes_total":    bytes_total,
                "bytes_mean":     float(flen_vals.mean()),
                "bytes_std":      float(flen_vals.std() if n > 1 else 0.0),
                "bytes_rate":     bytes_total / safe_dur,

                # payload
                "payload_mean":       float(payload_vals.mean()),
                "payload_zero_ratio": float((payload_vals == 0).mean()),

                # TCP flags
                "syn_count":      syn_c,
                "ack_count":      int(grp["_ack"].sum()),
                "rst_count":      rst_c,
                "fin_count":      int(grp["_fin"].sum()),
                "psh_count":      int(grp["_psh"].sum()),
                "syn_ratio":      syn_c / n,
                "rst_ratio":      rst_c / n,
                "syn_only_ratio": float(grp["_syn_only"].mean()),
                "null_ratio":     float(grp["_null"].mean()),

                # window
                "window_mean":       float(window_vals.mean()),
                "window_std":        float(window_vals.std() if n > 1 else 0.0),
                "window_zero_ratio": float((window_vals == 0).mean()),

                # IP
                "ttl_mean": float(grp["_ttl"].mean()),
                "ttl_std":  float(grp["_ttl"].std() if n > 1 else 0.0),

                # label: majority vote (uniform within a labeled capture)
                "label": grp["label"].mode().iloc[0],
            }
            rows.append(row)

    return pd.DataFrame(rows)


def add_cross_flow_features(
    flows: pd.DataFrame,
    reference_flows: pd.DataFrame | None = None,
) -> pd.DataFrame:
    """
    Append per-src_ip aggregate statistics to each flow.

    reference_flows: the dataframe to compute stats FROM (should be the
    training split only). If None, uses flows itself (full-dataset mode,
    only valid when not evaluating a held-out test set).
    """
    source = reference_flows if reference_flows is not None else flows
    src_stats = source.groupby("src_ip").agg(
        src_unique_dst_ports=("dst_port", "nunique"),
        src_unique_dst_ips=("dst_ip",   "nunique"),
        src_total_flows=("packet_count", "count"),
    ).reset_index()

    merged = flows.merge(src_stats, on="src_ip", how="left")
    # Unknown src_ips (unseen in training) get 0 — conservative, no leakage
    for col in ("src_unique_dst_ports", "src_unique_dst_ips", "src_total_flows"):
        merged[col] = merged[col].fillna(0).astype(int)
    return merged


# ── feature columns used for training ────────────────────────────────────────

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


# ── train / test split ────────────────────────────────────────────────────────

def split_flows(flows: pd.DataFrame, test_size: float, mode: str):
    """
    Returns (train_idx, test_idx) as integer position arrays.

    stratified: random stratified split
    temporal:   last test_size fraction by flow_start_time
                (falls back to stratified per class if any class has < 2 flows
                 in the temporal test window)
    """
    if mode == "stratified":
        idx = np.arange(len(flows))
        tr, te = train_test_split(
            idx, test_size=test_size, stratify=flows["label"].values, random_state=42
        )
        return tr, te

    # temporal: sort by flow_start_time, cut globally
    sorted_idx = flows.sort_values("flow_start_time").index.tolist()
    cut = int(len(sorted_idx) * (1 - test_size))
    tr = sorted_idx[:cut]
    te = sorted_idx[cut:]

    # Safety: ensure every label appears in both splits
    tr_labels = set(flows.loc[tr, "label"])
    te_labels = set(flows.loc[te, "label"])
    missing = tr_labels.symmetric_difference(te_labels)
    if missing:
        print(f"  WARNING: temporal split is missing labels {missing} in one split; "
              "falling back to stratified.")
        idx = np.arange(len(flows))
        tr, te = train_test_split(
            idx, test_size=test_size, stratify=flows["label"].values, random_state=42
        )
    return tr, te


# ── plotting ─────────────────────────────────────────────────────────────────

def set_style():
    plt.rcParams.update({
        "figure.facecolor": "#1a1a2e",
        "axes.facecolor":   "#16213e",
        "axes.labelcolor":  "#e0e0e0",
        "axes.titlecolor":  "#00d4ff",
        "xtick.color":      "#e0e0e0",
        "ytick.color":      "#e0e0e0",
        "text.color":       "#e0e0e0",
        "grid.color":       "#2a2a4a",
    })


def plot_cm(y_true, y_pred, classes, title, path):
    fig, ax = plt.subplots(figsize=(8, 7))
    ConfusionMatrixDisplay(confusion_matrix(y_true, y_pred),
                           display_labels=classes).plot(ax=ax, colorbar=False, cmap="Blues")
    ax.set_title(title, pad=14, fontsize=12)
    fig.savefig(path, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close(fig)
    print(f"  Saved -> {path}")


def plot_importance(importances, names, title, path):
    idx    = np.argsort(importances)[::-1]
    names  = [names[i] for i in idx]
    vals   = importances[idx]
    colors = plt.cm.plasma(np.linspace(0.3, 0.9, len(names)))

    fig, ax = plt.subplots(figsize=(12, 5))
    ax.bar(names, vals, color=colors)
    ax.set_ylabel("Importance")
    ax.set_title(title, fontsize=12)
    plt.xticks(rotation=40, ha="right")
    fig.tight_layout()
    fig.savefig(path, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close(fig)
    print(f"  Saved -> {path}")


# ── train / evaluate ─────────────────────────────────────────────────────────

def train_eval(model, name, X_tr, X_te, y_tr, y_te, le, run_cv):
    print(f"\n{'─'*55}")
    print(f"  Training {name} ...")
    model.fit(X_tr, y_tr)

    if run_cv:
        cv = cross_val_score(model, X_tr, y_tr, cv=5, scoring="f1_macro", n_jobs=-1)
        print(f"  5-fold CV macro-F1: {cv.mean():.4f} +/- {cv.std():.4f}")

    y_pred  = model.predict(X_te)
    report  = classification_report(y_te, y_pred, target_names=le.classes_, digits=4)
    print(f"\n{report}")
    return y_pred, report


# ── main ─────────────────────────────────────────────────────────────────────

def main():
    args = parse_args()
    os.makedirs(PLOTS_DIR, exist_ok=True)
    set_style()

    if not os.path.exists(args.dataset):
        print(f"ERROR: {args.dataset} not found. Run pcap_to_csv_v2.sh first.")
        sys.exit(1)

    # ── load packets ─────────────────────────────────────────────────────
    print(f"  Loading {args.dataset} ...")
    df = pd.read_csv(args.dataset, low_memory=False)
    df["timestamp"] = pd.to_numeric(df["timestamp"], errors="coerce")
    df["src_port"]  = pd.to_numeric(df["src_port"],  errors="coerce").fillna(0).astype(int)
    df["dst_port"]  = pd.to_numeric(df["dst_port"],  errors="coerce").fillna(0).astype(int)
    print(f"  Packets loaded: {len(df)}")

    # ── aggregate into flows (no cross-flow stats yet) ───────────────────
    print(f"  Aggregating packets into flows (timeout={args.flow_timeout}s) ...")
    flows_base = aggregate_flows(df, flow_timeout=args.flow_timeout)
    print(f"  Flows: {len(flows_base)}")

    print("\n  Class distribution (flows):")
    for lbl, cnt in flows_base["label"].value_counts().items():
        print(f"    {lbl:<12} {cnt}")

    # ── train / test split BEFORE cross-flow features ────────────────────
    print(f"\n  Split mode: {args.split_mode}")
    train_idx, test_idx = split_flows(flows_base, args.test_size, args.split_mode)
    train_base = flows_base.loc[train_idx]
    test_base  = flows_base.loc[test_idx]
    print(f"  Train flows   : {len(train_base)}")
    print(f"  Test flows    : {len(test_base)}")

    # ── add cross-flow features using only training data as reference ─────
    # This prevents test flows from observing training-derived aggregates
    # and preserves a realistic production setup (stats come from seen data only).
    train_flows = add_cross_flow_features(train_base, reference_flows=train_base)
    test_flows  = add_cross_flow_features(test_base,  reference_flows=train_base)

    # Save the full-dataset CSV with cross-flow stats for inspection
    flows_output = args.output_flows if args.output_flows else \
        os.path.join(os.path.dirname(args.dataset), "attack_traffic_flows.csv")
    full_flows = add_cross_flow_features(flows_base)
    full_flows.to_csv(flows_output, index=False)
    print(f"  Saved -> {flows_output}")

    # Cross-flow lookup table (saved with model for inference use)
    cross_flow_stats = train_base.groupby("src_ip").agg(
        src_unique_dst_ports=("dst_port", "nunique"),
        src_unique_dst_ips=("dst_ip",   "nunique"),
        src_total_flows=("packet_count", "count"),
    ).reset_index()

    # ── prepare features / labels ────────────────────────────────────────
    le = LabelEncoder()
    le.fit(sorted(flows_base["label"].unique()))

    X_train = train_flows[FEATURE_COLS].fillna(0).values
    y_train = le.transform(train_flows["label"])
    X_test  = test_flows[FEATURE_COLS].fillna(0).values
    y_test  = le.transform(test_flows["label"])

    print(f"\n  Feature count : {len(FEATURE_COLS)}")

    # ── Random Forest ────────────────────────────────────────────────────
    rf = RandomForestClassifier(
        n_estimators=300, max_depth=None,
        class_weight="balanced", n_jobs=-1, random_state=42,
    )
    rf_pred, rf_report = train_eval(
        rf, "Random Forest", X_train, X_test, y_train, y_test, le,
        run_cv=not args.no_cv,
    )
    plot_cm(y_test, rf_pred, le.classes_,
            "Random Forest — Flow-Level Confusion Matrix",
            os.path.join(PLOTS_DIR, "confusion_matrix_rf_flows.png"))
    plot_importance(rf.feature_importances_, FEATURE_COLS,
                    "Random Forest — Flow Feature Importances",
                    os.path.join(PLOTS_DIR, "feature_importance_flows.png"))
    rf_path = os.path.join(MODELS_DIR, "rf_flows.joblib")
    joblib.dump({
        "model": rf,
        "label_encoder": le,
        "feature_names": FEATURE_COLS,
        "cross_flow_stats": cross_flow_stats,
    }, rf_path)
    print(f"  Saved -> {rf_path}")

    # ── Hist Gradient Boosting ───────────────────────────────────────────
    hgb = HistGradientBoostingClassifier(
        max_iter=300, learning_rate=0.05, max_depth=6,
        class_weight="balanced", random_state=42,
    )
    hgb_pred, hgb_report = train_eval(
        hgb, "Hist Gradient Boosting", X_train, X_test, y_train, y_test, le,
        run_cv=not args.no_cv,
    )
    plot_cm(y_test, hgb_pred, le.classes_,
            "Hist Gradient Boosting — Flow-Level Confusion Matrix",
            os.path.join(PLOTS_DIR, "confusion_matrix_hgb_flows.png"))
    hgb_path = os.path.join(MODELS_DIR, "hgb_flows.joblib")
    joblib.dump({
        "model": hgb,
        "label_encoder": le,
        "feature_names": FEATURE_COLS,
        "cross_flow_stats": cross_flow_stats,
    }, hgb_path)
    print(f"  Saved -> {hgb_path}")

    # ── report ───────────────────────────────────────────────────────────
    report_path = os.path.join(MODELS_DIR, "classification_report_flows.txt")
    with open(report_path, "w") as f:
        f.write("=" * 60 + "\n")
        f.write("TAD Flow-Level Classification Report\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Source packets : {len(df)}\n")
        f.write(f"Flows          : {len(flows_base)}\n")
        f.write(f"Flow timeout   : {args.flow_timeout}s\n")
        f.write(f"Split mode     : {args.split_mode}\n")
        f.write(f"Features       : {FEATURE_COLS}\n")
        f.write(f"Train flows    : {len(X_train)}\n")
        f.write(f"Test flows     : {len(X_test)}\n\n")
        f.write("Random Forest\n" + "-" * 40 + "\n")
        f.write(rf_report + "\n\n")
        f.write("Hist Gradient Boosting\n" + "-" * 40 + "\n")
        f.write(hgb_report + "\n")
    print(f"\n  Saved -> {report_path}")
    print("\nDone.")


if __name__ == "__main__":
    main()
