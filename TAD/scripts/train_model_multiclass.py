"""
train_model_multiclass.py
=========================
Trains multi-class traffic classifiers (Random Forest + Hist Gradient Boosting)
on the TAD dataset to distinguish: benign / bruteforce / dos / scan

Features are behavioural only — raw src_port, dst_port, tcp_seq, tcp_ack are
excluded to avoid overfitting to lab port assignments and session identity.

Usage:
    python3 TAD/scripts/train_model_multiclass.py
    python3 TAD/scripts/train_model_multiclass.py --dataset TAD/data/attack_traffic_multiclass.csv

Outputs (in TAD/models/multiclass/):
    rf_multiclass.joblib
    hgb_multiclass.joblib
    plots/
        confusion_matrix_rf.png
        confusion_matrix_hgb.png
        feature_importance_rf.png
        feature_importance_hgb.png
        classification_report.txt
"""

import argparse
import os
import sys
from collections import deque

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from imblearn.over_sampling import SMOTE
from sklearn.ensemble import (
    HistGradientBoostingClassifier,
    RandomForestClassifier,
    VotingClassifier,
)
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.svm import SVC

# ── paths ───────────────────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TAD_ROOT   = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
DEFAULT_DATASET  = os.path.join(TAD_ROOT, "data", "attack_traffic_multiclass.csv")
FALLBACK_DATASET = os.path.join(TAD_ROOT, "data", "attack_traffic_advanced.csv")
MODELS_DIR = os.path.join(TAD_ROOT, "models", "multiclass")
PLOTS_DIR  = os.path.join(MODELS_DIR, "plots")

PROTOCOL_MAP = {
    "TCP": 0, "UDP": 1, "ICMP": 2, "ARP": 3, "DNS": 4,
    "HTTP": 5, "HTTPS": 6, "SSH": 7, "SSHv2": 7,
    "TLSv1.2": 8, "TLSv1.3": 9, "Unknown": 10,
}


def parse_args():
    p = argparse.ArgumentParser(description="Train TAD multi-class traffic classifier")
    p.add_argument("--dataset", default=None, help="Path to training CSV")
    p.add_argument("--test-size", type=float, default=0.2)
    p.add_argument("--n-estimators", type=int, default=300,
                   help="Trees in Random Forest")
    p.add_argument("--window", type=int, default=20,
                   help="Rolling context window size (packets per src_ip)")
    p.add_argument("--no-cv", action="store_true",
                   help="Skip 5-fold cross-validation (faster)")
    p.add_argument("--no-smote", action="store_true",
                   help="Skip SMOTE oversampling on the training split")
    return p.parse_args()


# ── TCP flag decomposition ───────────────────────────────────────────────────

def _parse_flags(val) -> int:
    try:
        s = str(val).strip()
        return int(s, 16) if s.startswith(("0x", "0X")) else int(s, 0)
    except (ValueError, TypeError):
        return 0


def _flag_features(flags_series: pd.Series) -> pd.DataFrame:
    vals = flags_series.apply(_parse_flags)
    syn  = (vals & 0x02).astype(bool)
    ack  = (vals & 0x10).astype(bool)
    return pd.DataFrame({
        "flag_fin":      (vals & 0x01).astype(int),
        "flag_syn":      syn.astype(int),
        "flag_rst":      (vals & 0x04).astype(int),
        "flag_psh":      (vals & 0x08).astype(int),
        "flag_ack":      ack.astype(int),
        "flag_syn_only": (syn & ~ack).astype(int),
        "flag_null":     (vals == 0).astype(int),
    }, index=flags_series.index)


# ── label handling ───────────────────────────────────────────────────────────

def _infer_multiclass_label(df: pd.DataFrame) -> pd.Series:
    """Fall back when only binary labels (0/1) are present."""
    labels = pd.Series(["benign"] * len(df), index=df.index)
    attack = ~df["label"].astype(str).isin(["0", "benign", "0.0"])

    def _safe_float(v):
        try:
            return float(v)
        except (ValueError, TypeError):
            return float("nan")

    dst = df["dst_port"].apply(_safe_float)
    labels[attack & (dst == 22)] = "bruteforce"
    labels[attack & (dst == 80)] = "dos"
    labels[attack & (dst != 22) & (dst != 80)] = "scan"
    return labels


# ── feature engineering ──────────────────────────────────────────────────────

PAIR_K = 60          # rolling window (packets) for the per-pair flow features


def _pair_features(df: pd.DataFrame, k: int = PAIR_K) -> pd.DataFrame:
    """Per-{src,dst}-pair flow features over the pair's last k packets, the one
    class of signal the per-source rolling stats cannot see -- whether traffic
    is a one-way flood (DoS/scan) or a real two-way service exchange. Three
    features, each verified (offline, Cohen's d) to separate benign K8s chatter
    from real attack traffic better than balance alone:

      ctx_pair_balance    min(fwd,rev)/max(fwd,rev)     ~0 one-way, ~1 balanced
      ctx_pair_replydata  reverse-direction PSH share   server pushes data back
      ctx_pair_handshake  reverse SYN-ACK / fwd SYN     new-connection activity

    Computed in the DataFrame's given (arrival/timestamp) order so
    PacketClassifier's live per-pair state reproduces it byte-for-byte."""
    src = df["src_ip"].astype(str).values
    dst = df["dst_ip"].astype(str).values
    flags = df["tcp_flags"].apply(_parse_flags).values
    n = len(df)
    bal = np.zeros(n); reply = np.zeros(n); hs = np.zeros(n)
    wins: dict = {}
    for i in range(n):
        a, b = src[i], dst[i]
        pair = (a, b) if a <= b else (b, a)
        fwd = a <= b                              # canonical direction A->B
        fb = int(flags[i])
        syn = (fb & 0x02) and not (fb & 0x10)     # SYN-only (connection attempt)
        sa  = (fb & 0x02) and (fb & 0x10)         # SYN-ACK (handshake reply)
        psh = fb & 0x08                           # data push
        w = wins.get(pair)
        if w is None:
            w = wins[pair] = deque(maxlen=k)
        w.append((fwd, bool(syn), bool(sa), bool(psh)))
        f = sum(1 for r in w if r[0]); rv = len(w) - f
        mx = max(f, rv)
        bal[i] = (min(f, rv) / mx) if mx > 0 else 0.0
        reply[i] = sum(1 for r in w if (not r[0]) and r[3]) / len(w)
        fsyn = sum(1 for r in w if r[0] and r[1])
        rsa  = sum(1 for r in w if (not r[0]) and r[2])
        hs[i] = rsa / (fsyn + 1.0)
    return pd.DataFrame({"ctx_pair_balance": bal, "ctx_pair_replydata": reply,
                         "ctx_pair_handshake": hs}, index=df.index)


def build_rolling_context(df: pd.DataFrame, k: int = 20) -> pd.DataFrame:
    """
    For each packet, compute rolling statistics from the last k packets
    sharing the same src_ip. These give each packet its source's recent
    behavioural context without relying on raw port identity.

    Key signals:
      ctx_unique_dst_ports — rises fast for port scanners
      ctx_pkt_rate         — very high for DoS floods
      ctx_bytes_rate       — high for volumetric DoS
      ctx_syn_ratio        — high for SYN scans / SYN floods
      ctx_rst_ratio        — high for RST scans
    """
    df_work = pd.DataFrame({
        "src_ip":    df["src_ip"].values,
        "timestamp": pd.to_numeric(df["timestamp"], errors="coerce").fillna(0).values,
        "frame_len": pd.to_numeric(df["frame_len"], errors="coerce").fillna(0).values,
        "dst_port":  pd.to_numeric(df["dst_port"],  errors="coerce").fillna(0).values,
        "tcp_flags": df["tcp_flags"].apply(_parse_flags).values,
    }, index=df.index)

    df_s = df_work.sort_values(["src_ip", "timestamp"])

    df_s["_syn"]  = ((df_s["tcp_flags"] & 0x02) > 0).astype(int)
    df_s["_rst"]  = ((df_s["tcp_flags"] & 0x04) > 0).astype(int)
    df_s["_null"] = (df_s["tcp_flags"] == 0).astype(int)
    df_s["_iat"]  = df_s.groupby("src_ip")["timestamp"].diff().fillna(0)

    grp = df_s.groupby("src_ip", group_keys=False)

    ctx = pd.DataFrame(index=df_s.index)
    ctx["ctx_iat_mean"]   = grp["_iat"].transform(lambda x: x.rolling(k, min_periods=1).mean())
    ctx["ctx_iat_std"]    = grp["_iat"].transform(lambda x: x.rolling(k, min_periods=1).std().fillna(0))
    ctx["ctx_bytes_mean"] = grp["frame_len"].transform(lambda x: x.rolling(k, min_periods=1).mean())
    ctx["ctx_syn_ratio"]  = grp["_syn"].transform(lambda x: x.rolling(k, min_periods=1).mean())
    ctx["ctx_rst_ratio"]  = grp["_rst"].transform(lambda x: x.rolling(k, min_periods=1).mean())
    ctx["ctx_null_ratio"] = grp["_null"].transform(lambda x: x.rolling(k, min_periods=1).mean())

    # Unique dst ports in last k packets per src_ip
    src_arr  = df_s["src_ip"].values
    dst_arr  = df_s["dst_port"].values
    ts_arr   = df_s["timestamp"].values
    flen_arr = df_s["frame_len"].values
    n = len(df_s)

    unique_ports = np.zeros(n, dtype=np.float32)
    pkt_rate     = np.zeros(n, dtype=np.float32)
    bytes_rate   = np.zeros(n, dtype=np.float32)

    # Track the first index belonging to each src_ip to prevent cross-group windows
    src_start: dict[str, int] = {}
    for i in range(n):
        src = src_arr[i]
        if src not in src_start:
            src_start[src] = i
        start = max(src_start[src], i - k + 1)
        win_dst  = dst_arr[start:i + 1]
        win_ts   = ts_arr[start:i + 1]
        win_flen = flen_arr[start:i + 1]
        dur = max(float(win_ts[-1] - win_ts[0]), 1e-6)
        unique_ports[i] = float(len(np.unique(win_dst)))
        pkt_rate[i]     = len(win_ts) / dur
        bytes_rate[i]   = float(win_flen.sum()) / dur

    ctx["ctx_unique_dst_ports"] = unique_ports
    ctx["ctx_pkt_rate"]         = pkt_rate
    ctx["ctx_bytes_rate"]       = bytes_rate

    return ctx.reindex(df.index).fillna(0)


def build_features(df: pd.DataFrame, k: int = 20) -> tuple[pd.DataFrame, list[str]]:
    """
    Returns (feature_df, feature_names).
    Raw src_port / dst_port / tcp_seq / tcp_ack are NOT included as features —
    they overfit to lab topology. Derived binary signals and rolling context are
    used instead.
    """
    feats = pd.DataFrame(index=df.index)

    # TCP flags — individual bits carry attack signatures (SYN flood, NULL scan…)
    feats = pd.concat([feats, _flag_features(df["tcp_flags"])], axis=1)

    # Window / ACK anomaly
    feats["tcp_window_size"]     = pd.to_numeric(df["tcp_window_size"], errors="coerce").fillna(0)
    feats["tcp_window_zero"]     = (feats["tcp_window_size"] == 0).astype(int)
    feats["tcp_window_large"]    = (feats["tcp_window_size"] > 60000).astype(int)
    feats["tcp_ack_zero_nonsyn"] = (
        (pd.to_numeric(df["tcp_ack"], errors="coerce").fillna(0) == 0)
        & (feats["flag_syn"] == 0)
    ).astype(int)

    # Payload length — use tcp_len if available (v2 CSV), else estimate
    if "tcp_len" in df.columns:
        feats["payload_len"] = pd.to_numeric(df["tcp_len"], errors="coerce").fillna(0).clip(lower=0)
    else:
        feats["payload_len"] = (pd.to_numeric(df["frame_len"], errors="coerce").fillna(0) - 54).clip(lower=0)
    feats["payload_zero"] = (feats["payload_len"] == 0).astype(int)
    feats["frame_len"]    = pd.to_numeric(df["frame_len"], errors="coerce").fillna(0)

    # Port signals — derived only (well-known vs ephemeral, equality)
    src = pd.to_numeric(df["src_port"], errors="coerce").fillna(0)
    dst = pd.to_numeric(df["dst_port"], errors="coerce").fillna(0)
    feats["dst_well_known"] = (dst < 1024).astype(int)
    feats["src_well_known"] = (src < 1024).astype(int)
    feats["port_equal"]     = (src == dst).astype(int)

    # IP / protocol
    feats["ip_ttl"]        = pd.to_numeric(df["ip_ttl"], errors="coerce").fillna(0)
    feats["ttl_suspicious"] = df["ip_ttl"].apply(
        lambda v: 1 if pd.to_numeric(v, errors="coerce") in (64, 128, 255) else 0
    )
    feats["protocol_enc"]  = df["protocol"].apply(
        lambda v: PROTOCOL_MAP.get(str(v).strip(), PROTOCOL_MAP["Unknown"])
    )

    # Single-packet IAT (diff from previous packet of same src_ip)
    if "timestamp" in df.columns:
        ts = pd.to_numeric(df["timestamp"], errors="coerce")
        feats["interarrival_time"] = (
            df.assign(_ts=ts).sort_values("_ts")
            .groupby("src_ip")["_ts"].diff()
            .reindex(df.index).fillna(0).clip(lower=0)
        )
    else:
        feats["interarrival_time"] = 0.0

    # Rolling window context — the most discriminating features
    if "timestamp" in df.columns and "src_ip" in df.columns:
        ctx = build_rolling_context(df, k=k)
        feats = pd.concat([feats, ctx], axis=1)
        # Per-pair bidirectional flow features (balance / reply-data / handshake)
        # -- the one-way-flood vs two-way-conversation signal the per-source
        # rolling features cannot see. Computed in arrival (timestamp) order so
        # the streaming extractor reproduces them exactly.
        feats = pd.concat([feats, _pair_features(df)], axis=1)

    return feats, list(feats.columns)


def load_and_prepare(dataset_path: str, window: int = 20):
    print(f"  Loading {dataset_path} ...")
    df = pd.read_csv(dataset_path, low_memory=False)
    print(f"  Shape: {df.shape}")

    lbl_raw = df["label"].astype(str).str.strip().str.lower()
    unique  = set(lbl_raw.unique())
    print(f"  Unique labels: {sorted(unique)}")

    if unique.issubset({"0", "1", "0.0", "1.0"}):
        print("  Binary labels detected — reconstructing multi-class from port heuristics")
        df["label"] = _infer_multiclass_label(df)
        lbl_raw = df["label"].astype(str).str.strip().str.lower()

    le = LabelEncoder()
    le.fit(sorted(lbl_raw.unique()))
    y = le.transform(lbl_raw)
    print(f"  Label encoding: {dict(zip(le.classes_, le.transform(le.classes_)))}")

    print(f"  Building features (rolling window k={window}) ...")
    X_df, feat_names = build_features(df, k=window)
    print(f"  Feature count: {len(feat_names)}")
    return X_df.values, y, le, feat_names


# ── plotting ─────────────────────────────────────────────────────────────────

def set_plot_style():
    plt.rcParams.update({
        "figure.facecolor": "#1a1a2e",
        "axes.facecolor":   "#16213e",
        "axes.labelcolor":  "#e0e0e0",
        "axes.titlecolor":  "#00d4ff",
        "xtick.color":      "#e0e0e0",
        "ytick.color":      "#e0e0e0",
        "text.color":       "#e0e0e0",
        "grid.color":       "#2a2a4a",
        "font.family":      "DejaVu Sans",
    })


def plot_confusion_matrix(y_true, y_pred, class_names, title, path):
    fig, ax = plt.subplots(figsize=(8, 7))
    disp = ConfusionMatrixDisplay(confusion_matrix(y_true, y_pred),
                                  display_labels=class_names)
    disp.plot(ax=ax, colorbar=False, cmap="Blues")
    ax.set_title(title, pad=14, fontsize=12)
    fig.savefig(path, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close(fig)
    print(f"  Saved -> {path}")


def plot_feature_importance(importances, feat_names, title, out_path):
    idx   = np.argsort(importances)[::-1]
    names = [feat_names[i] for i in idx]
    vals  = importances[idx]
    colors = plt.cm.plasma(np.linspace(0.3, 0.9, len(names)))

    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar(names, vals, color=colors)
    ax.set_xlabel("Feature")
    ax.set_ylabel("Importance")
    ax.set_title(title, fontsize=12)
    plt.xticks(rotation=35, ha="right")
    fig.tight_layout()
    fig.savefig(out_path, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close(fig)
    print(f"  Saved -> {out_path}")


# ── train / evaluate ─────────────────────────────────────────────────────────

def train_and_evaluate(model, name, X_train, X_test, y_train, y_test, le, run_cv):
    print(f"\n{'─'*50}")
    print(f"  Training {name} ...")
    model.fit(X_train, y_train)

    if run_cv:
        cv = cross_val_score(model, X_train, y_train, cv=5,
                             scoring="f1_macro", n_jobs=-1)
        print(f"  5-fold CV macro-F1: {cv.mean():.4f} +/- {cv.std():.4f}")

    y_pred = model.predict(X_test)
    report = classification_report(y_test, y_pred,
                                   target_names=le.classes_, digits=4)
    print(f"\n{report}")
    return y_pred, report


# ── main ─────────────────────────────────────────────────────────────────────

def main():
    args = parse_args()
    os.makedirs(PLOTS_DIR, exist_ok=True)
    set_plot_style()

    dataset_path = args.dataset or (
        DEFAULT_DATASET if os.path.exists(DEFAULT_DATASET) else FALLBACK_DATASET
    )
    if not os.path.exists(dataset_path):
        print(f"ERROR: dataset not found: {dataset_path}")
        print("  Run pcap_to_csv_v2.sh first.")
        sys.exit(1)

    X, y, le, feat_names = load_and_prepare(dataset_path)
    print(f"\n  Classes: {le.classes_}")
    for i, cls in enumerate(le.classes_):
        print(f"    {i} -> {cls}: {(y == i).sum()} samples")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, stratify=y, random_state=42
    )
    print(f"\n  Train: {len(X_train)}  Test: {len(X_test)}")

    # ── Random Forest ─────────────────────────────────────────────────────
    rf = RandomForestClassifier(
        n_estimators=args.n_estimators,
        max_depth=None,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42,
    )
    rf_pred, rf_report = train_and_evaluate(
        rf, "Random Forest", X_train, X_test, y_train, y_test, le,
        run_cv=not args.no_cv,
    )
    plot_confusion_matrix(
        y_test, rf_pred, le.classes_,
        "Random Forest — Multi-Class Confusion Matrix",
        os.path.join(PLOTS_DIR, "confusion_matrix_rf.png"),
    )
    plot_feature_importance(
        rf.feature_importances_, feat_names,
        "Random Forest — Feature Importances",
        os.path.join(PLOTS_DIR, "feature_importance_rf.png"),
    )
    rf_path = os.path.join(MODELS_DIR, "rf_multiclass.joblib")
    joblib.dump({"model": rf, "label_encoder": le, "feature_names": feat_names}, rf_path)
    print(f"  Saved -> {rf_path}")

    # ── Hist Gradient Boosting (replaces slow GradientBoostingClassifier) ─
    hgb = HistGradientBoostingClassifier(
        max_iter=200,
        learning_rate=0.1,
        max_depth=6,
        class_weight="balanced",
        random_state=42,
    )
    hgb_pred, hgb_report = train_and_evaluate(
        hgb, "Hist Gradient Boosting", X_train, X_test, y_train, y_test, le,
        run_cv=not args.no_cv,
    )
    plot_confusion_matrix(
        y_test, hgb_pred, le.classes_,
        "Hist Gradient Boosting — Multi-Class Confusion Matrix",
        os.path.join(PLOTS_DIR, "confusion_matrix_hgb.png"),
    )
    # HistGradientBoostingClassifier doesn't expose feature_importances_ natively
    # RF importance plot already covers feature analysis
    hgb_path = os.path.join(MODELS_DIR, "hgb_multiclass.joblib")
    joblib.dump({"model": hgb, "label_encoder": le, "feature_names": feat_names}, hgb_path)
    print(f"  Saved -> {hgb_path}")

    # ── combined report ───────────────────────────────────────────────────
    report_path = os.path.join(MODELS_DIR, "classification_report.txt")
    with open(report_path, "w") as f:
        f.write("=" * 60 + "\n")
        f.write("TAD Multi-Class Classification Report\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Dataset  : {dataset_path}\n")
        f.write(f"Classes  : {list(le.classes_)}\n")
        f.write(f"Features : {feat_names}\n")
        f.write(f"Train    : {len(X_train)} samples\n")
        f.write(f"Test     : {len(X_test)} samples\n\n")
        f.write("Random Forest\n" + "-" * 40 + "\n")
        f.write(rf_report + "\n\n")
        f.write("Hist Gradient Boosting\n" + "-" * 40 + "\n")
        f.write(hgb_report + "\n")
    print(f"\n  Saved -> {report_path}")
    print("\nDone.")


if __name__ == "__main__":
    main()
