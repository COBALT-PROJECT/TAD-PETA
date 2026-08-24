"""
zeroday_test_newdataset.py
==========================
Evaluate the EXISTING (already-trained) 4-class flow models against the new
8-class NewDataset15062026, treating the post-exploit classes the old models
were never trained on as ZERO-DAY attacks.

Nothing in the production pipeline is modified. This script only *imports*
`aggregate_flows` / `add_cross_flow_features` / `FEATURE_COLS` from
`flow_aggregation.py` and *loads* the saved model artifacts read-only.

Old models know 4 classes:  benign, bruteforce, dos, scan
New dataset has 8 labels. Mapping into the old model's world:

    benign            -> benign            (KNOWN)
    stress_test       -> dos               (KNOWN family, new capture)
    nmap_scan         -> scan              (KNOWN)
    hydra_bruteforce  -> bruteforce        (KNOWN)
    ssh_connection            )
    reconnaissance_commands   )  ZERO-DAY  (no matching class in old model —
    reverse_shell_wait        )            post-exploitation kill-chain)
    interactive_shell         )

A closed-set classifier cannot output "unknown", so zero-day performance is
measured as NOVELTY:
  * detection rate = fraction of zero-day flows NOT predicted `benign`
    (i.e. flagged as *some* attack -> would still trigger PETA mitigation)
  * prediction confidence (max predict_proba) vs known classes -> whether a
    low-confidence threshold could flag novelty.

Usage:
    PYTHONPATH=$(pwd)/TAD/scripts python3 TAD/scripts/zeroday_test_newdataset.py
    PYTHONPATH=$(pwd)/TAD/scripts python3 TAD/scripts/zeroday_test_newdataset.py \
        --csv TAD/data/NewDataset15062026/labeled_packets_deep.csv
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
from sklearn.metrics import classification_report, confusion_matrix, ConfusionMatrixDisplay

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)
from flow_aggregation import aggregate_flows, add_cross_flow_features, FEATURE_COLS
from train_model_multiclass import build_features

TAD_ROOT   = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
DATA_DIR   = os.path.join(TAD_ROOT, "data", "NewDataset15062026")
MODELS_DIR = os.path.join(TAD_ROOT, "models", "multiclass")
DEFAULT_CSV = os.path.join(DATA_DIR, "labeled_packets_deep.csv")

# ── label mapping: new 8-class -> old 4-class world ──────────────────────────
NEW_TO_OLD = {
    "benign":           "benign",
    "stress_test":      "dos",
    "nmap_scan":        "scan",
    "hydra_bruteforce": "bruteforce",
}
ZERO_DAY_LABELS = [
    "ssh_connection",
    "reconnaissance_commands",
    "reverse_shell_wait",
    "interactive_shell",
]

# TCP flag letters -> bitmask (scapy/tshark convention)
FLAG_BITS = {"F": 0x01, "S": 0x02, "R": 0x04, "P": 0x08,
             "A": 0x10, "U": 0x20, "E": 0x40, "C": 0x80}


def flags_letters_to_int(v) -> int:
    if pd.isna(v):
        return 0
    b = 0
    for ch in str(v).strip():
        b |= FLAG_BITS.get(ch, 0)
    return b


def adapt_schema(df: pd.DataFrame) -> pd.DataFrame:
    """Map the NewDataset per-packet CSV onto the v2 schema aggregate_flows expects."""
    out = pd.DataFrame()
    # format="mixed": some rows have fractional seconds, some don't. A single
    # inferred format silently turns the fractionless ones into NaT -> garbage
    # epoch (INT64_MIN), which corrupts timing features. Parse each robustly.
    ts = pd.to_datetime(df["packet_time_utc"], utc=True, errors="coerce", format="mixed")
    out["timestamp"] = ts.view("int64").astype("float64") / 1e9
    out.loc[ts.isna(), "timestamp"] = 0.0
    out["frame_len"] = pd.to_numeric(df["packet_length"], errors="coerce").fillna(0)
    out["tcp_window_size"] = 0                       # absent in this capture
    out["tcp_ack"] = 0                               # absent -> tcp_ack_zero_nonsyn degraded
    out["ip_ttl"] = pd.to_numeric(df["ip_ttl"], errors="coerce").fillna(0)
    # letter flags -> integer bitmask (else _to_int() would zero every flow's flags)
    out["tcp_flags"] = df["tcp_flags"].apply(flags_letters_to_int)
    out["src_ip"] = df["src_ip"]
    out["dst_ip"] = df["dst_ip"]
    out["src_port"] = pd.to_numeric(df["src_port"], errors="coerce").fillna(0).astype(int)
    out["dst_port"] = pd.to_numeric(df["dst_port"], errors="coerce").fillna(0).astype(int)
    # uppercase so PROTOCOL_MAP resolves (tcp->TCP) instead of falling back to Unknown
    out["protocol"] = df["protocol"].astype(str).str.upper()
    out["label"] = df["label"]
    # no tcp_len column -> flow/per-packet builders fall back to frame_len-54
    return out


def load_model(path):
    art = joblib.load(path)
    return art["model"], art["label_encoder"], art.get("feature_names", FEATURE_COLS)


def evaluate(name, model, le, true8, X, report_lines):
    old_classes = list(le.classes_)
    pred_idx = model.predict(X)
    pred_lbl = le.inverse_transform(pred_idx)
    proba = model.predict_proba(X)
    conf = proba.max(axis=1)

    true8 = np.asarray(true8)
    exp_old = np.array([NEW_TO_OLD.get(l, "ZERO_DAY") for l in true8])
    pred_attack = pred_lbl != "benign"

    def line(s=""):
        print(s)
        report_lines.append(s)

    line("\n" + "=" * 72)
    line(f"MODEL: {name}   (known classes: {old_classes})")
    line("=" * 72)

    # ── A. KNOWN classes ─────────────────────────────────────────────────
    known_mask = exp_old != "ZERO_DAY"
    line("\n[A] KNOWN classes — old model vs new-capture attacks of the same family")
    line(f"    (mapping: {NEW_TO_OLD})")
    yk_true = exp_old[known_mask]
    yk_pred = pred_lbl[known_mask]
    line("")
    line(classification_report(yk_true, yk_pred, labels=old_classes,
                               target_names=old_classes, digits=3, zero_division=0))
    line("    Confusion matrix (rows=true mapped label, cols=prediction):")
    cm = confusion_matrix(yk_true, yk_pred, labels=old_classes)
    line("    " + "            ".join([""] + old_classes))
    for r, cls in zip(cm, old_classes):
        line(f"    {cls:<12} " + "  ".join(f"{v:>8}" for v in r))

    # ── B. ZERO-DAY classes ──────────────────────────────────────────────
    line("\n[B] ZERO-DAY classes — labels the old model was NEVER trained on")
    line(f"    {'label':<26}{'flows':>6}{'flagged_attack':>16}{'det_rate':>10}{'mean_conf':>11}   predicted_as")
    for zl in ZERO_DAY_LABELS:
        m = true8 == zl
        n = int(m.sum())
        if n == 0:
            line(f"    {zl:<26}{0:>6}{'—':>16}{'—':>10}{'—':>11}   (no flows)")
            continue
        flagged = int(pred_attack[m].sum())
        det = flagged / n
        mc = float(conf[m].mean())
        vc = pd.Series(pred_lbl[m]).value_counts()
        pred_str = ", ".join(f"{k}:{v}" for k, v in vc.items())
        line(f"    {zl:<26}{n:>6}{flagged:>16}{det:>9.0%}{mc:>11.3f}   {pred_str}")

    zd_mask = exp_old == "ZERO_DAY"
    if zd_mask.any():
        det_all = pred_attack[zd_mask].mean()
        line(f"\n    Overall zero-day detection rate (flagged as some attack): {det_all:.1%}")

    # ── C. Binary attack-vs-benign (what actually triggers PETA) ──────────
    line("\n[C] Binary view — attack detection (any non-benign prediction triggers PETA)")
    true_attack = true8 != "benign"
    line(classification_report(
        np.where(true_attack, "attack", "benign"),
        np.where(pred_attack, "attack", "benign"),
        labels=["benign", "attack"], target_names=["benign", "attack"],
        digits=3, zero_division=0))

    # ── D. Confidence as a novelty signal ────────────────────────────────
    line("[D] Prediction confidence (max predict_proba) — novelty signal")
    line(f"    known benign flows      : mean conf {conf[exp_old=='benign'].mean():.3f}")
    known_atk = known_mask & (exp_old != "benign")
    if known_atk.any():
        line(f"    known attack flows      : mean conf {conf[known_atk].mean():.3f}")
    if zd_mask.any():
        line(f"    zero-day flows          : mean conf {conf[zd_mask].mean():.3f}")
        for thr in (0.5, 0.6, 0.7):
            line(f"      zero-day flows with conf < {thr}: "
                 f"{(conf[zd_mask] < thr).mean():.0%}")

    return pred_lbl, conf


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default=DEFAULT_CSV)
    ap.add_argument("--flow-timeout", type=float, default=60.0)
    ap.add_argument("--out", default=os.path.join(DATA_DIR, "zeroday_test_results.md"))
    args = ap.parse_args()

    print(f"Loading {args.csv} ...")
    raw = pd.read_csv(args.csv)
    print(f"  packets: {len(raw)}")
    adapted = adapt_schema(raw)

    print("Aggregating into 5-tuple flows ...")
    flows = aggregate_flows(adapted, flow_timeout=args.flow_timeout)
    # cross-flow stats computed from the new dataset itself (full-dataset mode) so
    # the scan behavioural signal is available; the old attacker IP is unseen by
    # the saved artifact stats, which would otherwise zero these features out.
    flows = add_cross_flow_features(flows)
    print(f"  flows: {len(flows)}")

    report_lines = []
    report_lines.append("# Zero-Day Test — Existing 4-class flow models vs NewDataset15062026\n")
    report_lines.append(f"- Source CSV: `{os.path.relpath(args.csv, TAD_ROOT)}`  ({len(raw)} packets)")
    report_lines.append(f"- Flows after 5-tuple aggregation (timeout={args.flow_timeout}s): **{len(flows)}**")
    report_lines.append("- Cross-flow stats: computed from this dataset (full-dataset mode)\n")

    fl = flows["label"].value_counts()
    report_lines.append("## Flow counts per label\n")
    report_lines.append("| label | flows | role |")
    report_lines.append("|---|---|---|")
    role = {**{k: "known→" + v for k, v in NEW_TO_OLD.items()},
            **{z: "ZERO-DAY" for z in ZERO_DAY_LABELS}}
    for lbl in list(NEW_TO_OLD) + ZERO_DAY_LABELS:
        report_lines.append(f"| {lbl} | {int(fl.get(lbl, 0))} | {role.get(lbl,'')} |")
    report_lines.append("")
    print("\nFlow counts per label:")
    for lbl in list(NEW_TO_OLD) + ZERO_DAY_LABELS:
        print(f"  {lbl:<26} {int(fl.get(lbl,0)):>6}  ({role.get(lbl,'')})")

    body = ["\n## FLOW-LEVEL models (production path)\n", "```"]
    for name, path in [("rf_flows",  os.path.join(MODELS_DIR, "rf_flows.joblib")),
                       ("hgb_flows", os.path.join(MODELS_DIR, "hgb_flows.joblib"))]:
        if not os.path.exists(path):
            print(f"  (skip {name}: {path} not found)")
            continue
        model, le, feats = load_model(path)
        X = flows[feats].fillna(0).values
        evaluate(name, model, le, flows["label"].values, X, body)
    body.append("```\n")

    # ── PER-PACKET models: zero-day classes keep their real packet counts ────
    print("\nBuilding per-packet features for per-packet models ...")
    feats_df, feat_names = build_features(adapted)
    body.append("## PER-PACKET models (zero-day classes preserved: "
                "post-exploit packets do not collapse under flow aggregation)\n")
    body.append("```")
    pkt_counts = raw["label"].value_counts()
    print("Per-packet zero-day support:",
          {z: int(pkt_counts.get(z, 0)) for z in ZERO_DAY_LABELS})
    for name, path in [("rf_multiclass",  os.path.join(MODELS_DIR, "rf_multiclass.joblib")),
                       ("hgb_multiclass", os.path.join(MODELS_DIR, "hgb_multiclass.joblib"))]:
        if not os.path.exists(path):
            print(f"  (skip {name}: {path} not found)")
            continue
        model, le, mfeats = load_model(path)
        cols = [c for c in mfeats if c in feats_df.columns]
        X = feats_df[cols].fillna(0).values
        evaluate(name, model, le, adapted["label"].values, X, body)
    body.append("```\n")
    report_lines.extend(body)

    with open(args.out, "w") as f:
        f.write("\n".join(report_lines))
    print(f"\nSaved report -> {args.out}")


if __name__ == "__main__":
    main()
