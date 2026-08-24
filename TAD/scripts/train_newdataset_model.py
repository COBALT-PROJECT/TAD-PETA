"""
train_newdataset_model.py
=========================
Train a NEW attack-detection model on NewDataset15062026 (per-packet).

Reuses, unchanged:
  * build_features  (train_model_multiclass.py)   — 21 behavioural features
  * adapt_schema    (zeroday_test_newdataset.py)   — NewDataset CSV -> v2 schema

Does NOT touch the production artifacts. Saves under distinct names:
  TAD/models/multiclass/rf_newdataset_<taxonomy>.joblib

Taxonomies:
  8class  — all 8 fine-grained labels (micro-classes unlearnable, expect low tail F1)
  5class  — collapse the 4 post-exploit labels into `post_exploitation`
            (benign, stress_test, nmap_scan, hydra_bruteforce, post_exploitation)
  binary  — benign vs attack

Split modes:
  stratified — random stratified per-packet split (repo default)
  group      — GroupShuffleSplit by 5-tuple flow: no packets from the same flow
               appear in both train and test (harder, less leakage / more honest)

Usage:
  PYTHONPATH=$(pwd)/TAD/scripts python3 TAD/scripts/train_newdataset_model.py \
      --taxonomy 5class --split group --model both
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
from sklearn.inspection import permutation_importance
from sklearn.metrics import (balanced_accuracy_score, classification_report,
                             ConfusionMatrixDisplay, confusion_matrix, f1_score)
from sklearn.model_selection import (GroupShuffleSplit, StratifiedKFold,
                                     cross_val_score, train_test_split)
from sklearn.preprocessing import LabelEncoder

PLOTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
                         "models", "multiclass", "plots")

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)
from train_model_multiclass import build_features, build_rolling_context
from zeroday_test_newdataset import adapt_schema

TAD_ROOT   = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
DATA_DIR   = os.path.join(TAD_ROOT, "data", "NewDataset15062026")
MODELS_DIR = os.path.join(TAD_ROOT, "models", "multiclass")
DEFAULT_CSV = os.path.join(DATA_DIR, "labeled_packets_deep.csv")

POST_EXPLOIT = {"ssh_connection", "reconnaissance_commands",
                "reverse_shell_wait", "interactive_shell"}


def collapse_labels(labels: pd.Series, taxonomy: str) -> pd.Series:
    if taxonomy == "8class":
        return labels
    if taxonomy == "5class":
        return labels.apply(lambda l: "post_exploitation" if l in POST_EXPLOIT else l)
    if taxonomy == "binary":
        return labels.apply(lambda l: "benign" if l == "benign" else "attack")
    raise ValueError(taxonomy)


def flow_group_ids(adapted: pd.DataFrame) -> np.ndarray:
    """5-tuple id per packet so a flow never straddles train/test."""
    key = (adapted["src_ip"].astype(str) + "|" + adapted["dst_ip"].astype(str) + "|" +
           adapted["src_port"].astype(str) + "|" + adapted["dst_port"].astype(str) + "|" +
           adapted["protocol"].astype(str))
    return key.values


def split(X, y, groups, mode, test_size=0.2, seed=42):
    if mode == "stratified":
        idx = np.arange(len(y))
        tr, te = train_test_split(idx, test_size=test_size, stratify=y, random_state=seed)
        return tr, te
    # group split by flow
    gss = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=seed)
    tr, te = next(gss.split(X, y, groups))
    return tr, te


def train_one(name, model, X_tr, X_te, y_tr, y_te, classes, out_lines):
    def line(s=""):
        print(s); out_lines.append(s)

    model.fit(X_tr, y_tr)
    y_pred = model.predict(X_te)
    macro_f1 = f1_score(y_te, y_pred, average="macro")
    bal_acc  = balanced_accuracy_score(y_te, y_pred)
    acc      = (y_pred == y_te).mean()
    # overfit signal: train-set macro-F1 vs test-set macro-F1
    train_f1 = f1_score(y_tr, model.predict(X_tr), average="macro")

    line("\n" + "=" * 66)
    line(f"  {name}")
    line("=" * 66)
    line(classification_report(y_te, y_pred, target_names=classes, digits=4, zero_division=0))
    line(f"  overall accuracy   : {acc:.4f}")
    line(f"  balanced accuracy  : {bal_acc:.4f}   (macro-avg recall)")
    line(f"  macro F1 (test)    : {macro_f1:.4f}")
    line(f"  macro F1 (train)   : {train_f1:.4f}   [train-test gap = {train_f1-macro_f1:+.4f}]")
    line("\n  Confusion matrix (rows=true, cols=pred):")
    cm = confusion_matrix(y_te, y_pred)
    line("    " + " ".join(f"{c[:10]:>11}" for c in classes))
    for r, c in zip(cm, classes):
        line(f"    {c[:14]:<14}" + " ".join(f"{v:>11}" for v in r))
    return model, dict(name=name, accuracy=acc, balanced_accuracy=bal_acc,
                       macro_f1=macro_f1, train_macro_f1=train_f1)


def diagnose_overfit(model_factory, X_tr, y_tr, tag, out_lines):
    """Stratified 5-fold CV on the training data — low variance + CV≈test => not overfit."""
    def line(s=""):
        print(s); out_lines.append(s)
    line("\n" + "-" * 66)
    line(f"  OVERFIT DIAGNOSTIC — {tag}")
    line("-" * 66)
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    scores = cross_val_score(model_factory(), X_tr, y_tr, cv=skf,
                             scoring="f1_macro", n_jobs=-1)
    line(f"  5-fold CV macro-F1 : {scores.mean():.4f} +/- {scores.std():.4f}")
    line(f"  per-fold           : {', '.join(f'{s:.4f}' for s in scores)}")
    return scores


def explain(model, X_te, y_te, feat_names, classes, y_pred, tag, out_lines):
    """Model-agnostic permutation importance + confusion-matrix plot."""
    def line(s=""):
        print(s); out_lines.append(s)
    os.makedirs(PLOTS_DIR, exist_ok=True)

    line("\n" + "-" * 66)
    line(f"  EXPLAINABILITY — {tag}")
    line("-" * 66)
    # Permutation importance on a capped test sample (works for HGB too, which
    # has no native feature_importances_). Measures the macro-F1 drop when a
    # feature's values are shuffled -> higher = more the model relies on it.
    n = min(len(X_te), 8000)
    rng = np.random.RandomState(42)
    sel = rng.choice(len(X_te), n, replace=False)
    r = permutation_importance(model, X_te[sel], y_te[sel], scoring="f1_macro",
                               n_repeats=10, random_state=42, n_jobs=-1)
    order = np.argsort(r.importances_mean)[::-1]
    line("  Permutation importance (macro-F1 drop when feature shuffled):")
    for i in order[:15]:
        line(f"    {feat_names[i]:<24} {r.importances_mean[i]:+.4f} +/- {r.importances_std[i]:.4f}")

    # sanity: raw-identity features must NOT dominate (would signal memorisation)
    identity_like = [f for f in feat_names if any(k in f.lower()
                     for k in ("ip", "port")) and "well_known" not in f and "equal" not in f]
    if identity_like:
        line(f"  (identity-like features present: {identity_like})")

    # bar plot
    top = order[:15][::-1]
    fig, ax = plt.subplots(figsize=(9, 6))
    ax.barh([feat_names[i] for i in top], [r.importances_mean[i] for i in top],
            xerr=[r.importances_std[i] for i in top], color="#00a8cc")
    ax.set_xlabel("Permutation importance (macro-F1 drop)")
    ax.set_title(f"Feature importance — {tag}")
    fig.tight_layout()
    imp_path = os.path.join(PLOTS_DIR, f"importance_{tag}.png")
    fig.savefig(imp_path, dpi=140, bbox_inches="tight"); plt.close(fig)
    line(f"  Saved -> {os.path.relpath(imp_path, TAD_ROOT)}")

    # confusion matrix plot
    fig, ax = plt.subplots(figsize=(7, 6))
    ConfusionMatrixDisplay(confusion_matrix(y_te, y_pred), display_labels=classes).plot(
        ax=ax, colorbar=False, cmap="Blues", xticks_rotation=45)
    ax.set_title(f"Confusion matrix — {tag}")
    fig.tight_layout()
    cm_path = os.path.join(PLOTS_DIR, f"confusion_{tag}.png")
    fig.savefig(cm_path, dpi=140, bbox_inches="tight"); plt.close(fig)
    line(f"  Saved -> {os.path.relpath(cm_path, TAD_ROOT)}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default=DEFAULT_CSV)
    ap.add_argument("--taxonomy", choices=["8class", "5class", "binary"], default="5class")
    ap.add_argument("--split", choices=["stratified", "group"], default="group")
    ap.add_argument("--features", choices=["base", "rich"], default="rich",
                    help="rich = base 21 features + rolling per-source context")
    ap.add_argument("--model", choices=["rf", "hgb", "both"], default="both")
    ap.add_argument("--test-size", type=float, default=0.2)
    ap.add_argument("--cv", action="store_true", help="run 5-fold CV overfit diagnostic")
    ap.add_argument("--explain", action="store_true",
                    help="permutation importance + confusion/importance plots for best model")
    args = ap.parse_args()

    out_lines = [f"# New-dataset model — taxonomy={args.taxonomy}, split={args.split}\n"]

    print(f"Loading {args.csv} ...")
    raw = pd.read_csv(args.csv)
    adapted = adapt_schema(raw)
    # Sort by timestamp (stable) so build_features' internal global/per-src sorts
    # are no-ops. This makes the per-packet + rolling features STREAMING-equivalent:
    # a live wrapper processing packets in arrival order reproduces them exactly.
    adapted = adapted.sort_values("timestamp", kind="stable").reset_index(drop=True)
    print(f"  packets: {len(adapted)}")

    # build_features already appends build_rolling_context (30 features total:
    # 21 per-packet + 9 rolling context) when timestamp + src_ip are present.
    print(f"Building per-packet features ({args.features}) ...")
    feats_df, _ = build_features(adapted)
    if args.features == "base":
        feats_df = feats_df[[c for c in feats_df.columns if not c.startswith("ctx_")]]
    feat_names = list(feats_df.columns)

    y_str = collapse_labels(adapted["label"], args.taxonomy).values
    le = LabelEncoder().fit(sorted(np.unique(y_str)))
    y = le.transform(y_str)
    classes = list(le.classes_)
    X = feats_df.fillna(0).values
    groups = flow_group_ids(adapted)

    print(f"  taxonomy classes: {classes}")
    dist = pd.Series(y_str).value_counts()
    for c in classes:
        print(f"    {c:<22} {int(dist.get(c,0))}")
    out_lines.append(f"- packets: {len(adapted)}")
    out_lines.append(f"- classes: {classes}")
    out_lines.append(f"- class counts: {dict((c,int(dist.get(c,0))) for c in classes)}\n")

    tr, te = split(X, y, groups, args.split, args.test_size)
    print(f"\n  train packets: {len(tr)}   test packets: {len(te)}   split={args.split}")
    out_lines.append(f"- split: {args.split}  (train {len(tr)} / test {len(te)})")
    X_tr, X_te, y_tr, y_te = X[tr], X[te], y[tr], y[te]

    results = []
    trained = {}
    if args.model in ("rf", "both"):
        rf = RandomForestClassifier(n_estimators=300, class_weight="balanced",
                                    n_jobs=-1, random_state=42)
        m, r = train_one("Random Forest", rf, X_tr, X_te, y_tr, y_te, classes, out_lines)
        trained["rf"] = m; results.append(r)
    if args.model in ("hgb", "both"):
        # early_stopping off: its internal validation split fails when a class
        # has <2 training samples (8class micro-classes)
        hgb = HistGradientBoostingClassifier(max_iter=400, learning_rate=0.06,
                                             max_depth=8, class_weight="balanced",
                                             early_stopping=False, random_state=42)
        try:
            m, r = train_one("Hist Gradient Boosting", hgb, X_tr, X_te, y_tr, y_te,
                             classes, out_lines)
            trained["hgb"] = m; results.append(r)
        except ValueError as e:
            print(f"  (HGB skipped: {e})")

    # save best by macro F1
    best = max(results, key=lambda r: r["macro_f1"])
    best_key = "rf" if best["name"].startswith("Random") else "hgb"
    tag = f"{args.taxonomy}_{args.split}"

    # ── overfit diagnostics + explainability on the best model ───────────────
    if args.cv:
        if best_key == "rf":
            factory = lambda: RandomForestClassifier(n_estimators=300,
                        class_weight="balanced", n_jobs=-1, random_state=42)
        else:
            factory = lambda: HistGradientBoostingClassifier(max_iter=400,
                        learning_rate=0.06, max_depth=8, class_weight="balanced",
                        early_stopping=False, random_state=42)
        diagnose_overfit(factory, X_tr, y_tr, tag, out_lines)
    if args.explain:
        explain(trained[best_key], X_te, y_te, feat_names, classes,
                trained[best_key].predict(X_te), tag, out_lines)
    art_path = os.path.join(MODELS_DIR, f"{best_key}_newdataset_{args.taxonomy}.joblib")
    joblib.dump({"model": trained[best_key], "label_encoder": le,
                 "feature_names": feat_names, "taxonomy": args.taxonomy,
                 "split_mode": args.split}, art_path)
    print(f"\nBest: {best['name']}  macro-F1={best['macro_f1']:.4f}  "
          f"bal-acc={best['balanced_accuracy']:.4f}  acc={best['accuracy']:.4f}")
    print(f"Saved -> {art_path}")
    out_lines.append(f"\n**Best: {best['name']} — macro-F1={best['macro_f1']:.4f}, "
                     f"balanced-acc={best['balanced_accuracy']:.4f}, acc={best['accuracy']:.4f}**")
    out_lines.append(f"Artifact: `{os.path.relpath(art_path, TAD_ROOT)}`")

    report = os.path.join(DATA_DIR, f"train_results_{args.taxonomy}_{args.split}.md")
    os.makedirs(DATA_DIR, exist_ok=True)          # report dir may not exist in a fresh checkout
    with open(report, "w") as f:
        f.write("\n".join(out_lines))
    print(f"Saved report -> {report}")


if __name__ == "__main__":
    main()
