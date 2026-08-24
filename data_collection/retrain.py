#!/usr/bin/env python3
"""
One-command retrain from collected labelled data.

Merges your labelled capture(s) with the existing training set, BACKS UP the
current model(s), then runs the project's real trainer
(TAD/scripts/train_newdataset_model.py) to produce a new, drop-in
hgb_newdataset_5class.joblib.

    python3 retrain.py labelled_run1.csv labelled_run2.csv
    python3 retrain.py labelled.csv --no-base        # new data only
    python3 retrain.py labelled.csv --taxonomy 5class --split group

Why merge with the base set by default: training on the new data alone makes the
model forget the old distribution. Keeping both retains what it knew and adds the
new live traffic. If your new data is tiny next to the 86k base, it barely shifts
the model — collect more, or use --no-base to weight the new data heavily.
"""
import argparse
import os
import shutil
import subprocess
import sys
from datetime import datetime

import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
TAD_ROOT = os.path.join(HERE, "..", "TAD")
SCRIPTS = os.path.join(TAD_ROOT, "scripts")
MODELS_DIR = os.path.join(TAD_ROOT, "models", "multiclass")
BASE_CSV = os.path.join(TAD_ROOT, "data", "labeled_packets_deep.csv")
TRAINER = os.path.join(SCRIPTS, "train_newdataset_model.py")

REQUIRED = ["packet_time_utc", "src_ip", "src_port", "dst_ip", "dst_port",
            "protocol", "tcp_flags", "packet_length", "ip_ttl", "label"]


def load_checked(path):
    df = pd.read_csv(path)
    missing = [c for c in REQUIRED if c not in df.columns]
    if missing:
        sys.exit(f"ERROR: {path} is missing columns: {missing}")
    return df[REQUIRED]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("labelled", nargs="+", help="labelled CSV(s) from label_capture.py")
    ap.add_argument("--no-base", action="store_true",
                    help="do NOT merge the existing training set (new data only)")
    ap.add_argument("--base", default=BASE_CSV, help="base training CSV to merge")
    ap.add_argument("--taxonomy", default="5class", choices=["8class", "5class", "binary"])
    ap.add_argument("--split", default="group", choices=["stratified", "group"])
    ap.add_argument("--smote", action="store_true",
                    help="oversample rare classes with SMOTE instead of class_weight")
    ap.add_argument("--out", default=os.path.join(HERE, "combined_dataset.csv"),
                    help="where to write the merged training CSV")
    ap.add_argument("--dry-run", action="store_true", help="merge + report only, don't train")
    a = ap.parse_args()

    # 1. Merge
    frames = []
    if not a.no_base:
        print(f"[merge] base: {a.base}")
        frames.append(load_checked(a.base))
    for p in a.labelled:
        print(f"[merge] new : {p}")
        frames.append(load_checked(p))
    combined = pd.concat(frames, ignore_index=True)
    combined.to_csv(a.out, index=False)
    print(f"[merge] -> {a.out}  ({len(combined):,} rows)")
    print("[merge] label mix:")
    for lab, n in combined["label"].value_counts().items():
        print(f"          {lab:<24} {n:>8}  ({100*n/len(combined):.1f}%)")
    # crude balance warning: is the NEW data a rounding error vs base?
    if not a.no_base:
        new_rows = sum(len(load_checked(p)) for p in a.labelled)
        frac = 100 * new_rows / len(combined)
        print(f"[merge] new data is {frac:.1f}% of the training set"
              + ("  (small — collect more or use --no-base)" if frac < 10 else ""))

    if a.dry_run:
        print("[dry-run] stopping before training.")
        return

    # 2. Back up current models (retraining overwrites hgb_newdataset_<tax>.joblib)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = os.path.join(MODELS_DIR, f"backup-{stamp}")
    os.makedirs(backup, exist_ok=True)
    saved = 0
    for f in os.listdir(MODELS_DIR):
        if f.endswith(".joblib"):
            shutil.copy2(os.path.join(MODELS_DIR, f), os.path.join(backup, f))
            saved += 1
    print(f"[backup] {saved} model(s) -> {backup}")

    # 3. Train via the project's real trainer (produces a drop-in artifact)
    existing_pp = os.environ.get("PYTHONPATH", "")
    env = dict(os.environ,
               PYTHONPATH=os.pathsep.join([SCRIPTS, existing_pp]) if existing_pp else SCRIPTS)
    cmd = [sys.executable, TRAINER, "--csv", a.out,
           "--taxonomy", a.taxonomy, "--split", a.split, "--model", "both"]
    if a.smote:
        cmd.append("--smote")
    print(f"[train] {' '.join(cmd)}\n")
    rc = subprocess.call(cmd, env=env)
    if rc != 0:
        sys.exit(f"ERROR: trainer exited {rc}. Your old model is safe in {backup}.")

    print(f"\n[done] new model written to {MODELS_DIR}")
    print(f"       backup of previous model: {backup}")
    print(f"       to roll back: cp {backup}/*.joblib {MODELS_DIR}/")
    print("       restart the stack (./run_all.sh) to load the new model.")


if __name__ == "__main__":
    main()
