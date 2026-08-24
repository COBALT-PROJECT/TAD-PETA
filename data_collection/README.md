# Collecting labelled training data

Turn a live attack run into a labelled CSV you can retrain the TAD model on.
This closes the **distribution shift** seen on live traffic (the model was
~99.99% on its training capture but only ~0.77 median confidence live, with
false positives on normal outbound traffic).

```
 kali:    cronAttack2.py  ──runs timed attack phases──►  metrics.txt (phase windows)
 sniffer: WP5Sniffer.py   ──captures every packet────►  raw_capture.csv
                                     │
                          label_capture.py (this dir)
                                     │
                            labelled.csv  ──►  retrain
```

## 0. One-time fix on kali: make `metrics.txt` UTC

`cronAttack2.py`'s `record_phase()` writes **local** time; the sniffer writes
**UTC**. Align them so labels match. Replace the two `.isoformat()` lines:

```python
# BEFORE
start_str = datetime.fromtimestamp(start_time).isoformat()
end_str   = datetime.fromtimestamp(end_time).isoformat()

# AFTER  (add `timezone` to the datetime import)
from datetime import datetime, timezone
start_str = datetime.fromtimestamp(start_time, timezone.utc).replace(tzinfo=None).isoformat()
end_str   = datetime.fromtimestamp(end_time,   timezone.utc).replace(tzinfo=None).isoformat()
```

If you can't change it, skip this and pass `--tz-offset-hours <your UTC offset>`
to `label_capture.py` instead (e.g. `3` if kali local time is UTC+3).

> Not committing `cronAttack2.py` here on purpose — it contains a plaintext SSH
> password. Keep it on kali; back it up before editing (`cp cronAttack2.py cronAttack2.py.bak`).

## 1. On the sniffer VM: capture + save

Use the collection build of the sniffer ([WP5Sniffer.py](WP5Sniffer.py)). It adds
two env knobs to the original: `SAVE_CSV` (write a local CSV) and `FORWARD`
(set `0` to collect without TAD running).

```bash
# collect ONLY (TAD does not need to be up):
SAVE_CSV=raw_capture.csv FORWARD=0 sudo -E python3 WP5Sniffer.py

# or collect AND forward to a live TAD at the same time:
SAVE_CSV=raw_capture.csv sudo -E python3 WP5Sniffer.py
```

`sudo -E` preserves the env vars. Rows are written before each POST attempt, so
the capture is complete even if TAD is down. Ctrl-C to stop; it prints
`saved=<n>`.

## 2. On kali: run the attack

```bash
python3 cronAttack2.py     # writes metrics.txt; type `exit` at the shell prompt to continue
```

Start the sniffer (step 1) **before** the attack and stop it **after** — you want
the benign lead-in/out too.

## 3. Label

Copy `raw_capture.csv` + `metrics.txt` to this folder, then:

```bash
python3 label_capture.py --raw raw_capture.csv --metrics metrics.txt --out labelled.csv
# if you skipped step 0:  add  --tz-offset-hours <your offset>
```

Defaults: attacker `10.163.1.105` (cronAttack2's kali). Override with
`--attacker <ip>` (repeatable). A packet is labelled attack only if it's in a
phase window **and** the attacker is in the flow — everything else stays benign,
so background traffic during an attack is correctly benign (this is what stops
the model false-alarming on normal traffic).

Sanity-check the printed distribution. If it's all benign, it's almost always a
timezone mismatch (step 0) or a wrong `--attacker` IP.

## 4. Retrain (one command)

Collect several runs (vary timing, background load, intensity), then:

```bash
python3 retrain.py labelled_run1.csv labelled_run2.csv ...
```

[retrain.py](retrain.py) merges your labelled CSV(s) with the existing training
set, **backs up the current model** (retraining overwrites
`hgb_newdataset_5class.joblib`), and runs the project trainer to produce a new
drop-in artifact. Then restart the stack (`./run_all.sh`) to load it.

- `--no-base` — train on the new data only (heavier weight on live traffic, but
  risks forgetting the old distribution)
- `--dry-run` — merge + show the label mix without training
- roll back — the script prints the backup path; `cp backup-*/*.joblib` over the
  model dir

Keep the taxonomy the model expects: `benign`, `nmap_scan`, `hydra_bruteforce`,
`post_exploitation`, `stress_test`. The phase→label mapping lives at the top of
[label_capture.py](label_capture.py) (`PHASE_LABELS`).
