#!/usr/bin/env python3
"""
Turn a raw sniffer capture + cronAttack2's metrics.txt into a LABELLED
training CSV, in the same schema/taxonomy the TAD model uses.

    python3 label_capture.py --raw raw_capture.csv --metrics metrics.txt \
                             --out labelled.csv

How a packet gets its label:
  1. its packet_time_utc must fall inside an attack phase's [start, end) window
  2. AND the attacker must be a participant (src or dst == an --attacker IP)
Everything else -> benign.

Rule 2 is what keeps background traffic that merely *coincides* with an attack
window labelled benign. Without it, normal traffic during a scan window would be
mislabelled as attack and the model learns to false-alarm on it — the exact
distribution-shift / false-positive problem this collection is meant to fix.

Timezone: the sniffer writes packet_time_utc in UTC. cronAttack2's ORIGINAL
record_phase() writes LOCAL time -> pass --tz-offset-hours <your UTC offset>.
After you apply the UTC fix in data_collection/README.md, use 0 (the default).
"""
import argparse
import collections
import csv
from datetime import datetime, timedelta

# metrics.txt phase name  ->  model taxonomy label. Unmapped phases -> benign.
PHASE_LABELS = {
    "nmap_scan":               "nmap_scan",
    "hydra_bruteforce":        "hydra_bruteforce",
    "ssh_connection":          "post_exploitation",
    "reverse_shell_setup":     "post_exploitation",
    "reverse_shell_wait":      "post_exploitation",
    "reconnaissance_commands": "post_exploitation",
    "interactive_shell":       "post_exploitation",
    "stress_test":             "stress_test",
}


def parse_iso(s):
    return datetime.fromisoformat(s.strip())


def load_windows(metrics_path, tz_offset_hours):
    """metrics.txt -> [(start_utc, end_utc, label)], skipping zero/benign phases."""
    shift = timedelta(hours=tz_offset_hours)
    windows = []
    with open(metrics_path) as f:
        for row in csv.DictReader(f):        # header: phase,start_time,end_time,duration_seconds
            phase = row["phase"]
            label = PHASE_LABELS.get(phase)
            if label is None:
                print(f"  [skip] phase '{phase}' not in PHASE_LABELS -> benign window")
                continue
            start = parse_iso(row["start_time"]) - shift   # -> UTC
            end   = parse_iso(row["end_time"])   - shift
            if end <= start:
                continue
            windows.append((start, end, label))
    windows.sort()
    return windows


def label_for(t, src, dst, sport, dport, windows, attackers, use_attacker_filter,
              benign_ports):
    for start, end, label in windows:
        if start <= t < end:
            if use_attacker_filter and not (src in attackers or dst in attackers):
                return "benign"        # in-window but not attacker traffic -> benign
            # De-contaminate: the benign traffic generator runs on the attacker
            # host and hammers these HTTP ports. Inside a NON-stress window that
            # traffic is the generator (benign), NOT the attack — stress is the
            # only legitimate attack on those ports. Reclassify it to benign.
            if (label != "stress_test" and benign_ports
                    and (sport in benign_ports or dport in benign_ports)):
                return "benign"
            return label
    return "benign"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", required=True, help="raw capture CSV from WP5Sniffer (SAVE_CSV)")
    ap.add_argument("--metrics", required=True, help="metrics.txt from cronAttack2")
    ap.add_argument("--out", required=True, help="output labelled CSV")
    ap.add_argument("--attacker", action="append", default=["10.163.1.105"],
                    help="attacker IP (repeatable); default cronAttack2's 10.163.1.105")
    ap.add_argument("--tz-offset-hours", type=float, default=0.0,
                    help="hours to subtract from metrics.txt times to reach UTC "
                         "(0 after applying the record_phase UTC fix)")
    ap.add_argument("--no-attacker-filter", action="store_true",
                    help="label purely by time window (don't require attacker in flow)")
    ap.add_argument("--benign-ports", default="8080,8090",
                    help="HTTP ports the benign generator uses; attacker traffic to "
                         "these OUTSIDE a stress window is re-labelled benign "
                         "(fixes generator-on-attacker contamination). '' to disable.")
    a = ap.parse_args()

    attackers = set(a.attacker)
    benign_ports = {int(p) for p in a.benign_ports.split(",") if p.strip().isdigit()}
    windows = load_windows(a.metrics, a.tz_offset_hours)
    print(f"loaded {len(windows)} attack windows; attacker(s)={sorted(attackers)} "
          f"filter={'off' if a.no_attacker_filter else 'on'}")
    for s, e, lab in windows:
        print(f"  {lab:<18} {s.isoformat()} -> {e.isoformat()}  ({(e-s).total_seconds():.0f}s)")

    counts = collections.Counter()
    in_window_other = 0        # packets inside a window but not attacker traffic
    with open(a.raw) as fin, open(a.out, "w", newline="") as fout:
        reader = csv.DictReader(fin)
        fields = reader.fieldnames + (["label"] if "label" not in reader.fieldnames else [])
        writer = csv.DictWriter(fout, fieldnames=fields)
        writer.writeheader()
        for row in reader:
            try:
                t = parse_iso(row["packet_time_utc"])
            except (KeyError, ValueError):
                row["label"] = "benign"; writer.writerow(row); counts["benign"] += 1; continue
            def _port(v):
                try: return int(v)
                except (TypeError, ValueError): return -1
            lab = label_for(t, row.get("src_ip"), row.get("dst_ip"),
                            _port(row.get("src_port")), _port(row.get("dst_port")),
                            windows, attackers, not a.no_attacker_filter, benign_ports)
            # diagnostic: was this packet inside a window but reclassified benign?
            if lab == "benign" and not a.no_attacker_filter:
                for s, e, _ in windows:
                    if s <= t < e:
                        in_window_other += 1
                        break
            row["label"] = lab
            writer.writerow(row)
            counts[lab] += 1

    total = sum(counts.values())
    print(f"\nwrote {total} labelled packets -> {a.out}")
    for lab, n in counts.most_common():
        print(f"  {lab:<18} {n:>8}  ({100*n/total:.1f}%)")
    if in_window_other:
        print(f"\n  note: {in_window_other} packets fell in an attack window but were "
              f"NOT attacker traffic -> kept benign (background). "
              f"Use --no-attacker-filter to disable that.")
    if counts["benign"] == total:
        print("\n  WARNING: everything is benign. Likely a timezone mismatch — try "
              "--tz-offset-hours, or check the --attacker IP.")


if __name__ == "__main__":
    main()
