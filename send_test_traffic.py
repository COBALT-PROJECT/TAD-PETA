#!/usr/bin/env python3
"""Replay real capture packets into the TAD endpoint (batched, in capture order).

    python3 send_test_traffic.py                     # 1000-packet sample
    python3 send_test_traffic.py --all               # full 86,845-packet capture
    python3 send_test_traffic.py --url http://10.163.1.126:8002/ingest/raw
"""
import argparse, collections, json, os, time, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
POST = ["ssh_connection", "reconnaissance_commands", "reverse_shell_wait", "interactive_shell"]

ap = argparse.ArgumentParser()
ap.add_argument("--url", default="http://127.0.0.1:8002/ingest/raw")
ap.add_argument("--csv", default=None)
ap.add_argument("--all", action="store_true", help="use the full capture")
ap.add_argument("--batch", type=int, default=500, help="rows per request (max 10000)")
a = ap.parse_args()

import pandas as pd
csv = a.csv or os.path.join(HERE, "TAD", "data",
                            "labeled_packets_deep.csv" if a.all else "sample_traffic.csv")
df = pd.read_csv(csv).sort_values("packet_time_utc")          # capture order matters
truth = df["label"].apply(lambda l: "post_exploitation" if l in POST else l).value_counts()
print(f"{len(df)} packets from {os.path.basename(csv)}")
print("  ground truth:", dict(truth))

rows = json.loads(df.drop(columns=["label"], errors="ignore").to_json(orient="records"))
tot = collections.Counter(); n = disp = 0
t0 = time.time()
for i in range(0, len(rows), a.batch):
    chunk = rows[i:i + a.batch]
    req = urllib.request.Request(a.url, data=json.dumps({"rows": chunk}).encode(),
                                 headers={"Content-Type": "application/json"})
    r = json.load(urllib.request.urlopen(req))
    n += r["count"]; disp += r["dispatched"]
    tot.update(p["label"] for p in r["predictions"])
    print(f"  batch {i//a.batch+1}: {r['count']:>5} pkts  attacks={r['attacks']:>5} "
          f"dispatched={r['dispatched']:>5}")
dt = time.time() - t0
print(f"\n{n} packets in {dt:.1f}s ({n/dt:,.0f} pkt/s) | dispatched={disp}")
print("predictions:", dict(tot))
