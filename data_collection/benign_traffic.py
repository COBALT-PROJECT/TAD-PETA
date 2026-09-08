#!/usr/bin/env python3
"""
Generate NORMAL (benign) traffic to the testbed hosts while the sniffer runs.

Run this during a capture (before/around/after the attack) so the dataset has
realistic benign traffic — the thing that stops the model false-alarming on
normal activity. Stdlib only; runs anywhere.

    python3 benign_traffic.py                 # run until Ctrl-C
    python3 benign_traffic.py --duration 300  # run 5 minutes then stop
    python3 benign_traffic.py --rate 5        # ~5 actions/sec (default ~1.5)

Only hits hosts the sniffer can see — edit HOSTS / WEB below to match.
Keep the rate MODERATE: a flood would look like a DoS, not benign.

*** RUN THIS ON A HOST THAT IS NOT THE ATTACKER (not 10.163.1.105). ***
The labeler flags any in-window packet where the attacker IP is involved as the
attack. Benign traffic sent FROM the attacker host therefore gets mislabeled as
the attack (this wrecked post_exploitation precision once). This script refuses
to run on the attacker host unless you pass --force.
"""
import argparse
import random
import socket
import subprocess
import time
import urllib.request

# The attacker host — benign traffic must NOT originate here (see docstring).
ATTACKER_IP = "10.163.1.105"

# Hosts the sniffer captures (edit to match what `tcpdump -i ens19` shows).
HOSTS = ["10.163.1.126", "10.163.1.204", "10.163.1.249",
         "10.163.1.120", "10.163.1.118", "10.163.1.123"]

# Web endpoints to GET (normal HTTP requests). Root path is fine; 404s still
# generate benign request/response traffic.
# 10.163.1.126:8090 = dummy_service.py (always up). Add others only if live.
WEB = [
    "http://10.163.1.126:8090",
    "http://10.163.1.126:8090/status",
    "http://10.163.1.204:8080",
    "http://10.163.1.249:8080",
]


def http_get(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 normal-user"})
        with urllib.request.urlopen(req, timeout=3) as r:
            r.read(2048)                       # pull a little body
        return f"GET {url}"
    except Exception as e:
        # a refused/404/timeout still sent real packets -> still benign traffic
        return f"GET {url} ({type(e).__name__})"


def ping(host):
    subprocess.run(["ping", "-c", "1", "-W", "1", host],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return f"ping {host}"


def _local_ips():
    """Best-effort set of this host's IPv4 addresses."""
    try:
        out = subprocess.run(["hostname", "-I"], capture_output=True,
                             text=True, timeout=3).stdout
        return set(out.split())
    except Exception:
        try:
            return {socket.gethostbyname(socket.gethostname())}
        except Exception:
            return set()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--duration", type=float, default=0,
                    help="seconds to run (0 = until Ctrl-C)")
    ap.add_argument("--rate", type=float, default=1.5,
                    help="approx actions per second (keep it moderate!)")
    ap.add_argument("--force", action="store_true",
                    help="run even on the attacker host (will contaminate labels)")
    a = ap.parse_args()

    if ATTACKER_IP in _local_ips() and not a.force:
        print("=" * 70)
        print(f"REFUSING TO RUN: this host has the attacker IP {ATTACKER_IP}.")
        print("Benign traffic from the attacker host gets swept into attack")
        print("windows and mislabeled as the attack (it wrecked post_exploitation")
        print("precision before). Run this on a DIFFERENT host, or pass --force")
        print("if you really mean to (and rely on label_capture's --benign-ports).")
        print("=" * 70)
        raise SystemExit(1)

    gap = 1.0 / max(a.rate, 0.1)
    end = time.time() + a.duration if a.duration else None
    n = 0
    print(f"[benign] generating normal traffic to {HOSTS} at ~{a.rate}/s "
          f"({'until Ctrl-C' if not end else f'{a.duration:.0f}s'})")
    try:
        while end is None or time.time() < end:
            # mostly web, some pings — like a real user/service mix
            if random.random() < 0.7:
                msg = http_get(random.choice(WEB))
            else:
                msg = ping(random.choice(HOSTS))
            n += 1
            if n % 20 == 0:
                print(f"[benign] {n} actions... last: {msg}")
            time.sleep(gap * random.uniform(0.5, 1.5))   # natural jitter
    except KeyboardInterrupt:
        pass
    print(f"[benign] done. {n} actions generated.")


if __name__ == "__main__":
    main()
