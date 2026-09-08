#!/usr/bin/env python3
"""
Hypervisor packet-metadata forwarder + TRAINING-DATA COLLECTOR.

Same as the original WP5Sniffer, but with two collection additions (see
`### COLLECTION` markers):

  * SAVE_CSV  -> also write every captured row to a local CSV, in the exact
                dataset schema, so a run can be turned into labelled training
                data (pair it with metrics.txt via label_capture.py).
  * FORWARD   -> set to "0" to collect ONLY (no POST). Lets you capture without
                TAD/PETA running.

Rows are saved from the consumer thread, BEFORE the POST attempt, so the
capture is complete even if the ingest API is down or slow.

Emitted rows use the exact dataset field names:
  packet_time_utc, src_ip, src_port, dst_ip, dst_port,
  protocol, tcp_flags, packet_length, ip_ttl
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP
import csv                                          ### COLLECTION
import os
import sys
import time
import json
import queue
import random
import threading
from datetime import datetime, timezone

import requests

# ==========================================
# CONFIGURATION
# ==========================================
INTERFACE = "ens19"

# --- Ingest endpoint (POST JSON here instead of saving locally) ---
INGEST_URL = "http://10.163.1.126:8002/ingest/raw"

### COLLECTION -------------------------------------------------------------
# Save every captured row to this CSV (empty = don't save). Overridable by env.
#   SAVE_CSV=raw_capture.csv sudo -E python3 WP5Sniffer.py
SAVE_CSV = os.environ.get("SAVE_CSV", "")
# Forward to the ingest API too? "0" = collect only (no POST, TAD not needed).
FORWARD  = os.environ.get("FORWARD", "1") != "0"
# CSV header = dataset schema, in order.
CSV_FIELDS = ["packet_time_utc", "src_ip", "src_port", "dst_ip", "dst_port",
              "protocol", "tcp_flags", "packet_length", "ip_ttl"]
### -----------------------------------------------------------------------

# --- Buffer / batching / rate-limit knobs (DoS protection) ---
BATCH_SIZE        = 1000     # max rows per POST request
FLUSH_INTERVAL    = 1.0      # seconds: force a flush even if the batch is not full
MIN_POST_INTERVAL = 0.20     # seconds: minimum gap between POSTs  -> <= 5 req/s cap
MAX_QUEUE         = 100_000  # max buffered rows before we drop (memory backpressure)
HTTP_TIMEOUT      = (5, 10)  # (connect, read) seconds
MAX_RETRIES       = 5        # per-batch retry attempts on transient failure
BACKOFF_BASE      = 0.5      # seconds: exponential backoff base
BACKOFF_CAP       = 30.0     # seconds: max backoff between retries

# Numeric IP protocols we do not decode into a named layer above.
_PROTO_NAMES = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmpv6"}

# Updated with all IPs from the mapping spreadsheet
TARGET_HOSTS = [
    "10.163.1.103",  # VM 1160 (Data-Lake)
    "10.163.1.118",  # VM 1158 (ai-target-of-evaluation)
    "10.163.1.120",  # VM 1155 (iam)
#   "10.163.1.121",  # VM 1124 (Worker3)
    "10.163.1.122",  # VM 1089 (sdtm)
    "10.163.1.123",  # cobalt
    "10.163.1.125",  # VM 1084 (watchtower)
    "10.163.1.126",  # VM 1082 (sdt / TAD-PETA) — dummy target for collection (collect-only!)
    "10.163.1.127",  # VM 1077 (Clouditor / orchestrator)
#   "10.163.1.128",  # VM 1049 (Worker2)
#   "10.163.1.129",  # VM 1033 (Worker1)
#    "10.163.1.130",  # VM 1031 (MasterK3s)
    "10.163.1.160",  # VM 1257 / 1050 (CCM-Manager)
    "10.163.1.170",  # sqlserver
    "10.163.1.176",  # VM 1191 (mysql)
    "10.163.1.204",  # VM 1219 (ccmui - retained from original script)
    "10.163.1.211",  # VM 1087 (cobalt-dlt)
    "10.163.1.249",  # VM 1232 (ral-cp-drm)
]


# ==========================================
# PACKET -> ROW
# ==========================================
def packet_to_row(packet):
    """Extract dataset-shaped metadata from a packet. Returns dict or None."""
    if not packet.haslayer(IP):
        return None
    ip = packet[IP]

    src_port = None
    dst_port = None
    tcp_flags = None

    if packet.haslayer(TCP):
        tcp = packet[TCP]
        protocol = "tcp"
        src_port = int(tcp.sport)
        dst_port = int(tcp.dport)
        tcp_flags = str(tcp.flags)          # e.g. "S", "SA", "PA", "FA"
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        protocol = "udp"
        src_port = int(udp.sport)
        dst_port = int(udp.dport)
    elif packet.haslayer(ICMP):
        protocol = "icmp"
    else:
        protocol = _PROTO_NAMES.get(int(ip.proto), str(int(ip.proto)))

    # Naive-UTC ISO-8601 with microseconds, matching the dataset sample
    # (e.g. "2026-06-15T18:36:46.495822").
    packet_time_utc = (
        datetime.fromtimestamp(float(packet.time), tz=timezone.utc)
        .replace(tzinfo=None)
        .isoformat()
    )

    return {
        "packet_time_utc": packet_time_utc,
        "src_ip": ip.src,
        "src_port": src_port,
        "dst_ip": ip.dst,
        "dst_port": dst_port,
        "protocol": protocol,
        "tcp_flags": tcp_flags,
        "packet_length": len(packet),
        "ip_ttl": int(ip.ttl),
    }


# ==========================================
# BUFFERED, RATE-LIMITED SENDER
# ==========================================
class BufferedSender(threading.Thread):
    """Consumer thread: drains a bounded queue, batches rows, POSTs JSON,
    and (optionally) appends every row to a CSV for later labelling."""

    POLL = 0.5  # seconds: queue poll interval (keeps shutdown responsive)

    def __init__(self, url):
        super().__init__(daemon=True, name="ingest-sender")
        self.url = url
        self.q = queue.Queue(maxsize=MAX_QUEUE)
        self.stop_event = threading.Event()
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})
        # Stats
        self.sent = 0
        self.failed = 0
        self.dropped = 0
        self.saved = 0                              ### COLLECTION
        self._last_post = 0.0

        ### COLLECTION: open the CSV sink once (append; write header if new).
        self._csv_file = None
        self._csv = None
        if SAVE_CSV:
            new = not os.path.exists(SAVE_CSV) or os.path.getsize(SAVE_CSV) == 0
            self._csv_file = open(SAVE_CSV, "a", newline="")
            self._csv = csv.DictWriter(self._csv_file, fieldnames=CSV_FIELDS)
            if new:
                self._csv.writeheader()
                self._csv_file.flush()

    # ---- producer side (called from the sniff callback) ----
    def submit(self, row):
        """Non-blocking enqueue. Drops (and counts) if the buffer is full."""
        try:
            self.q.put_nowait(row)
        except queue.Full:
            self.dropped += 1

    ### COLLECTION: persist a batch to CSV before anything can fail.
    def _save(self, batch):
        if not self._csv:
            return
        self._csv.writerows(batch)
        self._csv_file.flush()
        self.saved += len(batch)

    # ---- consumer side ----
    def run(self):
        batch = []
        last_flush = time.monotonic()
        while True:
            try:
                batch.append(self.q.get(timeout=self.POLL))
                # Fast-fill the rest of the batch without extra waits.
                while len(batch) < BATCH_SIZE:
                    batch.append(self.q.get_nowait())
            except queue.Empty:
                pass

            now = time.monotonic()
            flush_due = (
                len(batch) >= BATCH_SIZE
                or (batch and now - last_flush >= FLUSH_INTERVAL)
                or (batch and self.stop_event.is_set())
            )
            if flush_due:
                self._flush(batch)
                batch = []
                last_flush = time.monotonic()

            if self.stop_event.is_set() and self.q.empty() and not batch:
                break

        self.session.close()
        if self._csv_file:                          ### COLLECTION
            self._csv_file.close()

    def _retry_delay(self, attempt, resp=None):
        """Honor Retry-After if present, else exponential backoff w/ full jitter."""
        if resp is not None:
            ra = resp.headers.get("Retry-After")
            if ra:
                try:
                    return min(float(ra), BACKOFF_CAP)
                except ValueError:
                    pass
        ceiling = min(BACKOFF_CAP, BACKOFF_BASE * (2 ** (attempt - 1)))
        return random.uniform(0, ceiling)

    def _flush(self, batch):
        self._save(batch)                           ### COLLECTION: save first

        if not FORWARD:                             ### COLLECTION: collect-only
            print(f"[SAVE] {len(batch):>4} rows -> {SAVE_CSV}  "
                  f"(saved={self.saved}, dropped={self.dropped}, qsize={self.q.qsize()})")
            return

        # Rate limit: enforce minimum spacing between POSTs.
        gap = MIN_POST_INTERVAL - (time.monotonic() - self._last_post)
        if gap > 0:
            time.sleep(gap)

        payload = json.dumps({"rows": batch})

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                resp = self.session.post(
                    self.url, data=payload, timeout=HTTP_TIMEOUT
                )
                self._last_post = time.monotonic()

                if resp.status_code < 400:
                    self.sent += len(batch)
                    print(f"[SENT] {len(batch):>4} rows -> {resp.status_code}  "
                          f"(sent={self.sent}, saved={self.saved}, "
                          f"dropped={self.dropped}, qsize={self.q.qsize()})")
                    return

                if resp.status_code == 429 or resp.status_code >= 500:
                    delay = self._retry_delay(attempt, resp)
                    print(f"[WARN] ingest {resp.status_code}; retry "
                          f"{attempt}/{MAX_RETRIES} in {delay:.1f}s")
                    time.sleep(delay)
                    continue

                # Other 4xx: client error, retrying won't help.
                print(f"[ERROR] ingest {resp.status_code}; dropping {len(batch)} rows")
                self.failed += len(batch)
                return

            except requests.RequestException as exc:
                delay = self._retry_delay(attempt)
                print(f"[WARN] POST failed ({exc}); retry "
                      f"{attempt}/{MAX_RETRIES} in {delay:.1f}s")
                time.sleep(delay)

        self.failed += len(batch)
        print(f"[ERROR] gave up on {len(batch)} rows after {MAX_RETRIES} retries")


# ==========================================
# MAIN
# ==========================================
def main():
    if os.getuid() != 0:
        print("!!! Error: This script must be run as root (sudo) !!!")
        sys.exit(1)

    sender = BufferedSender(INGEST_URL)
    sender.start()

    def process_packet(packet):
        row = packet_to_row(packet)
        if row is not None:
            sender.submit(row)

    bpf_filter = " or ".join(f"host {ip}" for ip in TARGET_HOSTS)
    full_filter = f"({bpf_filter}) and not arp"

    print(f"[*] Sniffer started on {INTERFACE}")
    if FORWARD:
        print(f"[*] Forwarding metadata to: {INGEST_URL}")
    else:
        print("[*] FORWARD=0 -> collect-only, not POSTing")
    if SAVE_CSV:                                    ### COLLECTION
        print(f"[*] Saving rows to CSV: {SAVE_CSV}")
    print(f"[*] batch<= {BATCH_SIZE}, flush every {FLUSH_INTERVAL}s, "
          f"min POST gap {MIN_POST_INTERVAL}s, queue cap {MAX_QUEUE}")
    print("[*] Press Ctrl+C to stop...\n")

    try:
        sniff(iface=INTERFACE, filter=full_filter, prn=process_packet, store=False)
    except KeyboardInterrupt:
        pass
    finally:
        print("\n[*] Stopping; flushing buffer...")
        sender.stop_event.set()
        sender.join(timeout=FLUSH_INTERVAL + HTTP_TIMEOUT[1] * MAX_RETRIES + 5)
        print(f"[*] Done. sent={sender.sent}, saved={sender.saved}, "
              f"failed={sender.failed}, dropped={sender.dropped}")


if __name__ == "__main__":
    main()
