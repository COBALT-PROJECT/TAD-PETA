#!/usr/bin/env python3
"""
Reverse-shell TRAFFIC SIMULATOR — for defensive IDS training-data collection.

Generates the network *pattern* of a reverse shell so you can capture
`post_exploitation` traffic against ANY target (not just a prepared host):

  * the victim dials OUT to the attacker's listener (kali:4444),
  * then an interactive command/response exchange follows.

It is NOT a backdoor: it NEVER executes a received command. It replies with
canned, fixed fake output of varying sizes (to mimic recon output like
whoami / id / ps). Purpose is purely to produce the traffic shape for training
a detector. Run it on each target alongside dummy_service.py.

    ATTACKER=10.163.1.105 PORT=4444 python3 revshell_sim.py

It loops (a "beacon"): when the attacker's listener is up (during the attack's
reverse-shell phase) it connects and generates traffic; otherwise the connection
is refused, exactly like a cron-triggered payload retrying.
"""
import os
import random
import socket
import time

ATTACKER  = os.environ.get("ATTACKER", "10.163.1.105")
PORT      = int(os.environ.get("PORT", "4444"))
RECONNECT = float(os.environ.get("RECONNECT", "15"))   # seconds between beacons
PROMPT    = b"root@victim:~# "

# Canned fake outputs — NO command is executed. Sizes vary like real recon
# output so the packet-size distribution resembles a genuine shell session.
FAKE_OUTPUTS = [
    b"root\n",
    b"/root\n",
    b"uid=0(root) gid=0(root) groups=0(root)\n",
    b"Linux victim 6.8.0-137-generic #137 SMP x86_64 GNU/Linux\n",
    b"eth0  inet 10.0.0.5/24  ether 02:42:0a:00:00:05\n" * 3,
    b"USER  PID  %CPU  %MEM  COMMAND\n" + b"root  1  0.0  0.3  /sbin/init\n" * 10,
]


def run_session(sock):
    """Behave like an interactive shell at the NETWORK level only."""
    sock.sendall(PROMPT)                       # shells print a prompt on connect
    while True:
        cmd = sock.recv(4096)                  # a "command" from the attacker
        if not cmd:
            break                              # attacker closed the session
        # think-time, then reply with FAKE output (never executed) + prompt
        time.sleep(random.uniform(0.05, 0.4))
        sock.sendall(random.choice(FAKE_OUTPUTS) + PROMPT)


def main():
    print(f"[revshell-sim] beaconing to {ATTACKER}:{PORT} every {RECONNECT}s "
          f"— TRAFFIC SIMULATOR, no command execution")
    while True:
        try:
            with socket.create_connection((ATTACKER, PORT), timeout=5) as s:
                print("[revshell-sim] connected -> generating reverse-shell traffic")
                run_session(s)
                print("[revshell-sim] session ended")
        except (ConnectionRefusedError, OSError):
            pass                               # listener down -> refused (beacon)
        time.sleep(RECONNECT)


if __name__ == "__main__":
    main()
