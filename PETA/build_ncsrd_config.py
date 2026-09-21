"""
build_ncsrd_config.py
=====================
Generates the NCSRD testbed PETA config from one source of truth:

    PETA/ncsrd_topology_peta.json   — the 18 target VMs
    PETA/attack_mapping.json        — mitigations per attack x asset context

Run after editing TARGET_HOSTS:

    python3 PETA/build_ncsrd_config.py

INVARIANT (validated at the end): scoring_engine.evaluate_node() does
    attack_mapping[attack]["contexts"][node["type"]]
and returns [] for an unknown type -> that node would silently get NO mitigation.
So every context used by a node MUST exist under EVERY attack type. The script
fails loudly if that is ever violated.

All mitigation actions are real Ubuntu commands (ufw / nftables / fail2ban /
systemd / sshd / sysctl / auditd) because every target VM is Ubuntu.
"""

import itertools
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

# ── the NCSRD testbed ────────────────────────────────────────────────────────
# (ip, id, name, context/type, criticality, role, open_ports)
TARGET_HOSTS = [
    ("10.163.1.103", "ncsrd-datalake",   "Data-Lake",               "Database", 9,  "VM 1160 — data lake store",        [5432, 9000, 22]),
    ("10.163.1.118", "ncsrd-toe",        "ai-target-of-evaluation", "Frontend", 7,  "VM 1158 — AI target of evaluation",[80, 443, 8080, 22]),
    ("10.163.1.137", "ncsrd-toe-quantum","quantum-target-of-evaluation","Frontend",7,"Quantum target of evaluation",     [80, 443, 8080, 22]),
    ("10.163.1.120", "ncsrd-iam",        "iam",                     "Identity", 10, "VM 1155 — identity & access mgmt", [389, 636, 8443, 22]),
    ("10.163.1.121", "ncsrd-worker3",    "Worker3",                 "Compute",  6,  "VM 1124 — K3s worker 3",           [10250, 30000, 22]),
    ("10.163.1.122", "ncsrd-sdtm",       "sdtm",                    "Security", 8,  "VM 1089 — SDT manager",            [8001, 22]),
    ("10.163.1.123", "ncsrd-cobalt",     "cobalt",                  "Frontend", 7,  "cobalt application node",          [80, 443, 22]),
    ("10.163.1.125", "ncsrd-watchtower", "watchtower",              "Security", 8,  "VM 1084 — monitoring / watchtower",[3000, 9090, 22]),
    ("10.163.1.126", "ncsrd-sdt-tad",    "sdt / TAD-PETA",          "Security", 9,  "VM 1082 — SDT + TAD/PETA services",[8000, 8001, 8002, 8080, 22]),
    ("10.163.1.127", "ncsrd-clouditor",  "Clouditor / orchestrator","Security", 9,  "VM 1077 — Clouditor orchestrator", [9090, 8080, 22]),
    ("10.163.1.128", "ncsrd-worker2",    "Worker2",                 "Compute",  6,  "VM 1049 — K3s worker 2",           [10250, 30000, 22]),
    ("10.163.1.129", "ncsrd-worker1",    "Worker1",                 "Compute",  6,  "VM 1033 — K3s worker 1",           [10250, 30000, 22]),
    ("10.163.1.130", "ncsrd-k3s-master", "MasterK3s",               "Compute",  10, "VM 1031 — K3s control plane",      [6443, 2379, 10250, 22]),
    ("10.163.1.160", "ncsrd-ccm-manager","CCM-Manager",             "Frontend", 8,  "VM 1257/1050 — CCM manager",       [8080, 443, 22]),
    ("10.163.1.170", "ncsrd-sqlserver",  "sqlserver",               "Database", 9,  "SQL Server host",                  [1433, 22]),
    ("10.163.1.176", "ncsrd-mysql",      "mysql",                   "Database", 9,  "VM 1191 — MySQL",                  [3306, 22]),
    ("10.163.1.204", "ncsrd-ccmui",      "ccmui",                   "Frontend", 6,  "VM 1219 — CCM web UI",             [80, 443, 22]),
    ("10.163.1.211", "ncsrd-cobalt-dlt", "cobalt-dlt",              "Database", 8,  "VM 1087 — cobalt DLT ledger",      [8545, 30303, 22]),
    ("10.163.1.249", "ncsrd-ral-cp-drm", "ral-cp-drm",              "Frontend", 7,  "VM 1232 — RAL CP DRM",             [8080, 443, 22]),
]

# link = {"source": A, "target": B}  meaning A depends on / talks to B.
# scoring_engine walks UPSTREAM: for a target node it collects link.source where
# link.target == node, i.e. the components in front of it. That is what lets PETA
# mitigate at the frontend instead of taking a critical database offline.
LINKS = [
    ("ncsrd-toe",         "ncsrd-datalake"),
    ("ncsrd-toe",         "ncsrd-iam"),
    ("ncsrd-toe-quantum", "ncsrd-iam"),
    ("ncsrd-toe-quantum", "ncsrd-k3s-master"),
    ("ncsrd-cobalt",      "ncsrd-cobalt-dlt"),
    ("ncsrd-cobalt",      "ncsrd-iam"),
    ("ncsrd-ccmui",       "ncsrd-ccm-manager"),
    ("ncsrd-ccm-manager", "ncsrd-mysql"),
    ("ncsrd-ccm-manager", "ncsrd-iam"),
    ("ncsrd-ral-cp-drm",  "ncsrd-sqlserver"),
    ("ncsrd-ral-cp-drm",  "ncsrd-iam"),
    ("ncsrd-worker1",     "ncsrd-k3s-master"),
    ("ncsrd-worker2",     "ncsrd-k3s-master"),
    ("ncsrd-worker3",     "ncsrd-k3s-master"),
    ("ncsrd-sdtm",        "ncsrd-sdt-tad"),
    ("ncsrd-watchtower",  "ncsrd-sdt-tad"),
    ("ncsrd-clouditor",   "ncsrd-sdt-tad"),
    ("ncsrd-sdt-tad",     "ncsrd-k3s-master"),
    ("ncsrd-toe",         "ncsrd-k3s-master"),
    ("ncsrd-cobalt",      "ncsrd-k3s-master"),
]

CONTEXTS = ["Frontend", "Database", "Compute", "Identity", "Security"]


def M(mid, desc, action, impact, eff):
    return {"mitigation_id": mid, "description": desc, "action": action,
            "impact_level": impact, "effectiveness": eff}


# ── mitigations: attack -> context -> [options] (all Ubuntu) ─────────────────
# impact_level: Low = barely disruptive .. Critical = takes the service down
# effectiveness: how well it stops THIS attack
ATTACKS = {
    "Denial_of_Service": {
        "att_ck_name": "Network Denial of Service: Reflection Amplification",
        "att_id": "T1498.002",
        "contexts": {
            "Frontend": [
                M("M1037.F1", "Rate limit at nginx", "nginx -s reload after limit_req_zone $binary_remote_addr zone=ddos:10m rate=10r/s", "Low", "Medium"),
                M("M1037.F2", "Rate limit new conns with ufw", "ufw limit proto tcp from any to any port 443", "Low", "Medium"),
                M("M1037.F3", "Drop source with nftables", "nft add rule inet filter input ip saddr $SOURCE_IP drop", "Low", "High"),
                M("M1037.F4", "Enable upstream scrubbing", "curl -X POST api.cdn.provider/scrubbing?enable=true", "Medium", "High"),
            ],
            "Database": [
                M("M1037.D1", "Restrict DB port to app subnet", "ufw delete allow 3306 && ufw allow from 10.163.1.0/24 to any port 3306", "Medium", "High"),
                M("M1037.D2", "Cap concurrent connections", "mysql -e \"SET GLOBAL max_connections=150;\"", "Medium", "Medium"),
                M("M1037.D3", "Throttle source at host firewall", "iptables -A INPUT -s $SOURCE_IP -p tcp --dport 3306 -m limit --limit 20/s -j ACCEPT", "Low", "Medium"),
                M("M1037.D4", "Stop DB service", "systemctl stop mysql", "Critical", "Critical"),
            ],
            "Compute": [
                M("M1037.C1", "Rate limit NodePort range", "iptables -A INPUT -p tcp --dport 30000:32767 -m limit --limit 50/s -j ACCEPT", "Low", "Medium"),
                M("M1037.C2", "Drop source at node firewall", "ufw deny from $SOURCE_IP", "Low", "High"),
                M("M1037.C3", "Cordon node and drain workloads", "kubectl cordon $NODE && kubectl drain $NODE --ignore-daemonsets", "High", "High"),
            ],
            "Identity": [
                M("M1037.I1", "Rate limit auth endpoint", "nft add rule inet filter input tcp dport 8443 limit rate 20/second accept", "Low", "Medium"),
                M("M1037.I2", "Drop source IP", "ufw deny from $SOURCE_IP", "Low", "High"),
                M("M1037.I3", "Restrict IAM to internal subnet", "ufw allow from 10.163.1.0/24 to any port 8443 && ufw deny 8443", "Medium", "High"),
            ],
            "Security": [
                M("M1037.S1", "Rate limit ingest endpoint", "nft add rule inet filter input tcp dport 8002 limit rate 100/second accept", "Low", "Medium"),
                M("M1037.S2", "Drop source IP", "ufw deny from $SOURCE_IP", "Low", "High"),
                M("M1037.S3", "Restrict service to management subnet", "ufw allow from 10.163.1.0/24 to any port 8002 && ufw deny 8002", "Medium", "High"),
            ],
        },
    },
    "SYN_Flood": {
        "att_ck_name": "Endpoint Denial of Service: TCP SYN Flood",
        "att_id": "T1499.001",
        "contexts": {
            c: [
                M(f"M1037.SYN.{c[0]}1", "Enable SYN cookies", "sysctl -w net.ipv4.tcp_syncookies=1", "Low", "High"),
                M(f"M1037.SYN.{c[0]}2", "Enlarge SYN backlog", "sysctl -w net.ipv4.tcp_max_syn_backlog=4096 && sysctl -w net.ipv4.tcp_synack_retries=2", "Low", "Medium"),
                M(f"M1037.SYN.{c[0]}3", "Rate limit SYN packets", "iptables -A INPUT -p tcp --syn -m limit --limit 25/s --limit-burst 50 -j ACCEPT", "Low", "High"),
                M(f"M1037.SYN.{c[0]}4", "Drop source IP", "ufw deny from $SOURCE_IP", "Medium", "High"),
            ] for c in CONTEXTS
        },
    },
    "Port_Scan": {
        "att_ck_name": "Network Service Discovery",
        "att_id": "T1046",
        "contexts": {
            "Frontend": [
                M("M1030.F1", "Ban scanner with fail2ban", "fail2ban-client set portscan banip $SOURCE_IP", "Low", "High"),
                M("M1030.F2", "Drop scanner at firewall", "ufw deny from $SOURCE_IP", "Low", "High"),
                M("M1030.F3", "Default-deny inbound, allow only 80/443", "ufw default deny incoming && ufw allow 80,443/tcp", "Medium", "High"),
            ],
            "Database": [
                M("M1030.D1", "Ban scanner with fail2ban", "fail2ban-client set portscan banip $SOURCE_IP", "Low", "High"),
                M("M1030.D2", "Expose DB port only to app subnet", "ufw delete allow 3306 && ufw allow from 10.163.1.0/24 to any port 3306", "Medium", "Critical"),
                M("M1030.D3", "Drop scanner at firewall", "ufw deny from $SOURCE_IP", "Low", "High"),
            ],
            "Compute": [
                M("M1030.C1", "Ban scanner with fail2ban", "fail2ban-client set portscan banip $SOURCE_IP", "Low", "High"),
                M("M1030.C2", "Restrict kubelet API to control plane", "ufw allow from 10.163.1.130 to any port 10250 && ufw deny 10250", "Medium", "High"),
                M("M1030.C3", "Drop scanner at firewall", "ufw deny from $SOURCE_IP", "Low", "High"),
            ],
            "Identity": [
                M("M1030.I1", "Ban scanner with fail2ban", "fail2ban-client set portscan banip $SOURCE_IP", "Low", "High"),
                M("M1030.I2", "Restrict LDAP/OIDC to internal subnet", "ufw allow from 10.163.1.0/24 to any port 389,636,8443 && ufw deny 389,636,8443", "Medium", "Critical"),
                M("M1030.I3", "Drop scanner at firewall", "ufw deny from $SOURCE_IP", "Low", "High"),
            ],
            "Security": [
                M("M1030.S1", "Ban scanner with fail2ban", "fail2ban-client set portscan banip $SOURCE_IP", "Low", "High"),
                M("M1030.S2", "Drop scanner at firewall", "ufw deny from $SOURCE_IP", "Low", "High"),
                M("M1030.S3", "Restrict management ports to admin subnet", "ufw allow from 10.163.1.0/24 to any port 8000,8001,8002 && ufw deny 8000,8001,8002", "Medium", "High"),
            ],
        },
    },
    "Brute_Force": {
        "att_ck_name": "Brute Force: Password Guessing",
        "att_id": "T1110.001",
        "contexts": {
            "Frontend": [
                M("M1036.F1", "Ban source via fail2ban sshd jail", "fail2ban-client set sshd banip $SOURCE_IP", "Low", "High"),
                M("M1036.F2", "Rate limit SSH", "ufw limit ssh", "Low", "Medium"),
                M("M1036.F3", "Cap SSH auth attempts", "sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config && systemctl reload ssh", "Low", "High"),
                M("M1036.F4", "Disable password auth (keys only)", "sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && systemctl reload ssh", "Medium", "Critical"),
            ],
            "Database": [
                M("M1036.D1", "Ban source via fail2ban", "fail2ban-client set sshd banip $SOURCE_IP", "Low", "High"),
                M("M1036.D2", "Lock targeted DB account", "mysql -e \"ALTER USER '$TARGET_USER'@'%' ACCOUNT LOCK;\"", "Medium", "Critical"),
                M("M1036.D3", "Restrict DB auth to app subnet", "ufw allow from 10.163.1.0/24 to any port 3306 && ufw deny 3306", "Medium", "High"),
                M("M1036.D4", "Disable password auth (keys only)", "sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && systemctl reload ssh", "Medium", "Critical"),
            ],
            "Compute": [
                M("M1036.C1", "Ban source via fail2ban", "fail2ban-client set sshd banip $SOURCE_IP", "Low", "High"),
                M("M1036.C2", "Rate limit SSH", "ufw limit ssh", "Low", "Medium"),
                M("M1036.C3", "Disable password auth (keys only)", "sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && systemctl reload ssh", "Medium", "Critical"),
            ],
            "Identity": [
                M("M1036.I1", "Ban source via fail2ban", "fail2ban-client set sshd banip $SOURCE_IP", "Low", "High"),
                M("M1036.I2", "Lock the targeted identity", "kubectl -n iam exec deploy/keycloak -- /opt/keycloak/bin/kcadm.sh update users/$TARGET_USER -s enabled=false", "Medium", "Critical"),
                M("M1036.I3", "Enforce account lockout policy", "pam-auth-update --enable faillock && sed -i 's/^#*deny.*/deny = 5/' /etc/security/faillock.conf", "Low", "High"),
                M("M1036.I4", "Disable password auth (keys only)", "sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && systemctl reload ssh", "Medium", "Critical"),
            ],
            "Security": [
                M("M1036.S1", "Ban source via fail2ban", "fail2ban-client set sshd banip $SOURCE_IP", "Low", "High"),
                M("M1036.S2", "Rate limit SSH", "ufw limit ssh", "Low", "Medium"),
                M("M1036.S3", "Restrict SSH to admin subnet", "ufw allow from 10.163.1.0/24 to any port 22 && ufw deny 22", "Medium", "High"),
            ],
        },
    },
    "SQL_Injection": {
        "att_ck_name": "Exploit Public-Facing Application",
        "att_id": "T1190",
        "contexts": {
            "Frontend": [
                M("M1051.F1", "Enable WAF SQLi ruleset", "a2enmod security2 && sed -i 's/SecRuleEngine.*/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf && systemctl reload apache2", "Low", "High"),
                M("M1051.F2", "Block source IP", "ufw deny from $SOURCE_IP", "Low", "Medium"),
                M("M1051.F3", "Patch application packages", "apt-get update && apt-get install --only-upgrade -y $APP_PACKAGE", "Medium", "Critical"),
                M("M1051.F4", "Take endpoint offline", "systemctl stop nginx", "Critical", "Critical"),
            ],
            "Database": [
                M("M1051.D1", "Revoke risky privileges from app user", "mysql -e \"REVOKE FILE, SUPER ON *.* FROM '$APP_USER'@'%'; FLUSH PRIVILEGES;\"", "Low", "High"),
                M("M1051.D2", "Enable general query audit", "mysql -e \"SET GLOBAL general_log='ON';\"", "Low", "Medium"),
                M("M1051.D3", "Restrict DB to app subnet", "ufw allow from 10.163.1.0/24 to any port 3306 && ufw deny 3306", "Medium", "High"),
                M("M1051.D4", "Stop DB service", "systemctl stop mysql", "Critical", "Critical"),
            ],
            "Compute": [
                M("M1051.C1", "Apply NetworkPolicy to isolate pod", "kubectl -n $NS apply -f deny-egress-netpol.yaml", "Medium", "High"),
                M("M1051.C2", "Block source IP", "ufw deny from $SOURCE_IP", "Low", "Medium"),
                M("M1051.C3", "Roll out patched image", "kubectl -n $NS set image deploy/$APP $APP=$IMAGE:patched", "Medium", "Critical"),
            ],
            "Identity": [
                M("M1051.I1", "Block source IP", "ufw deny from $SOURCE_IP", "Low", "Medium"),
                M("M1051.I2", "Rotate IAM service credentials", "kubectl -n iam delete secret iam-db-credentials && kubectl -n iam create secret generic iam-db-credentials --from-literal=password=$NEW_PW", "Medium", "High"),
                M("M1051.I3", "Patch IAM packages", "apt-get update && apt-get install --only-upgrade -y keycloak", "Medium", "Critical"),
            ],
            "Security": [
                M("M1051.S1", "Block source IP", "ufw deny from $SOURCE_IP", "Low", "Medium"),
                M("M1051.S2", "Patch service packages", "apt-get update && apt-get upgrade -y", "Medium", "High"),
                M("M1051.S3", "Restrict API to management subnet", "ufw allow from 10.163.1.0/24 to any port 8000,8001,8002 && ufw deny 8000,8001,8002", "Medium", "High"),
            ],
        },
    },
    # NEW — closes the TAD `post_exploitation` gap. Without this entry TAD
    # detects the compromise but PETA cannot dispatch any mitigation.
    "Host_Compromise": {
        "att_ck_name": "Command and Control / Execution: Reverse Shell on Compromised Host",
        "att_id": "T1059.004",
        "contexts": {
            "Frontend": [
                M("M1040.F1", "Kill non-interactive reverse shells", "pkill -9 -f 'bash -i' ; pkill -9 -f 'nc -e'", "Low", "Medium"),
                M("M1040.F2", "Block C2 egress to source", "ufw deny out to $SOURCE_IP", "Low", "High"),
                M("M1040.F3", "Terminate attacker SSH sessions and revoke keys", "pkill -9 -u $COMPROMISED_USER sshd ; truncate -s 0 /home/$COMPROMISED_USER/.ssh/authorized_keys", "Medium", "High"),
                M("M1040.F4", "Network-isolate the host", "ufw default deny incoming && ufw default deny outgoing && ufw allow from 10.163.1.0/24 to any port 22", "High", "Critical"),
            ],
            "Database": [
                M("M1040.D1", "Kill reverse shell processes", "pkill -9 -f 'bash -i' ; pkill -9 -f 'nc -e'", "Low", "Medium"),
                M("M1040.D2", "Block C2 egress", "ufw deny out to $SOURCE_IP", "Low", "High"),
                M("M1040.D3", "Rotate DB credentials", "mysql -e \"ALTER USER '$APP_USER'@'%' IDENTIFIED BY '$NEW_PW'; FLUSH PRIVILEGES;\"", "Medium", "High"),
                M("M1040.D4", "Network-isolate the host", "ufw default deny incoming && ufw default deny outgoing", "Critical", "Critical"),
            ],
            "Compute": [
                M("M1040.C1", "Kill reverse shell processes", "pkill -9 -f 'bash -i' ; pkill -9 -f 'nc -e'", "Low", "Medium"),
                M("M1040.C2", "Block C2 egress", "ufw deny out to $SOURCE_IP", "Low", "High"),
                M("M1040.C3", "Cordon and drain the node", "kubectl cordon $NODE && kubectl drain $NODE --ignore-daemonsets --delete-emptydir-data", "High", "High"),
                M("M1040.C4", "Isolate node and rotate kubelet certs", "ufw default deny outgoing && kubeadm certs renew all", "Critical", "Critical"),
            ],
            "Identity": [
                M("M1040.I1", "Kill reverse shell processes", "pkill -9 -f 'bash -i' ; pkill -9 -f 'nc -e'", "Low", "Medium"),
                M("M1040.I2", "Block C2 egress", "ufw deny out to $SOURCE_IP", "Low", "High"),
                M("M1040.I3", "Revoke all active sessions and tokens", "kubectl -n iam exec deploy/keycloak -- /opt/keycloak/bin/kcadm.sh delete sessions --realm master", "High", "Critical"),
                M("M1040.I4", "Network-isolate the identity host", "ufw default deny incoming && ufw default deny outgoing", "Critical", "Critical"),
            ],
            "Security": [
                M("M1040.S1", "Kill reverse shell processes", "pkill -9 -f 'bash -i' ; pkill -9 -f 'nc -e'", "Low", "Medium"),
                M("M1040.S2", "Block C2 egress", "ufw deny out to $SOURCE_IP", "Low", "High"),
                M("M1040.S3", "Enable auditd process accounting", "systemctl enable --now auditd && auditctl -a always,exit -F arch=b64 -S execve", "Low", "Medium"),
                M("M1040.S4", "Isolate host, preserve monitoring uplink", "ufw default deny outgoing && ufw allow out to 10.163.1.125", "High", "Critical"),
            ],
        },
    },
}


def build_topology():
    nodes = [{
        "id": nid, "name": name, "type": ctx, "criticality": crit,
        "role": role, "ip": ip, "open_ports": ports,
    } for ip, nid, name, ctx, crit, role, ports in TARGET_HOSTS]
    links = [{"source": s, "target": t} for s, t in LINKS]
    return {"topology": {"nodes": nodes, "links": links}}


def validate(topo, attacks):
    """Fail loudly if any node could ever receive no mitigation."""
    sys.path.insert(0, HERE)
    from scoring_engine import score_mitigations
    nodes = topo["topology"]["nodes"]
    links = topo["topology"]["links"]
    errors = []

    ids = [n["id"] for n in nodes]
    if len(ids) != len(set(ids)):
        errors.append("duplicate node ids")
    for l in links:
        if l["source"] not in ids or l["target"] not in ids:
            errors.append(f"link references unknown node: {l}")

    used = sorted({n["type"] for n in nodes})
    for atk, spec in attacks.items():
        for ctx in used:
            if ctx not in spec["contexts"]:
                errors.append(f"MISSING contexts['{ctx}'] under attack '{atk}'")

    # every (node, attack) pair must yield a real mitigation
    blank = 0
    for n, atk in itertools.product(nodes, attacks):
        r = score_mitigations(attacks, atk, n, nodes, links)
        if not r or "mitigation_id" not in r:
            errors.append(f"NO mitigation: {n['id']} / {atk}")
            blank += 1
    return errors, len(nodes) * len(attacks) - blank, len(nodes) * len(attacks)


def main():
    topo = build_topology()
    errors, ok, total = validate(topo, ATTACKS)
    if errors:
        print("VALIDATION FAILED:")
        for e in errors[:20]:
            print("  -", e)
        sys.exit(1)

    with open(os.path.join(HERE, "ncsrd_topology_peta.json"), "w") as f:
        json.dump(topo, f, indent=2)
    with open(os.path.join(HERE, "attack_mapping.json"), "w") as f:
        json.dump(ATTACKS, f, indent=2)

    print(f"  nodes            : {len(topo['topology']['nodes'])}")
    print(f"  links            : {len(topo['topology']['links'])}")
    print(f"  attack types     : {len(ATTACKS)}  ({', '.join(ATTACKS)})")
    print(f"  contexts         : {', '.join(CONTEXTS)}")
    print(f"  (node,attack) pairs resolving to a mitigation: {ok}/{total}")
    print("  wrote ncsrd_topology_peta.json + attack_mapping.json")


if __name__ == "__main__":
    main()
