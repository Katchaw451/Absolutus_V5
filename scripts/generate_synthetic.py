#!/usr/bin/env python3
"""Generate synthetic auth + nginx logs for Absolutus_V5 demos.

Creates ~5000 lines mixing benign traffic, a brute-force burst,
an HTTP scanner, and one IP that does both (the anomaly).
"""
import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(42)

N_BENIGN = 40
N_ATTACKERS = 30
LINES_PER_IP = 60
START = datetime(2026, 10, 30, 0, 0, 0)


def rand_ip(prefix_pool):
    return random.choice(prefix_pool)


BENIGN_IPS = [f"192.168.1.{i}" for i in range(10, 10 + N_BENIGN)]
ATTACKER_IPS = [f"203.0.113.{i}" for i in range(1, 1 + N_ATTACKERS)]
SCAN_IPS = [f"198.51.100.{i}" for i in range(1, 11)]
BOTH_IPS = ["203.0.113.99"]  # anomaly: scans AND brute-forces


def fmt_auth(ts, user, ip, ok):
    verb = "Accepted" if ok else "Failed"
    return (
        f"{ts.strftime('%b %d %H:%M:%S')} host sshd[1234]: "
        f"{verb} password for {user} from {ip} port 50122 ssh2"
    )


def fmt_nginx(ts, ip, path, status):
    return (
        f'{ip} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
        f'"GET {path} HTTP/1.1" {status} 512 "-" "curl/7.68.0"'
    )


def main():
    auth, http = [], []

    # Benign users: log in a few times during the day, accepted.
    for ip in BENIGN_IPS:
        for _ in range(random.randint(3, 8)):
            ts = START + timedelta(hours=random.randint(8, 22),
                                   minutes=random.randint(0, 59))
            auth.append(fmt_auth(ts, "katchaw", ip, True))

    # Brute-force attackers: many failed logins in a short burst.
    for ip in ATTACKER_IPS:
        burst_start = START + timedelta(hours=random.randint(0, 23))
        for i in range(LINES_PER_IP):
            ts = burst_start + timedelta(seconds=i * 2)
            user = random.choice(["admin", "root", "oracle", "test"])
            auth.append(fmt_auth(ts, user, ip, False))

    # Scanners: 404 bursts on nginx.
    scan_paths = ["/admin", "/.env", "/wp-login.php", "/phpmyadmin",
                  "/config.php", "/backup.zip"]
    for ip in SCAN_IPS:
        burst_start = START + timedelta(hours=random.randint(0, 23))
        for i, path in enumerate(scan_paths * 10):  # 60 lines
            ts = burst_start + timedelta(seconds=i * 2)
            http.append(fmt_nginx(ts, ip, path, 404))

    # Benign HTTP traffic
    for ip in BENIGN_IPS:
        for _ in range(3):
            ts = START + timedelta(hours=random.randint(8, 22))
            http.append(fmt_nginx(ts, ip, "/", 200))

    # Both: scan + brute-force (the anomaly)
    for ip in BOTH_IPS:
        burst_start = START + timedelta(hours=3, minutes=15)
        for i in range(LINES_PER_IP):
            ts = burst_start + timedelta(seconds=i * 2)
            auth.append(fmt_auth(ts, "admin", ip, False))
        for i, path in enumerate(scan_paths * 10):
            ts = burst_start + timedelta(seconds=i * 2)
            http.append(fmt_nginx(ts, ip, path, 404))

    random.shuffle(auth)
    random.shuffle(http)

    Path("data/synthetic_auth.log").write_text("\n".join(auth) + "\n")
    Path("data/synthetic_nginx.log").write_text("\n".join(http) + "\n")
    print(f"[+] wrote {len(auth)} auth + {len(http)} http lines")


if __name__ == "__main__":
    main()
