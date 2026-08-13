"""
Synthetic network traffic generator.

Produces aggregated "flow" records: one row per source IP per 10-second
window -- the same shape a real IDS gets after extracting features from
packet captures or NetFlow data. Normal background traffic is mixed with
three labelled attack patterns.

The `label` column is ground truth. It is used only to evaluate the model;
the model itself never trains on it.

Usage
-----
    python data/generate_data.py                     # writes data/traffic.csv
    python data/generate_data.py --summary           # + class breakdown
    python data/generate_data.py --seed 7 --out data/test.csv
"""

import argparse
import csv
import os
import random
from datetime import datetime, timedelta

DEFAULT_SEED = 42
DEFAULT_WINDOWS = 180          # 180 x 10s = 30 minutes of simulated capture
WINDOW_SECONDS = 10
NUM_NORMAL_HOSTS = 25
CAPTURE_START = datetime(2026, 8, 7, 9, 0, 0)

# Default output sits next to this script, inside data/.
DEFAULT_OUTPUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "traffic.csv")

FIELDS = [
    "timestamp",
    "src_ip",
    "num_connections",
    "unique_dst_ports",
    "bytes_sent",
    "bytes_recv",
    "failed_logins",
    "syn_ratio",
    "avg_conn_duration",
    "label",
]

# Attacks are scheduled at fixed windows so the demo has a predictable
# narrative and results stay reproducible.
#   window_index -> (attack_type, attacker_ip)
ATTACK_SCHEDULE = {
    45: ("port_scan", "10.0.0.66"),
    46: ("port_scan", "10.0.0.66"),
    47: ("port_scan", "10.0.0.66"),
    90: ("brute_force", "10.0.0.77"),
    91: ("brute_force", "10.0.0.77"),
    92: ("brute_force", "10.0.0.77"),
    93: ("brute_force", "10.0.0.77"),
    140: ("ddos", "10.0.0.88"),
    141: ("ddos", "10.0.0.88"),
    142: ("ddos", "10.0.0.89"),
    143: ("ddos", "10.0.0.90"),
}


# --------------------------------------------------------------------------
# Traffic profiles
#
# To add an attack type: write a profile function, register it in
# ATTACK_PROFILES, then add entries to ATTACK_SCHEDULE.
# --------------------------------------------------------------------------

def normal_flow(rng, timestamp, src_ip):
    """Typical user session: few connections, balanced traffic, no failures."""
    return {
        "timestamp": timestamp.isoformat(),
        "src_ip": src_ip,
        "num_connections": rng.randint(1, 6),
        "unique_dst_ports": rng.randint(1, 3),
        "bytes_sent": round(rng.uniform(500, 8000), 1),
        "bytes_recv": round(rng.uniform(2000, 40000), 1),
        "failed_logins": rng.choice([0, 0, 0, 0, 1]),
        "syn_ratio": round(rng.uniform(0.05, 0.25), 3),
        "avg_conn_duration": round(rng.uniform(0.5, 12.0), 2),
        "label": "normal",
    }


def port_scan_flow(rng, timestamp, src_ip):
    """
    Reconnaissance: one host probing many ports quickly.

    Signature: high unique_dst_ports, near-1.0 syn_ratio (connections opened
    but never completed), almost no bytes_recv because ports refuse.
    """
    return {
        "timestamp": timestamp.isoformat(),
        "src_ip": src_ip,
        "num_connections": rng.randint(80, 300),
        "unique_dst_ports": rng.randint(60, 250),
        "bytes_sent": round(rng.uniform(3000, 9000), 1),
        "bytes_recv": round(rng.uniform(50, 500), 1),
        "failed_logins": 0,
        "syn_ratio": round(rng.uniform(0.85, 0.99), 3),
        "avg_conn_duration": round(rng.uniform(0.01, 0.1), 2),
        "label": "port_scan",
    }


def brute_force_flow(rng, timestamp, src_ip):
    """
    Credential stuffing against one service.

    Signature: failed_logins spikes while unique_dst_ports stays at 1 -- the
    attacker hammers one port (SSH, RDP) rather than exploring.
    """
    return {
        "timestamp": timestamp.isoformat(),
        "src_ip": src_ip,
        "num_connections": rng.randint(20, 60),
        "unique_dst_ports": 1,
        "bytes_sent": round(rng.uniform(1000, 3000), 1),
        "bytes_recv": round(rng.uniform(500, 1500), 1),
        "failed_logins": rng.randint(15, 55),
        "syn_ratio": round(rng.uniform(0.2, 0.4), 3),
        "avg_conn_duration": round(rng.uniform(0.2, 1.5), 2),
        "label": "brute_force",
    }


def ddos_flow(rng, timestamp, src_ip):
    """
    Volumetric flood aimed at exhausting the target.

    Signature: enormous num_connections and bytes_sent, near-zero bytes_recv
    and duration -- the target never gets to respond.
    """
    return {
        "timestamp": timestamp.isoformat(),
        "src_ip": src_ip,
        "num_connections": rng.randint(500, 1500),
        "unique_dst_ports": rng.randint(1, 3),
        "bytes_sent": round(rng.uniform(200000, 900000), 1),
        "bytes_recv": round(rng.uniform(0, 200), 1),
        "failed_logins": 0,
        "syn_ratio": round(rng.uniform(0.9, 1.0), 3),
        "avg_conn_duration": round(rng.uniform(0.001, 0.02), 2),
        "label": "ddos",
    }


ATTACK_PROFILES = {
    "port_scan": port_scan_flow,
    "brute_force": brute_force_flow,
    "ddos": ddos_flow,
}


def generate_rows(seed=DEFAULT_SEED, windows=DEFAULT_WINDOWS):
    """Build all flow records. Deterministic for a given seed."""
    rng = random.Random(seed)
    normal_ips = [f"10.0.0.{i}" for i in range(1, NUM_NORMAL_HOSTS + 1)]
    rows = []

    for window_index in range(windows):
        timestamp = CAPTURE_START + timedelta(seconds=window_index * WINDOW_SECONDS)

        # Only a subset of hosts are active per window -- real networks are
        # bursty, not uniformly busy.
        for src_ip in rng.sample(normal_ips, k=rng.randint(8, 18)):
            rows.append(normal_flow(rng, timestamp, src_ip))

        if window_index in ATTACK_SCHEDULE:
            attack_type, attacker_ip = ATTACK_SCHEDULE[window_index]
            rows.append(ATTACK_PROFILES[attack_type](rng, timestamp, attacker_ip))

    return rows


def write_csv(rows, path):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def print_summary(rows):
    counts = {}
    for row in rows:
        counts[row["label"]] = counts.get(row["label"], 0) + 1

    total = len(rows)
    print(f"\n  Total flows: {total}")
    print("  Class breakdown:")
    for label in sorted(counts, key=lambda k: -counts[k]):
        print(f"    {label:<14} {counts[label]:>6}  ({counts[label] / total * 100:5.2f}%)")

    print("\n  Attack schedule:")
    for window_index in sorted(ATTACK_SCHEDULE):
        attack_type, attacker_ip = ATTACK_SCHEDULE[window_index]
        offset = timedelta(seconds=window_index * WINDOW_SECONDS)
        print(f"    +{str(offset):>8}  {attack_type:<12} from {attacker_ip}")
    print()


def main():
    parser = argparse.ArgumentParser(description="Generate synthetic IDS traffic.")
    parser.add_argument("--out", default=DEFAULT_OUTPUT, help="output CSV path")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED, help="random seed")
    parser.add_argument("--windows", type=int, default=DEFAULT_WINDOWS,
                        help=f"number of {WINDOW_SECONDS}s windows to simulate")
    parser.add_argument("--summary", action="store_true",
                        help="print class breakdown and attack schedule")
    args = parser.parse_args()

    min_windows = max(ATTACK_SCHEDULE) + 1
    if args.windows < min_windows:
        parser.error(f"--windows must be at least {min_windows} so all "
                     f"scheduled attacks are included")

    rows = generate_rows(seed=args.seed, windows=args.windows)
    write_csv(rows, args.out)
    print(f"Wrote {len(rows)} flow records to {args.out} (seed={args.seed})")

    if args.summary:
        print_summary(rows)


if __name__ == "__main__":
    main()