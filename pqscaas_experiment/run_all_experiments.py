#!/usr/bin/env python3
"""
Master script to run all 6 PQSCAAS experiments.

Usage:
    python3 run_all_experiments.py           # Run all
    python3 run_all_experiments.py 1 2 3     # Run specific ones

Each experiment saves:
  results/*.csv
  figures/*.png + *.pdf
"""

import os
import sys
import subprocess
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)


EXPERIMENTS = [
    ('experiments.exp1_keygen',           'Exp 1: Key Generation'),
    ('experiments.exp2_client_encrypt',   'Exp 2: Client Encryption (AEAD vs Signcryption)'),
    ('experiments.exp3_server_signcrypt', 'Exp 3: Server-Side Signcryption (PQSCAAS-only)'),
    ('experiments.exp4_server_load',      'Exp 4: Server Signcryption Under Load (PQSCAAS-only)'),
    ('experiments.exp5_end_to_end',       'Exp 5: End-to-End Encryption (Client+Server)'),
    ('experiments.exp6_decrypt',          'Exp 6: Recipient Decryption'),
]


def run_experiment(module, name):
    print(f"\n{'='*72}")
    print(f" {name}")
    print(f"{'='*72}")
    start = time.time()
    result = subprocess.run([sys.executable, '-m', module], cwd=SCRIPT_DIR)
    elapsed = time.time() - start
    return result.returncode == 0, elapsed


def main():
    os.makedirs(os.path.join(SCRIPT_DIR, 'results'), exist_ok=True)
    os.makedirs(os.path.join(SCRIPT_DIR, 'figures'), exist_ok=True)

    # Parse selection
    if len(sys.argv) > 1:
        selected = [int(x) - 1 for x in sys.argv[1:] if x.isdigit()]
        to_run = [EXPERIMENTS[i] for i in selected if 0 <= i < len(EXPERIMENTS)]
    else:
        to_run = EXPERIMENTS

    print(f"Running {len(to_run)} experiment(s)...")

    results = {}
    total_start = time.time()
    for module, name in to_run:
        ok, elapsed = run_experiment(module, name)
        results[name] = ('PASS' if ok else 'FAIL', elapsed)

    total_elapsed = time.time() - total_start

    print(f"\n\n{'='*72}")
    print(" SUMMARY")
    print(f"{'='*72}")
    for name, (status, elapsed) in results.items():
        sym = '✓' if status == 'PASS' else '✗'
        print(f" {sym} {name:<55} [{status}] ({elapsed:.1f}s)")
    print(f"\nTotal time: {total_elapsed:.1f}s")
    print(f"Results: {os.path.join(SCRIPT_DIR, 'results')}")
    print(f"Figures: {os.path.join(SCRIPT_DIR, 'figures')}")

    return 0 if all(s[0] == 'PASS' for s in results.values()) else 1


if __name__ == '__main__':
    sys.exit(main())
