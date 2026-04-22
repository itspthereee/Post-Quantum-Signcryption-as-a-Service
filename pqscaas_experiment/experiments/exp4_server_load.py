"""
Experiment 4: Server Signcryption Under Load (PQSCAAS-only)
  X-axis: Arrival rate lambda (req/sec): 10, 25, 50, 100, 250, 500, 1000, 2000, 5000
  Y-axis: Server computation cost per request (ms)

Shows PQSCAAS's adaptive batching advantage:
  - At low lambda: small batches (B=1-2), per-request cost ~= non-batched
  - At high lambda: large batches, TEE enter/exit amortizes, cost drops

Baselines don't have this feature (no server, no batching), so this is
PQSCAAS-only. Shows the unique operational advantage of the service.
"""

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pqscaas import scheme as pq
from pqscaas import crypto_primitives as cp


LAMBDA_VALUES = [10, 25, 50, 100, 250, 500, 1000, 2000, 5000]
NUM_TRIALS = 50

NUM_ENCLAVES = 8
MAX_BATCH = 128
DELTA_MAX_MS = 50.0  # Max wait time before closing batch


def adaptive_batch_size(lam: float) -> int:
    """Compute effective batch size based on arrival rate."""
    lambda_per_enclave = lam / NUM_ENCLAVES
    expected_batch = lambda_per_enclave * (DELTA_MAX_MS / 1000.0)
    return max(1, min(MAX_BATCH, int(round(expected_batch))))


def run():
    results = {'lambda': [], 'batch_size': [],
               'PQSCAAS_per_req': [], 'PQSCAAS_per_req_std': []}

    # Pre-generate keys
    pk_r_kem, _, _ = cp.ml_kem_keygen()
    _, sk_u_sig, _ = cp.ml_dsa_keygen()

    for lam in LAMBDA_VALUES:
        B = adaptive_batch_size(lam)
        print(f"[Exp 4] lambda = {lam:>5} req/s, batch size B = {B}...")

        runs = []
        for trial in range(NUM_TRIALS):
            np.random.seed(trial * 31 + lam)
            # Measure per-request cost for this batch size
            per_req_cost = pq.phase4_per_request_cost(B, pk_r_kem, sk_u_sig)
            runs.append(per_req_cost)

        results['lambda'].append(lam)
        results['batch_size'].append(B)
        results['PQSCAAS_per_req'].append(np.mean(runs))
        results['PQSCAAS_per_req_std'].append(np.std(runs))

        print(f"  Per-request cost: {np.mean(runs):>10.4f} ms (B={B})")

    return pd.DataFrame(results)


def plot(df, out_path):
    fig, ax = plt.subplots(figsize=(8, 5.5))
    ax.errorbar(df['lambda'], df['PQSCAAS_per_req'],
                yerr=df['PQSCAAS_per_req_std'],
                marker='o', linestyle='-', color='#2E86AB',
                label='PQSCAAS (adaptive batching)', markersize=8,
                linewidth=2, capsize=4, capthick=1.5)

    # Annotate batch sizes at each point
    for _, row in df.iterrows():
        ax.annotate(f"B={row['batch_size']}",
                    xy=(row['lambda'], row['PQSCAAS_per_req']),
                    xytext=(5, 8), textcoords='offset points',
                    fontsize=9, color='gray')

    ax.set_xscale('log')
    ax.set_xlabel('Arrival rate $\\lambda$ (req/sec)', fontsize=12)
    ax.set_ylabel('Server cost per request (ms)', fontsize=12)
    ax.set_title('Exp 4: Server Signcryption Under Load (PQSCAAS)',
                 fontsize=13, fontweight='bold')
    ax.legend(loc='upper right', fontsize=11)
    ax.grid(True, which='both', ls='-', alpha=0.3)

    plt.tight_layout()
    plt.savefig(out_path, dpi=200, bbox_inches='tight')
    plt.savefig(out_path.replace('.png', '.pdf'), bbox_inches='tight')
    plt.close()


if __name__ == "__main__":
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.makedirs(os.path.join(base, 'results'), exist_ok=True)
    os.makedirs(os.path.join(base, 'figures'), exist_ok=True)

    df = run()
    df.to_csv(os.path.join(base, 'results', 'exp4_server_load.csv'), index=False)
    plot(df, os.path.join(base, 'figures', 'exp4_server_load.png'))
    print(f"\n✓ Exp 4 complete.")
    print(df.to_string(index=False))
