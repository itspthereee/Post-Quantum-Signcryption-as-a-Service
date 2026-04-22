"""
Experiment 2b: Signcryption Scalability - Multiple Requests (Fair Comparison)
  X-axis: Number of requests (1, 5, 10, 25, 50, 100)
  Y-axis: Signcryption computation cost (ms)

PQSCAAS WITH Batch-Oriented Multi-Enclave Provisioning (REALISTIC):
  - Server batch signcryption only (TEE overhead amortized across N requests)
  - Client AEAD is separate concern, not measured here

PQSCAAS WITHOUT Batch-Oriented Multi-Enclave Provisioning (BASELINE):
  - N * Server signcryption (full TEE overhead per request, no batching)
  - Shows cost without optimization

Baselines: N * (Client-side full signcryption) - sequential on single client

Key insight: Server batching dramatically reduces per-request signcryption cost.
PQSCAAS defers ALL signcryption to powerful server while clients stay lightweight.

Fixed file size: 1 MB per request (realistic IoT message size)
"""

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pqscaas import scheme as pq
from pqscaas import crypto_primitives as cp
from baselines import sinha2026, yu2021, bai2025


REQUEST_COUNTS = [1, 5, 10, 25, 50, 100]
FILE_SIZE = 1 * 1024 * 1024  # 1 MB per request
NUM_TRIALS = 20


def run():
    results = {'num_requests': [],
               'PQSCAAS_with_batch': [], 'PQSCAAS_with_batch_std': [],
               'PQSCAAS_without_batch': [], 'PQSCAAS_without_batch_std': [],
               'Sinha2026': [], 'Sinha2026_std': [],
               'Yu2021': [], 'Yu2021_std': [],
               'Bai2025': [], 'Bai2025_std': []}

    # Pre-generate keys once (amortized setup cost)
    pk_r_kem, _, _ = cp.ml_kem_keygen()
    _, sk_u_sig, _ = cp.ml_dsa_keygen()

    for num_reqs in REQUEST_COUNTS:
        print(f"\n[Exp 2b] Number of requests = {num_reqs}...")
        pq_batch_runs, pq_nobatch_runs, sinha_runs, yu_runs, bai_runs = [], [], [], [], []

        for trial in range(NUM_TRIALS):
            np.random.seed(trial * 42 + num_reqs)

            # ========== PQSCAAS WITH Batch-Oriented Multi-Enclave Provisioning ==========
            pq_batch_total_ms = 0.0
            descriptors = []

            # Client batch: N * AEAD operations (not measured - separate concern)
            for i in range(num_reqs):
                msg = os.urandom(FILE_SIZE)
                desc, _ = pq.phase3_client_encrypt(msg)  # Client AEAD (not counted)
                descriptors.append(desc)

            # Server batch: N signcryptions with AMORTIZED TEE overhead
            # Key advantage: TEE enter/exit costs (~16ms) spread across all requests
            _, t_server = pq.phase4_server_signcrypt_batch(descriptors, pk_r_kem, sk_u_sig)
            pq_batch_total_ms = t_server  # Only server cost
            pq_batch_runs.append(pq_batch_total_ms)

            # ========== PQSCAAS WITHOUT Batch-Oriented Multi-Enclave Provisioning ==========
            pq_nobatch_total_ms = 0.0
            for i in range(num_reqs):
                msg = os.urandom(FILE_SIZE)
                desc, _ = pq.phase3_client_encrypt(msg)  # Client AEAD (not counted)
                # Individual server operations (no batching, full TEE overhead per request)
                _, t_server = pq.phase4_server_signcrypt_single(desc, pk_r_kem, sk_u_sig)
                pq_nobatch_total_ms += t_server
            pq_nobatch_runs.append(pq_nobatch_total_ms)

            # ========== Baselines: Heavy client-side PQ (N sequential operations) ==========
            sinha_total_ms = 0.0
            yu_total_ms = 0.0
            bai_total_ms = 0.0

            for i in range(num_reqs):
                msg = os.urandom(FILE_SIZE)
                sinha_total_ms += sinha2026.ntru_client_signcrypt(msg)
                yu_total_ms += yu2021.lclss_client_signcrypt(msg)
                bai_total_ms += bai2025.mlcloosc_client_signcrypt(msg)

            sinha_runs.append(sinha_total_ms)
            yu_runs.append(yu_total_ms)
            bai_runs.append(bai_total_ms)

        results['num_requests'].append(num_reqs)
        results['PQSCAAS_with_batch'].append(np.mean(pq_batch_runs))
        results['PQSCAAS_with_batch_std'].append(np.std(pq_batch_runs))
        results['PQSCAAS_without_batch'].append(np.mean(pq_nobatch_runs))
        results['PQSCAAS_without_batch_std'].append(np.std(pq_nobatch_runs))
        results['Sinha2026'].append(np.mean(sinha_runs))
        results['Sinha2026_std'].append(np.std(sinha_runs))
        results['Yu2021'].append(np.mean(yu_runs))
        results['Yu2021_std'].append(np.std(yu_runs))
        results['Bai2025'].append(np.mean(bai_runs))
        results['Bai2025_std'].append(np.std(bai_runs))

        print(f"  Requests={num_reqs:3d}: "
              f"PQSCAAS(batch)={np.mean(pq_batch_runs):>8.2f}ms  "
              f"PQSCAAS(no-batch)={np.mean(pq_nobatch_runs):>8.2f}ms  |  "
              f"Baselines: Sinha={np.mean(sinha_runs):>8.2f}ms  Yu={np.mean(yu_runs):>8.2f}ms  Bai={np.mean(bai_runs):>8.2f}ms")

    return pd.DataFrame(results)


def plot(df, out_path):
    fig, ax = plt.subplots(figsize=(11, 6.5))
    for name, marker, ls, color in [
        ('PQSCAAS_with_batch',    'o', '-',  '#2E86AB'),
        ('PQSCAAS_without_batch', 'o', '--', '#5DADE2'),
        ('Bai2025',               's', '--', '#A23B72'),
        ('Sinha2026',             '^', '-.', '#F18F01'),
        ('Yu2021',                'D', ':',  '#C73E1D')]:
        ax.errorbar(df['num_requests'], df[name], yerr=df[f'{name}_std'],
                    marker=marker, linestyle=ls, color=color,
                    label=name, markersize=8, linewidth=2.5, capsize=5, capthick=2)

    ax.set_xlabel('Number of Requests', fontsize=12, fontweight='bold')
    ax.set_ylabel('Total Computation Cost (ms)', fontsize=12, fontweight='bold')
    ax.set_title('Exp 2b: Signcryption Scalability - Server-Side PQSCAAS vs Client-Side Baselines',
                 fontsize=13, fontweight='bold')
    ax.legend(loc='upper left', fontsize=10, framealpha=0.95)
    ax.grid(True, which='both', ls='-', alpha=0.3)
    ax.set_xticks(df['num_requests'])

    plt.tight_layout()
    plt.savefig(out_path, dpi=200, bbox_inches='tight')
    plt.savefig(out_path.replace('.png', '.pdf'), bbox_inches='tight')
    plt.close()


if __name__ == "__main__":
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.makedirs(os.path.join(base, 'results'), exist_ok=True)
    os.makedirs(os.path.join(base, 'figures'), exist_ok=True)

    df = run()
    df.to_csv(os.path.join(base, 'results', 'exp2_scalability_requests.csv'), index=False)
    plot(df, os.path.join(base, 'figures', 'exp2_scalability_requests.png'))
    print(f"\n✓ Exp 2b complete.")
    print(df.to_string(index=False))
