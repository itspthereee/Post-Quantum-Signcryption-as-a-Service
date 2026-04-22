"""
Experiment 3b: Unsigncryption Scalability - Multiple Requests (Fair Comparison)
  X-axis: Number of requests (1, 5, 10, 25, 50, 100)
  Y-axis: Unsigncryption computation cost (ms)

PQSCAAS: N * unsigncryption operations (recipient-side)
Baselines: N * Client-side unsigncryption

Note: Unsigncryption does NOT have batching capability, so both measure sequential operations.

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
               'PQSCAAS': [], 'PQSCAAS_std': [],
               'Sinha2026': [], 'Sinha2026_std': [],
               'Yu2021': [], 'Yu2021_std': [],
               'Bai2025': [], 'Bai2025_std': []}

    # Pre-generate keys (sender and recipient)
    pk_r_kem, sk_r_kem, _ = cp.ml_kem_keygen()  # Recipient keys
    pk_u_sig, sk_u_sig, _ = cp.ml_dsa_keygen()  # Sender keys

    for num_reqs in REQUEST_COUNTS:
        print(f"\n[Exp 3b] Number of requests = {num_reqs}...")
        pq_runs, sinha_runs, yu_runs, bai_runs = [], [], [], []

        for trial in range(NUM_TRIALS):
            np.random.seed(trial * 43 + num_reqs)

            # ========== PQSCAAS: N unsigncryption operations ==========
            pq_total_ms = 0.0

            for i in range(num_reqs):
                msg = os.urandom(FILE_SIZE)
                desc, _ = pq.phase3_client_encrypt(msg)
                sc, _ = pq.phase4_server_signcrypt_single(desc, pk_r_kem, sk_u_sig)
                # Recipient unsigncrypts - phase5_decrypt returns only time (float)
                t_unsig = pq.phase5_decrypt(sc, pk_u_sig, sk_r_kem)
                pq_total_ms += t_unsig

            pq_runs.append(pq_total_ms)

            # ========== Baselines: N unsigncryption operations ==========
            sinha_total_ms = 0.0
            yu_total_ms = 0.0
            bai_total_ms = 0.0

            for i in range(num_reqs):
                sinha_total_ms += sinha2026.ntru_decrypt(FILE_SIZE)
                yu_total_ms += yu2021.lclss_decrypt(FILE_SIZE)
                bai_total_ms += bai2025.mlcloosc_decrypt(FILE_SIZE)

            sinha_runs.append(sinha_total_ms)
            yu_runs.append(yu_total_ms)
            bai_runs.append(bai_total_ms)

        results['num_requests'].append(num_reqs)
        results['PQSCAAS'].append(np.mean(pq_runs))
        results['PQSCAAS_std'].append(np.std(pq_runs))
        results['Sinha2026'].append(np.mean(sinha_runs))
        results['Sinha2026_std'].append(np.std(sinha_runs))
        results['Yu2021'].append(np.mean(yu_runs))
        results['Yu2021_std'].append(np.std(yu_runs))
        results['Bai2025'].append(np.mean(bai_runs))
        results['Bai2025_std'].append(np.std(bai_runs))

        print(f"  Requests={num_reqs:3d}: "
              f"PQSCAAS={np.mean(pq_runs):>8.2f}ms  |  "
              f"Baselines: Sinha={np.mean(sinha_runs):>8.2f}ms  Yu={np.mean(yu_runs):>8.2f}ms  Bai={np.mean(bai_runs):>8.2f}ms")

    return pd.DataFrame(results)


def plot(df, out_path):
    fig, ax = plt.subplots(figsize=(10, 6))
    for name, marker, ls, color in [
        ('PQSCAAS',   'o', '-',  '#2E86AB'),
        ('Bai2025',   's', '--', '#A23B72'),
        ('Sinha2026', '^', '-.', '#F18F01'),
        ('Yu2021',    'D', ':',  '#C73E1D')]:
        ax.errorbar(df['num_requests'], df[name], yerr=df[f'{name}_std'],
                    marker=marker, linestyle=ls, color=color,
                    label=name, markersize=8, linewidth=2.5, capsize=5, capthick=2)

    ax.set_xlabel('Number of Requests', fontsize=12, fontweight='bold')
    ax.set_ylabel('Computation cost (ms)', fontsize=12, fontweight='bold')
    ax.set_title('Exp 3b: Unsigncryption Scalability',
                 fontsize=13, fontweight='bold')
    ax.legend(loc='upper left', fontsize=11, framealpha=0.95)
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
    df.to_csv(os.path.join(base, 'results', 'exp3_unsigncryption_scalability.csv'), index=False)
    plot(df, os.path.join(base, 'figures', 'exp3_unsigncryption_scalability.png'))
    print(f"\n✓ Exp 3b complete.")
    print(df.to_string(index=False))

