"""
Experiment 5: End-to-End Encryption (Client + Server Combined)
  X-axis: File size (1KB, 10KB, 100KB, 1MB, 10MB, 100MB)
  Y-axis: Total computation cost (ms)

Shows that even when PQSCAAS accounts for BOTH client AND server
computation, it is still competitive (or better) than baselines
that only do client-side signcryption.

PQSCAAS total = client AEAD + server signcryption
Baselines total = client full signcryption (no server)
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


FILE_SIZES = [
    (1 * 1024,          '1 KB'),
    (10 * 1024,         '10 KB'),
    (100 * 1024,        '100 KB'),
    (1024 * 1024,       '1 MB'),
    (10 * 1024 * 1024,  '10 MB'),
    (100 * 1024 * 1024, '100 MB'),
]
NUM_TRIALS = 50


def run():
    results = {'file_size_bytes': [], 'file_size_label': [],
               'PQSCAAS_total': [], 'PQSCAAS_total_std': [],
               'Sinha2026': [], 'Sinha2026_std': [],
               'Yu2021': [], 'Yu2021_std': [],
               'Bai2025': [], 'Bai2025_std': []}

    # Pre-generate keys for server
    pk_r_kem, _, _ = cp.ml_kem_keygen()
    _, sk_u_sig, _ = cp.ml_dsa_keygen()

    for size, label in FILE_SIZES:
        print(f"[Exp 5] File size = {label}...")
        pq_runs, sinha_runs, yu_runs, bai_runs = [], [], [], []

        for trial in range(NUM_TRIALS):
            np.random.seed(trial * 41 + size % 1000)
            msg = os.urandom(size)

            # PQSCAAS: client + server total
            desc, t_client = pq.phase3_client_encrypt(msg)
            _, t_server = pq.phase4_server_signcrypt_single(desc, pk_r_kem, sk_u_sig)
            pq_runs.append(t_client + t_server)

            # Baselines: client-only signcrypt
            sinha_runs.append(sinha2026.ntru_client_signcrypt(msg))
            yu_runs.append(yu2021.lclss_client_signcrypt(msg))
            bai_runs.append(bai2025.mlcloosc_client_signcrypt(msg))

        results['file_size_bytes'].append(size)
        results['file_size_label'].append(label)
        results['PQSCAAS_total'].append(np.mean(pq_runs))
        results['PQSCAAS_total_std'].append(np.std(pq_runs))
        results['Sinha2026'].append(np.mean(sinha_runs))
        results['Sinha2026_std'].append(np.std(sinha_runs))
        results['Yu2021'].append(np.mean(yu_runs))
        results['Yu2021_std'].append(np.std(yu_runs))
        results['Bai2025'].append(np.mean(bai_runs))
        results['Bai2025_std'].append(np.std(bai_runs))

        print(f"  PQSCAAS total: {np.mean(pq_runs):>10.3f} ms")
        print(f"  Bai2025:       {np.mean(bai_runs):>10.3f} ms")
        print(f"  Sinha2026:     {np.mean(sinha_runs):>10.3f} ms")
        print(f"  Yu2021:        {np.mean(yu_runs):>10.3f} ms")

    return pd.DataFrame(results)


def plot(df, out_path):
    fig, ax = plt.subplots(figsize=(8, 5.5))
    for name, label, marker, ls, color in [
        ('PQSCAAS_total', 'PQSCAAS (Client+Server)', 'o', '-',  '#2E86AB'),
        ('Bai2025',       'Bai2025',                 's', '--', '#A23B72'),
        ('Sinha2026',     'Sinha2026',               '^', '-.', '#F18F01'),
        ('Yu2021',        'Yu2021',                  'D', ':',  '#C73E1D')]:
        ax.errorbar(df['file_size_bytes'], df[name], yerr=df[f'{name}_std'],
                    marker=marker, linestyle=ls, color=color,
                    label=label, markersize=8, linewidth=2, capsize=4, capthick=1.5)
    ax.set_xscale('log'); ax.set_yscale('log')
    ax.set_xlabel('File size', fontsize=12)
    ax.set_ylabel('Total computation cost (ms)', fontsize=12)
    ax.set_title('Exp 5: End-to-End Encryption Cost (Client + Server)',
                 fontsize=13, fontweight='bold')
    ax.legend(loc='upper left', fontsize=11)
    ax.grid(True, which='both', ls='-', alpha=0.3)
    ax.set_xticks(df['file_size_bytes'])
    ax.set_xticklabels(df['file_size_label'])
    plt.tight_layout()
    plt.savefig(out_path, dpi=200, bbox_inches='tight')
    plt.savefig(out_path.replace('.png', '.pdf'), bbox_inches='tight')
    plt.close()


if __name__ == "__main__":
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.makedirs(os.path.join(base, 'results'), exist_ok=True)
    os.makedirs(os.path.join(base, 'figures'), exist_ok=True)

    df = run()
    df.to_csv(os.path.join(base, 'results', 'exp5_end_to_end.csv'), index=False)
    plot(df, os.path.join(base, 'figures', 'exp5_end_to_end.png'))
    print(f"\n✓ Exp 5 complete.")
    print(df.to_string(index=False))
