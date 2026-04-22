"""
Experiment 1: Phase 2 Key Generation
  X-axis: Number of concurrent users (N = 100, 500, 1K, 5K, 10K)
  Y-axis: Total computation cost (ms)
"""

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pqscaas import scheme as pq
from baselines import sinha2026, yu2021, bai2025


N_VALUES = [100, 500, 1000, 5000, 10000]
NUM_TRIALS = 50

PQSCAAS_BATCH_SIZE = 64
PQSCAAS_NUM_ENCLAVES = 8


def run():
    results = {'N': [], 'PQSCAAS': [], 'PQSCAAS_std': [],
               'Sinha2026': [], 'Sinha2026_std': [],
               'Yu2021': [], 'Yu2021_std': [],
               'Bai2025': [], 'Bai2025_std': []}

    for n in N_VALUES:
        print(f"[Exp 1] N = {n:>6} users...")
        pq_runs, sinha_runs, yu_runs, bai_runs = [], [], [], []
        for trial in range(NUM_TRIALS):
            np.random.seed(trial * 1000 + n)

            pq_runs.append(pq.phase2_total_keygen_cost(n, PQSCAAS_BATCH_SIZE, PQSCAAS_NUM_ENCLAVES))

            # For large N, estimate from bootstrap of 100 samples to save time
            n_sample = min(100, n)
            sinha_mean = np.mean([sinha2026.ntru_per_user_keygen() for _ in range(n_sample)])
            yu_mean = np.mean([yu2021.lclss_per_user_keygen() for _ in range(n_sample)])
            bai_mean = np.mean([bai2025.mlcloosc_per_user_keygen() for _ in range(n_sample)])

            sinha_runs.append(sinha_mean * n)
            yu_runs.append(yu_mean * n)
            bai_runs.append(bai_mean * n)

        results['N'].append(n)
        results['PQSCAAS'].append(np.mean(pq_runs))
        results['PQSCAAS_std'].append(np.std(pq_runs))
        results['Sinha2026'].append(np.mean(sinha_runs))
        results['Sinha2026_std'].append(np.std(sinha_runs))
        results['Yu2021'].append(np.mean(yu_runs))
        results['Yu2021_std'].append(np.std(yu_runs))
        results['Bai2025'].append(np.mean(bai_runs))
        results['Bai2025_std'].append(np.std(bai_runs))

        print(f"  PQSCAAS:   {np.mean(pq_runs):>12.2f} ms")
        print(f"  Bai2025:   {np.mean(bai_runs):>12.2f} ms")
        print(f"  Sinha2026: {np.mean(sinha_runs):>12.2f} ms")
        print(f"  Yu2021:    {np.mean(yu_runs):>12.2f} ms")

    return pd.DataFrame(results)


def plot(df, out_path):
    fig, ax = plt.subplots(figsize=(8, 5.5))
    for name, marker, ls, color in [
        ('PQSCAAS',   'o', '-',  '#2E86AB'),
        ('Bai2025',   's', '--', '#A23B72'),
        ('Sinha2026', '^', '-.', '#F18F01'),
        ('Yu2021',    'D', ':',  '#C73E1D')]:
        ax.errorbar(df['N'], df[name], yerr=df[f'{name}_std'],
                    marker=marker, linestyle=ls, color=color,
                    label=name, markersize=8, linewidth=2, capsize=4, capthick=1.5)
    ax.set_xscale('log'); ax.set_yscale('log')
    ax.set_xlabel('Number of concurrent users (N)', fontsize=12)
    ax.set_ylabel('Total computation cost (ms)', fontsize=12)
    ax.set_title('Exp 1: Key Generation Cost vs. Number of Users',
                 fontsize=13, fontweight='bold')
    ax.legend(loc='upper left', fontsize=11)
    ax.grid(True, which='both', ls='-', alpha=0.3)
    ax.set_xticks(N_VALUES)
    ax.set_xticklabels([f'{n:,}' if n < 1000 else f'{n//1000}K' for n in N_VALUES])
    plt.tight_layout()
    plt.savefig(out_path, dpi=200, bbox_inches='tight')
    plt.savefig(out_path.replace('.png', '.pdf'), bbox_inches='tight')
    plt.close()


if __name__ == "__main__":
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.makedirs(os.path.join(base, 'results'), exist_ok=True)
    os.makedirs(os.path.join(base, 'figures'), exist_ok=True)

    df = run()
    df.to_csv(os.path.join(base, 'results', 'exp1_keygen.csv'), index=False)
    plot(df, os.path.join(base, 'figures', 'exp1_keygen.png'))
    print(f"\n✓ Exp 1 complete. Saved to results/ and figures/")
    print(df.to_string(index=False))
