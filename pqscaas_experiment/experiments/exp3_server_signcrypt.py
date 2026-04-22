"""
Experiment 3: Server-Side Signcryption (PQSCAAS-only)
  X-axis: File size (1KB, 10KB, 100KB, 1MB, 10MB, 100MB)
  Y-axis: Server computation cost (ms)

PQSCAAS uniquely has a server component. Baselines do not, so this
experiment shows PQSCAAS alone.

Key insight: Server signcryption cost is NEARLY CONSTANT across file
sizes because the server only operates on:
  - C_KEM (1088 bytes)
  - W (32 bytes)
  - AAD (small)
  - H(CT) (32 bytes)
  - sigma (ML-DSA signature)

The file itself (CT) is already encrypted by the client — the server
never touches the full payload, only its hash.
"""

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pqscaas import scheme as pq
from pqscaas import crypto_primitives as cp


FILE_SIZES = [
    (1 * 1024,          '1 KB'),
    (10 * 1024,         '10 KB'),
    (100 * 1024,        '100 KB'),
    (1024 * 1024,       '1 MB'),
    (10 * 1024 * 1024,  '10 MB'),
    (100 * 1024 * 1024, '100 MB'),
]
NUM_TRIALS = 50
BATCH_SIZE = 50  # Default batch size for PQSCAAS


def run():
    results = {'file_size_bytes': [], 'file_size_label': [],
               'PQSCAAS_server': [], 'PQSCAAS_server_std': []}

    # Pre-generate recipient and user keys (not counted in timing)
    pk_r_kem, _, _ = cp.ml_kem_keygen()
    _, sk_u_sig, _ = cp.ml_dsa_keygen()

    for size, label in FILE_SIZES:
        print(f"[Exp 3] File size = {label}...")
        runs = []

        for trial in range(NUM_TRIALS):
            np.random.seed(trial * 23 + size % 1000)
            msg = os.urandom(size)

            # Client encrypts first (we need the descriptor for the server)
            desc, _ = pq.phase3_client_encrypt(msg)

            # Server signcrypts — this is what we measure
            _, t = pq.phase4_server_signcrypt_single(desc, pk_r_kem, sk_u_sig)
            runs.append(t)

        results['file_size_bytes'].append(size)
        results['file_size_label'].append(label)
        results['PQSCAAS_server'].append(np.mean(runs))
        results['PQSCAAS_server_std'].append(np.std(runs))

        print(f"  PQSCAAS server: {np.mean(runs):>10.4f} ms (std={np.std(runs):.4f})")

    return pd.DataFrame(results)


def plot(df, out_path):
    fig, ax = plt.subplots(figsize=(8, 5.5))
    ax.errorbar(df['file_size_bytes'], df['PQSCAAS_server'],
                yerr=df['PQSCAAS_server_std'],
                marker='o', linestyle='-', color='#2E86AB',
                label='PQSCAAS Server', markersize=8, linewidth=2,
                capsize=4, capthick=1.5)
    ax.set_xscale('log')
    ax.set_xlabel('File size', fontsize=12)
    ax.set_ylabel('Server computation cost (ms)', fontsize=12)
    ax.set_title('Exp 3: Server-Side Signcryption Cost (PQSCAAS)',
                 fontsize=13, fontweight='bold')
    ax.legend(loc='upper right', fontsize=11)
    ax.grid(True, which='both', ls='-', alpha=0.3)
    ax.set_xticks(df['file_size_bytes'])
    ax.set_xticklabels(df['file_size_label'])

    # Add note showing it's approximately constant
    mean_val = df['PQSCAAS_server'].mean()
    ax.axhline(y=mean_val, color='gray', linestyle=':', alpha=0.5,
               label=f'Mean ≈ {mean_val:.2f} ms')
    ax.legend(loc='upper right', fontsize=11)

    plt.tight_layout()
    plt.savefig(out_path, dpi=200, bbox_inches='tight')
    plt.savefig(out_path.replace('.png', '.pdf'), bbox_inches='tight')
    plt.close()


if __name__ == "__main__":
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.makedirs(os.path.join(base, 'results'), exist_ok=True)
    os.makedirs(os.path.join(base, 'figures'), exist_ok=True)

    df = run()
    df.to_csv(os.path.join(base, 'results', 'exp3_server_signcrypt.csv'), index=False)
    plot(df, os.path.join(base, 'figures', 'exp3_server_signcrypt.png'))
    print(f"\n✓ Exp 3 complete.")
    print(df.to_string(index=False))
