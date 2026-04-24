"""
Plot all 8 experiment results from CSVs.

Expected CSV files in results/:
  exp1_phase4_vs_filesize.csv
  exp2_signcrypt_batch_vs_requests.csv
  exp3_phase5_vs_filesize.csv
  exp4_unsigncrypt_vs_requests.csv
  exp5_signcrypt_throughput.csv
  exp6_unsigncrypt_throughput.csv
  exp7_revocation.csv
  exp8_keygen_vs_users.csv

Outputs saved to figures/ as PNG and PDF.
"""
import os
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(BASE_DIR, 'results')
FIG_DIR = os.path.join(BASE_DIR, 'figures')
os.makedirs(FIG_DIR, exist_ok=True)


# Consistent colors / markers across all figs
COLORS = {
    'PQSCAAS':            '#1f77b4',
    'PQSCAAS_no_timeout': '#1f77b4',
    'PQSCAAS_with_timeout':'#17becf',
    'Lazy':               '#1f77b4',
    'NonLazy':            '#d62728',
    'Sinha2026':          '#ff7f0e',
    'Yu2021':             '#2ca02c',
    'Bai2025':            '#d62728',
}

MARKERS = {
    'PQSCAAS':            'o',
    'PQSCAAS_no_timeout': 's',
    'PQSCAAS_with_timeout':'o',
    'Lazy':               'o',
    'NonLazy':            's',
    'Sinha2026':          '^',
    'Yu2021':             'v',
    'Bai2025':            'd',
}

LABELS = {
    'PQSCAAS':             'PQSCAAS',
    'PQSCAAS_no_timeout':  'PQSCAAS (batch, no timeout)',
    'PQSCAAS_with_timeout':'PQSCAAS (batch, with timeout)',
    'Lazy':                'Lazy revocation',
    'NonLazy':             'Non-lazy revocation',
    'Sinha2026':           'Sinha 2026',
    'Yu2021':              'Yu 2021',
    'Bai2025':             'Bai 2025',
}


def setup_ax(ax, xlabel, ylabel, title=None, logx=True, logy=True):
    ax.set_xlabel(xlabel, fontsize=12)
    ax.set_ylabel(ylabel, fontsize=12)
    if title:
        ax.set_title(title, fontsize=13)
    if logx:
        ax.set_xscale('log')
    if logy:
        ax.set_yscale('log')
    ax.grid(True, which='both', alpha=0.3, linestyle='--')
    ax.legend(fontsize=10, loc='best')


def save(fig, name):
    png = os.path.join(FIG_DIR, f'{name}.png')
    pdf = os.path.join(FIG_DIR, f'{name}.pdf')
    fig.tight_layout()
    fig.savefig(png, dpi=150, bbox_inches='tight')
    fig.savefig(pdf, bbox_inches='tight')
    plt.close(fig)
    print(f"  -> {png}")


# ----------------------------------------------------------------------------
# Fig 1: Phase 4 Signcryption vs File Size
# ----------------------------------------------------------------------------
def plot_fig1():
    csv = os.path.join(RESULTS_DIR, 'exp1_phase4_vs_filesize.csv')
    if not os.path.exists(csv):
        print("[Fig 1] skipped — no data")
        return
    df = pd.read_csv(csv)

    fig, ax = plt.subplots(figsize=(8, 5.5))
    x = df['file_size_bytes'].values

    for scheme in ['PQSCAAS', 'Sinha2026', 'Yu2021', 'Bai2025']:
        y   = df[f'{scheme}_mean'].values
        err = df[f'{scheme}_std'].values
        ax.errorbar(x, y, yerr=err, label=LABELS[scheme],
                    marker=MARKERS[scheme], color=COLORS[scheme],
                    linewidth=2, markersize=8, capsize=4)

    # Custom X tick labels
    ax.set_xticks(x)
    ax.set_xticklabels(df['file_size_label'].values, rotation=0)
    setup_ax(ax, 'File size', 'Computation cost (ms)',
             title='Fig. 1: Phase 4 Signcryption vs File Size',
             logx=True, logy=True)
    # Override x tick formatter to show labels properly
    ax.xaxis.set_major_formatter(plt.FixedFormatter(df['file_size_label'].values))
    ax.xaxis.set_major_locator(plt.FixedLocator(x))
    save(fig, 'fig1_phase4_vs_filesize')


# ----------------------------------------------------------------------------
# Fig 2: Signcryption with Batching vs # Requests
# ----------------------------------------------------------------------------
def plot_fig2():
    csv = os.path.join(RESULTS_DIR, 'exp2_signcrypt_batch_vs_requests.csv')
    if not os.path.exists(csv):
        print("[Fig 2] skipped — no data")
        return
    df = pd.read_csv(csv)

    fig, ax = plt.subplots(figsize=(8, 5.5))
    x = df['n_requests'].values

    schemes = ['PQSCAAS_no_timeout', 'PQSCAAS_with_timeout',
               'Sinha2026', 'Yu2021', 'Bai2025']
    for s in schemes:
        y   = df[f'{s}_mean'].values
        err = df[f'{s}_std'].values
        ax.errorbar(x, y, yerr=err, label=LABELS[s],
                    marker=MARKERS[s], color=COLORS[s],
                    linewidth=2, markersize=7, capsize=3)

    setup_ax(ax, 'Number of requests', 'Total computation cost (ms)',
             title='Fig. 2: Signcryption with Batching vs # Requests',
             logx=True, logy=True)
    save(fig, 'fig2_signcrypt_batch_vs_requests')


# ----------------------------------------------------------------------------
# Fig 3: Phase 5 Unsigncryption vs File Size
# ----------------------------------------------------------------------------
def plot_fig3():
    csv = os.path.join(RESULTS_DIR, 'exp3_phase5_vs_filesize.csv')
    if not os.path.exists(csv):
        print("[Fig 3] skipped — no data")
        return
    df = pd.read_csv(csv)

    fig, ax = plt.subplots(figsize=(8, 5.5))
    x = df['file_size_bytes'].values

    for scheme in ['PQSCAAS', 'Sinha2026', 'Yu2021', 'Bai2025']:
        y   = df[f'{scheme}_mean'].values
        err = df[f'{scheme}_std'].values
        ax.errorbar(x, y, yerr=err, label=LABELS[scheme],
                    marker=MARKERS[scheme], color=COLORS[scheme],
                    linewidth=2, markersize=8, capsize=4)

    ax.set_xticks(x)
    ax.set_xticklabels(df['file_size_label'].values)
    setup_ax(ax, 'File size', 'Computation cost (ms)',
             title='Fig. 3: Phase 5 Unsigncryption vs File Size',
             logx=True, logy=True)
    ax.xaxis.set_major_formatter(plt.FixedFormatter(df['file_size_label'].values))
    ax.xaxis.set_major_locator(plt.FixedLocator(x))
    save(fig, 'fig3_phase5_vs_filesize')


# ----------------------------------------------------------------------------
# Fig 4: Unsigncryption (Sequential) vs # Requests
# ----------------------------------------------------------------------------
def plot_fig4():
    csv = os.path.join(RESULTS_DIR, 'exp4_unsigncrypt_vs_requests.csv')
    if not os.path.exists(csv):
        print("[Fig 4] skipped — no data")
        return
    df = pd.read_csv(csv)

    fig, ax = plt.subplots(figsize=(8, 5.5))
    x = df['n_requests'].values

    for s in ['PQSCAAS', 'Sinha2026', 'Yu2021', 'Bai2025']:
        y   = df[f'{s}_mean'].values
        err = df[f'{s}_std'].values
        ax.errorbar(x, y, yerr=err, label=LABELS[s],
                    marker=MARKERS[s], color=COLORS[s],
                    linewidth=2, markersize=7, capsize=3)

    setup_ax(ax, 'Number of requests', 'Total computation cost (ms)',
             title='Fig. 4: Unsigncryption (Sequential) vs # Requests',
             logx=True, logy=True)
    save(fig, 'fig4_unsigncrypt_vs_requests')


# ----------------------------------------------------------------------------
# Fig 5: Signcryption Throughput vs Concurrent Workload
# ----------------------------------------------------------------------------
def plot_fig5():
    csv = os.path.join(RESULTS_DIR, 'exp5_signcrypt_throughput.csv')
    if not os.path.exists(csv):
        print("[Fig 5] skipped — no data")
        return
    df = pd.read_csv(csv)

    fig, ax = plt.subplots(figsize=(8, 5.5))
    x = df['workload'].values

    schemes = ['PQSCAAS_no_timeout', 'PQSCAAS_with_timeout',
               'Sinha2026', 'Yu2021', 'Bai2025']
    for s in schemes:
        y   = df[f'{s}_mean'].values
        err = df[f'{s}_std'].values
        ax.errorbar(x, y, yerr=err, label=LABELS[s],
                    marker=MARKERS[s], color=COLORS[s],
                    linewidth=2, markersize=7, capsize=3)

    setup_ax(ax, 'Number of concurrent requests (workload)', 'Throughput (req/sec)',
             title='Fig. 5: Signcryption Throughput vs Workload',
             logx=True, logy=True)
    save(fig, 'fig5_signcrypt_throughput')


# ----------------------------------------------------------------------------
# Fig 6: Unsigncryption Throughput vs Concurrent Workload
# ----------------------------------------------------------------------------
def plot_fig6():
    csv = os.path.join(RESULTS_DIR, 'exp6_unsigncrypt_throughput.csv')
    if not os.path.exists(csv):
        print("[Fig 6] skipped — no data")
        return
    df = pd.read_csv(csv)

    fig, ax = plt.subplots(figsize=(8, 5.5))
    x = df['workload'].values

    for s in ['PQSCAAS', 'Sinha2026', 'Yu2021', 'Bai2025']:
        y   = df[f'{s}_mean'].values
        err = df[f'{s}_std'].values
        ax.errorbar(x, y, yerr=err, label=LABELS[s],
                    marker=MARKERS[s], color=COLORS[s],
                    linewidth=2, markersize=7, capsize=3)

    setup_ax(ax, 'Number of concurrent requests (workload)', 'Throughput (req/sec)',
             title='Fig. 6: Unsigncryption Throughput vs Workload',
             logx=True, logy=True)
    save(fig, 'fig6_unsigncrypt_throughput')


# ----------------------------------------------------------------------------
# Fig 7: Revocation — Lazy vs Non-Lazy
# ----------------------------------------------------------------------------
def plot_fig7():
    csv = os.path.join(RESULTS_DIR, 'exp7_revocation.csv')
    if not os.path.exists(csv):
        print("[Fig 7] skipped — no data")
        return
    df = pd.read_csv(csv)

    fig, ax = plt.subplots(figsize=(8, 5.5))
    x = df['n_revoked'].values

    for s in ['Lazy', 'NonLazy']:
        y   = df[f'{s}_mean'].values
        err = df[f'{s}_std'].values
        ax.errorbar(x, y, yerr=err, label=LABELS[s],
                    marker=MARKERS[s], color=COLORS[s],
                    linewidth=2, markersize=8, capsize=4)

    setup_ax(ax, 'Number of revoked users', 'Revocation time (ms)',
             title='Fig. 7: Key Revocation — Lazy vs Non-Lazy\n(Active users = 500,000)',
             logx=True, logy=True)
    save(fig, 'fig7_revocation')


# ----------------------------------------------------------------------------
# Fig 8: Phase 2 Key Generation vs Concurrent Users
# ----------------------------------------------------------------------------
def plot_fig8():
    csv = os.path.join(RESULTS_DIR, 'exp8_keygen_vs_users.csv')
    if not os.path.exists(csv):
        print("[Fig 8] skipped — no data")
        return
    df = pd.read_csv(csv)

    fig, ax = plt.subplots(figsize=(8, 5.5))
    x = df['n_users'].values

    for s in ['PQSCAAS', 'Sinha2026', 'Yu2021', 'Bai2025']:
        y   = df[f'{s}_mean'].values
        err = df[f'{s}_std'].values
        ax.errorbar(x, y, yerr=err, label=LABELS[s],
                    marker=MARKERS[s], color=COLORS[s],
                    linewidth=2, markersize=8, capsize=4)

    setup_ax(ax, 'Number of concurrent users', 'Computation cost (ms)',
             title='Fig. 8: Phase 2 Key Generation vs Concurrent Users',
             logx=True, logy=True)
    save(fig, 'fig8_keygen_vs_users')


def main():
    print("=" * 70)
    print("Plotting all 8 figures")
    print("=" * 70)

    print("\n[Fig 1]"); plot_fig1()
    print("\n[Fig 2]"); plot_fig2()
    print("\n[Fig 3]"); plot_fig3()
    print("\n[Fig 4]"); plot_fig4()
    print("\n[Fig 5]"); plot_fig5()
    print("\n[Fig 6]"); plot_fig6()
    print("\n[Fig 7]"); plot_fig7()
    print("\n[Fig 8]"); plot_fig8()

    print("\nAll figures saved to", FIG_DIR)


if __name__ == '__main__':
    main()
