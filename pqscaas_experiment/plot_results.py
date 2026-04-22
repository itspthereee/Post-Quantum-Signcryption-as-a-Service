from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Iterable

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import pandas as pd


ROOT = Path(__file__).resolve().parent
DEFAULT_RESULTS_DIR = ROOT / "results"
DEFAULT_FIGURES_DIR = ROOT / "figures"


def configure_plot_style() -> None:
    plt.rcParams.update(
        {
            "figure.dpi": 160,
            "savefig.dpi": 220,
            "axes.titlesize": 14,
            "axes.labelsize": 12,
            "legend.fontsize": 10,
            "xtick.labelsize": 10,
            "ytick.labelsize": 10,
            "font.family": "DejaVu Sans",
            "axes.spines.top": False,
            "axes.spines.right": False,
            "axes.grid": True,
            "grid.alpha": 0.22,
            "grid.linestyle": "--",
        }
    )


def ensure_output_dir(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)


def clear_previous_figures(output_dir: Path) -> None:
    if not output_dir.exists():
        return

    for path in output_dir.iterdir():
        if path.is_file() and path.suffix.lower() in {".png", ".pdf"}:
            path.unlink()


def save_figure(fig: plt.Figure, output_dir: Path, stem: str) -> None:
    png_path = output_dir / f"{stem}.png"
    pdf_path = output_dir / f"{stem}.pdf"
    fig.tight_layout()
    fig.savefig(png_path, bbox_inches="tight")
    fig.savefig(pdf_path, bbox_inches="tight")
    plt.close(fig)


def load_csv(results_dir: Path, filename: str) -> pd.DataFrame:
    path = results_dir / filename
    if not path.exists():
        raise FileNotFoundError(f"Missing result file: {path}")
    return pd.read_csv(path)


def format_file_size_labels(values: Iterable[int]) -> list[str]:
    labels: list[str] = []
    for value in values:
        if value >= 1024 * 1024:
            labels.append(f"{value // (1024 * 1024)} MB")
        elif value >= 1024:
            labels.append(f"{value // 1024} KB")
        else:
            labels.append(f"{value} B")
    return labels


def plot_exp1_keygen(results_dir: Path, output_dir: Path) -> None:
    df = load_csv(results_dir, "exp1_keygen.csv")
    fig, ax = plt.subplots(figsize=(8.6, 5.2))

    x = df["N"].astype(float)
    schemes = [
        ("PQSCAAS", "PQSCAAS_std", "#B75BA0"),
        ("Sinha2026", "Sinha2026_std", "#D9480F"),
        ("Yu2021", "Yu2021_std", "#4682B4"),
        ("Bai2025", "Bai2025_std", "#5C940D"),
    ]

    for scheme, std_col, color in schemes:
        ax.errorbar(
            x,
            df[scheme],
            yerr=df[std_col],
            label=scheme,
            marker="o",
            linewidth=2.2,
            markersize=5.5,
            capsize=3,
            color=color,
        )

    ax.set_title("Experiment 1: Key Generation Cost")
    ax.set_xlabel("Number of users (N)")
    ax.set_ylabel("Time (ms)")
    ax.set_xscale("log")
    ax.set_xticks(x.tolist())
    ax.get_xaxis().set_major_formatter(plt.ScalarFormatter())
    ax.legend(ncol=2, frameon=False)
    save_figure(fig, output_dir, "exp1_keygen")


def plot_exp2_client_encrypt(results_dir: Path, output_dir: Path) -> None:
    df = load_csv(results_dir, "exp2_client_encrypt.csv")
    fig, ax = plt.subplots(figsize=(8.6, 5.2))

    x = df["file_size_bytes"].astype(float)
    labels = df["file_size_label"].tolist()
    schemes = [
        ("PQSCAAS", "PQSCAAS_std", "#B75BA0"),
        ("Sinha2026", "Sinha2026_std", "#D9480F"),
        ("Yu2021", "Yu2021_std", "#4682B4"),
        ("Bai2025", "Bai2025_std", "#5C940D"),
    ]

    for scheme, std_col, color in schemes:
        ax.errorbar(
            x,
            df[scheme],
            yerr=df[std_col],
            label=scheme,
            marker="o",
            linewidth=2.2,
            markersize=5.5,
            capsize=3,
            color=color,
        )

    ax.set_title("Experiment 2: Client Encryption Cost")
    ax.set_xlabel("File size")
    ax.set_ylabel("Time (ms)")
    ax.set_xscale("log")
    ax.set_xticks(x.tolist())
    ax.set_xticklabels(labels)
    ax.legend(ncol=2, frameon=False)
    save_figure(fig, output_dir, "exp2_client_encrypt")


def plot_exp3_server_signcrypt(results_dir: Path, output_dir: Path) -> None:
    df = load_csv(results_dir, "exp3_server_signcrypt.csv")
    fig, ax = plt.subplots(figsize=(8.2, 4.8))

    x = df["file_size_bytes"].astype(float)
    ax.errorbar(
        x,
        df["PQSCAAS_server"],
        yerr=df["PQSCAAS_server_std"],
        label="PQSCAAS server",
        marker="o",
        linewidth=2.4,
        markersize=5.5,
        capsize=3,
        color="#B75BA0",
    )
    ax.set_title("Experiment 3: Server-Side Signcryption")
    ax.set_xlabel("File size")
    ax.set_ylabel("Time (ms)")
    ax.set_xscale("log")
    ax.set_xticks(x.tolist())
    ax.set_xticklabels(df["file_size_label"].tolist())
    save_figure(fig, output_dir, "exp3_server_signcrypt")


def plot_exp4_server_load(results_dir: Path, output_dir: Path) -> None:
    df = load_csv(results_dir, "exp4_server_load.csv")
    fig, ax = plt.subplots(figsize=(8.2, 4.8))

    x = df["lambda"].astype(float)
    ax.errorbar(
        x,
        df["PQSCAAS_per_req"],
        yerr=df["PQSCAAS_per_req_std"],
        label="PQSCAAS per request",
        marker="o",
        linewidth=2.4,
        markersize=5.5,
        capsize=3,
        color="#B75BA0",
    )
    ax.set_title("Experiment 4: Server Load")
    ax.set_xlabel("Arrival rate (req/s)")
    ax.set_ylabel("Per-request cost (ms)")
    ax.set_xscale("log")
    ax.set_xticks(x.tolist())
    ax.get_xaxis().set_major_formatter(plt.ScalarFormatter())
    save_figure(fig, output_dir, "exp4_server_load")


def plot_exp5_end_to_end(results_dir: Path, output_dir: Path) -> None:
    df = load_csv(results_dir, "exp5_end_to_end.csv")
    fig, ax = plt.subplots(figsize=(8.6, 5.2))

    x = df["file_size_bytes"].astype(float)
    schemes = [
        ("PQSCAAS_total", "PQSCAAS_total_std", "#B75BA0"),
        ("Sinha2026", "Sinha2026_std", "#D9480F"),
        ("Yu2021", "Yu2021_std", "#4682B4"),
        ("Bai2025", "Bai2025_std", "#5C940D"),
    ]

    for scheme, std_col, color in schemes:
        ax.errorbar(
            x,
            df[scheme],
            yerr=df[std_col],
            label=scheme.replace("_total", ""),
            marker="o",
            linewidth=2.2,
            markersize=5.5,
            capsize=3,
            color=color,
        )

    ax.set_title("Experiment 5: End-to-End Cost")
    ax.set_xlabel("File size")
    ax.set_ylabel("Time (ms)")
    ax.set_xscale("log")
    ax.set_xticks(x.tolist())
    ax.set_xticklabels(df["file_size_label"].tolist())
    ax.legend(ncol=2, frameon=False)
    save_figure(fig, output_dir, "exp5_end_to_end")


def plot_exp6_decrypt(results_dir: Path, output_dir: Path) -> None:
    df = load_csv(results_dir, "exp6_decrypt.csv")
    fig, ax = plt.subplots(figsize=(8.6, 5.2))

    x = df["file_size_bytes"].astype(float)
    schemes = [
        ("PQSCAAS", "PQSCAAS_std", "#B75BA0"),
        ("Sinha2026", "Sinha2026_std", "#D9480F"),
        ("Yu2021", "Yu2021_std", "#4682B4"),
        ("Bai2025", "Bai2025_std", "#5C940D"),
    ]

    for scheme, std_col, color in schemes:
        ax.errorbar(
            x,
            df[scheme],
            yerr=df[std_col],
            label=scheme,
            marker="o",
            linewidth=2.2,
            markersize=5.5,
            capsize=3,
            color=color,
        )

    ax.set_title("Experiment 6: Recipient Decryption Cost")
    ax.set_xlabel("File size")
    ax.set_ylabel("Time (ms)")
    ax.set_xscale("log")
    ax.set_xticks(x.tolist())
    ax.set_xticklabels(df["file_size_label"].tolist())
    ax.legend(ncol=2, frameon=False)
    save_figure(fig, output_dir, "exp6_decrypt")


def plot_all(results_dir: Path, output_dir: Path) -> None:
    configure_plot_style()
    ensure_output_dir(output_dir)
    clear_previous_figures(output_dir)

    plot_exp1_keygen(results_dir, output_dir)
    plot_exp2_client_encrypt(results_dir, output_dir)
    plot_exp3_server_signcrypt(results_dir, output_dir)
    plot_exp4_server_load(results_dir, output_dir)
    plot_exp5_end_to_end(results_dir, output_dir)
    plot_exp6_decrypt(results_dir, output_dir)


def list_generated_figures(output_dir: Path) -> list[Path]:
    return sorted(
        path
        for path in output_dir.iterdir()
        if path.is_file() and path.suffix.lower() in {".png", ".pdf"}
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Plot PQSCAAS experiment results.")
    parser.add_argument(
        "--results-dir",
        type=Path,
        default=DEFAULT_RESULTS_DIR,
        help="Directory containing experiment CSV files.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_FIGURES_DIR,
        help="Directory where plots will be written.",
    )
    parser.add_argument(
        "--open-output-dir",
        action="store_true",
        help="Open the output directory after the figures are generated.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    plot_all(args.results_dir, args.output_dir)
    generated_files = list_generated_figures(args.output_dir)
    print(f"Saved {len(generated_files)} figure files to {args.output_dir}")
    for path in generated_files:
        print(f"  - {path}")

    if args.open_output_dir:
        os.startfile(args.output_dir)


if __name__ == "__main__":
    main()