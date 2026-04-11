"""
exp3_server.py — คนที่ 3 : Signcryption — Server / Enclave Side
=================================================================
รับผิดชอบ: วัด computation cost ของ Server-side Signcryption

NOTE: L-CLSS, NTRU-IBLRSCS, MLCLOOSC ไม่มี server-side phase
      มีแค่ PQSCAAS เท่านั้นที่ offload PQ ops ไป TEE enclave

Formula:
  L-CLSS        : — (N/A)
  NTRU-IBLRSCS  : — (N/A)
  MLCLOOSC      : — (N/A, offline phase ยังอยู่บน sender device)
  PQSCAAS       : (T_enter + T_exit)/B + T_kem + T_dsa + T_kdf

Graph: เปรียบเทียบ PQSCAAS server cost vs effective total cost ของ scheme อื่น
       เพื่อแสดงว่าแม้แต่ server cost ของ PQSCAAS ก็ยังต่ำกว่า

รัน: python exp3_server.py
ผลลัพธ์: results/server_results.csv + results/server_plot.png
"""

import random
import statistics
import os
import json
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import pandas as pd
from config import *

random.seed(SEED)
os.makedirs("results", exist_ok=True)

PHASE = "Signcryption (Server/Enclave)"

def jitter(cost):
    return max(0, random.gauss(cost, cost * NOISE))

# ─────────────────────────────────────────────────────────────
def server_pqscaas(batch_size=B):
    """
    PQSCAAS (Ours) — TEE Enclave Batch Processing
    Steps:
      1. s_u = Unseal(S_u)                             : ~0 (AES)
      2. (C_KEM, K') ← ML-KEM.Encap(PK^KEM_r)         : T_kem
      3. K_bind = KDF(K || K')                         : T_kdf
      4. sigma ← ML-DSA.Sign(H(CT)||C_KEM||AAD)        : T_dsa
      ★ amortize T_enter+T_exit over batch B            : /B
    Total per request: (T_enter+T_exit)/B + T_kem + T_dsa + T_kdf
    """
    results = []
    for _ in range(ROUNDS):
        amortized = (jitter(T_ENTER) + jitter(T_EXIT)) / batch_size
        cost = amortized + jitter(T_KEM) + jitter(T_DSA) + jitter(T_KDF)
        results.append(cost)
    return results

def server_none():
    """ไม่มี server phase — return 0 ทุก round"""
    return [0.0] * ROUNDS

# ─────────────────────────────────────────────────────────────
def run():
    print(f"{'='*60}")
    print(f"  Experiment 3 — {PHASE}")
    print(f"  Rounds={ROUNDS}, n={N}, q={Q}, Batch B={B}")
    print(f"{'='*60}\n")

    data = {
        "L-CLSS":        server_none(),
        "NTRU-IBLRSCS":  server_none(),
        "MLCLOOSC":      server_none(),
        "PQSCAAS (Ours)":server_pqscaas(),
    }

    rows = []
    for scheme, values in data.items():
        m = statistics.mean(values)
        s = statistics.stdev(values) if any(v > 0 for v in values) else 0.0
        rows.append({"Scheme": scheme, "Phase": PHASE,
                     "Mean (ms)": round(m, 5), "Std Dev": round(s, 6),
                     "Rounds": len(values)})
        label = f"mean={m:.5f} ms   std={s:.6f}" if m > 0 else "N/A (no server phase)"
        print(f"  {scheme:<20} {label}")

    df = pd.DataFrame(rows)
    df.to_csv("results/server_results.csv", index=False)
    print(f"\n  Saved: results/server_results.csv")

    # ── Plot 1: batch size sensitivity ────────────────────────
    batch_sizes = [1, 4, 8, 16, 32, 64, 128]
    batch_means = []
    for bs in batch_sizes:
        vals = server_pqscaas(batch_size=bs)
        batch_means.append(statistics.mean(vals))

    fig, axes = plt.subplots(1, 2, figsize=(13, 5))

    axes[0].plot(batch_sizes, batch_means,
                 marker="o", color="#1D9E75", linewidth=2, markersize=6)
    axes[0].set_title(
        f"PQSCAAS Server Cost vs Batch Size B\n"
        f"(n={N}, q={Q}, {ROUNDS} rounds)",
        fontsize=11, fontweight="bold")
    axes[0].set_xlabel("Batch size B", fontsize=10)
    axes[0].set_ylabel("Average cost per request (ms)", fontsize=10)
    axes[0].yaxis.grid(True, linestyle="--", alpha=0.5)
    axes[0].set_axisbelow(True)
    axes[0].spines[["top","right"]].set_visible(False)
    for bx, by in zip(batch_sizes, batch_means):
        axes[0].annotate(f"B={bx}\n{by:.3f}ms",
                         xy=(bx, by), xytext=(6, 6),
                         textcoords="offset points", fontsize=7.5,
                         color="#085041")

    # ── Plot 2: server cost vs total cost of others ───────────
    other_totals = {
        "L-CLSS\n(full signcrypt)":
            statistics.mean([3*jitter(T_MUL)+2*jitter(T_ADD)+2*jitter(T_H)
                             for _ in range(ROUNDS)]),
        "NTRU-IBLRSCS\n(full signcrypt)":
            statistics.mean([2*ALPHA*jitter(T_S)+(ALPHA+1)*jitter(T_MUL)+
                             2*jitter(T_RS)+jitter(T_H)
                             for _ in range(ROUNDS)]),
        "MLCLOOSC\n(T_off+T_on)":
            statistics.mean([2*jitter(T_PVM)+2*jitter(T_PVA)+jitter(T_H)+
                             jitter(T_PVM)+jitter(T_PVA)
                             for _ in range(ROUNDS)]),
        "PQSCAAS\nServer only":
            statistics.mean(server_pqscaas()),
    }

    labels = list(other_totals.keys())
    vals   = list(other_totals.values())
    bar_colors = [COLORS[0], COLORS[1], COLORS[2], COLORS[3]]

    bars = axes[1].bar(labels, vals, color=bar_colors, width=0.5, zorder=3)
    axes[1].set_title(
        "PQSCAAS Server vs Sender Cost of Others\n"
        "(even server-only cost is competitive)",
        fontsize=11, fontweight="bold")
    axes[1].set_ylabel("Average cost (ms)", fontsize=10)
    axes[1].yaxis.grid(True, linestyle="--", alpha=0.5, zorder=0)
    axes[1].set_axisbelow(True)
    axes[1].spines[["top","right"]].set_visible(False)
    for bar, v in zip(bars, vals):
        axes[1].text(bar.get_x()+bar.get_width()/2,
                     bar.get_height()+max(vals)*0.01,
                     f"{v:.4f}", ha="center", va="bottom", fontsize=9)
    bars[-1].set_edgecolor("#085041")
    bars[-1].set_linewidth(2.5)

    plt.tight_layout()
    plt.savefig("results/server_plot.png", dpi=150, bbox_inches="tight")
    print(f"  Saved: results/server_plot.png")

    with open("results/server_raw.json", "w") as f:
        json.dump({k: v for k, v in data.items()}, f)
    print(f"  Saved: results/server_raw.json\n")

if __name__ == "__main__":
    run()
