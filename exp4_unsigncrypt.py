"""
exp4_unsigncrypt.py — คนที่ 4 : Unsigncryption — Receiver Side
================================================================
รับผิดชอบ: วัด computation cost ของ Unsigncryption ฝั่ง receiver

Formula:
  L-CLSS        : 2*T_mul + T_add + T_h
  NTRU-IBLRSCS  : alpha*T_mul + T_sym + T_h
  MLCLOOSC      : T_pvm + T_pva + T_h
  PQSCAAS       : T_dsa + T_kem + T_sym + T_h

รัน: python exp4_unsigncrypt.py
ผลลัพธ์: results/unsigncrypt_results.csv + results/unsigncrypt_plot.png
"""

import random
import statistics
import os
import json
import matplotlib.pyplot as plt
import pandas as pd
from config import *

random.seed(SEED)
os.makedirs("results", exist_ok=True)

PHASE = "Unsigncryption (Receiver)"

def jitter(cost):
    return max(0, random.gauss(cost, cost * NOISE))

# ─────────────────────────────────────────────────────────────
def unsigncrypt_lclss():
    """
    L-CLSS (Yu et al. 2021)
    Steps:
      1. m = [v - v1*t_V - v2*d_V] mod q mod 2  : 2*T_mul + T_add
      2. h' = H2([A A 0; 0 BS BS]*eps - [...]*h) : T_h
      3. check eps <= 2sigma*sqrt(3l) and h=h'   : ~0
    Total: 2*T_mul + T_add + T_h
    """
    results = []
    for _ in range(ROUNDS):
        cost = 2*jitter(T_MUL) + jitter(T_ADD) + jitter(T_H)
        results.append(cost)
    return results

def unsigncrypt_ntru(alpha=ALPHA):
    """
    NTRU-IBLRSCS (Sinha et al. 2026)
    Steps:
      1. f = w - v*s2                            : T_mul (poly mul)
      2. k = floor(f * 2/q)                      : ~0
      3. m = c XOR G4(k || event)                : T_sym
      4. v' = G3(sum(z_i + z'_i*g + p - J*v))   : alpha*T_mul + T_h
      5. check ||z_i|| <= 2*sigma*n, v'=v        : ~0
    Total: alpha*T_mul + T_sym + T_h
    """
    results = []
    for _ in range(ROUNDS):
        cost = alpha*jitter(T_MUL) + jitter(T_SYM) + jitter(T_H)
        results.append(cost)
    return results

def unsigncrypt_mlcloosc():
    """
    MLCLOOSC (Bai et al. 2025)
    Steps:
      1. m_bar' = (2/q-1)(c3 - c1^T*d_R - c2^T*s_R)  : T_pvm
      2. w'1 = [Id|A'|(GH-BH)]*z1 - h*H1(IDS||mpk)    : T_pva
      3. w'2 = HighBits(CS*z2 - h*b_S)                 : T_pva (~0)
      4. check h = H2(m'||w'1||w'2)                    : T_h
    Total: T_pvm + T_pva + T_h
    """
    results = []
    for _ in range(ROUNDS):
        cost = jitter(T_PVM) + jitter(T_PVA) + jitter(T_H)
        results.append(cost)
    return results

def unsigncrypt_pqscaas():
    """
    PQSCAAS (Ours)
    Steps:
      1. Verify(PK^SIG_u, sigma) = 1          : T_dsa  (fail-fast before decrypt)
      2. K' = ML-KEM.Decap(SK^KEM_r, C_KEM)  : T_kem
      3. K  = KDF(K' || Context)              : T_kdf (~T_h)
      4. M  = AEAD.Dec(K, CT, AAD)            : T_sym  (O(|M|))
    Total: T_dsa + T_kem + T_sym + T_h
    """
    results = []
    for _ in range(ROUNDS):
        cost = jitter(T_DSA) + jitter(T_KEM) + jitter(T_SYM) + jitter(T_H)
        results.append(cost)
    return results

# ─────────────────────────────────────────────────────────────
def run():
    print(f"{'='*55}")
    print(f"  Experiment 4 — {PHASE}")
    print(f"  Rounds={ROUNDS}, n={N}, q={Q}, Ring alpha={ALPHA}")
    print(f"{'='*55}\n")

    data = {
        "L-CLSS":        unsigncrypt_lclss(),
        "NTRU-IBLRSCS":  unsigncrypt_ntru(),
        "MLCLOOSC":      unsigncrypt_mlcloosc(),
        "PQSCAAS (Ours)":unsigncrypt_pqscaas(),
    }

    rows = []
    for scheme, values in data.items():
        m = statistics.mean(values)
        s = statistics.stdev(values)
        rows.append({"Scheme": scheme, "Phase": PHASE,
                     "Mean (ms)": round(m, 5), "Std Dev": round(s, 6),
                     "Rounds": len(values)})
        print(f"  {scheme:<20} mean={m:.5f} ms   std={s:.6f}")

    df = pd.DataFrame(rows)
    df.to_csv("results/unsigncrypt_results.csv", index=False)
    print(f"\n  Saved: results/unsigncrypt_results.csv")

    # ── Plot ──────────────────────────────────────────────────
    means = [statistics.mean(data[s]) for s in SCHEMES]
    errs  = [statistics.stdev(data[s]) for s in SCHEMES]

    fig, axes = plt.subplots(1, 2, figsize=(13, 5))

    # Left: all 4 schemes
    bars = axes[0].bar(SCHEMES, means, color=COLORS, yerr=errs,
                       capsize=5, width=0.5, zorder=3,
                       error_kw={"linewidth": 1.2})
    axes[0].set_title(
        f"{PHASE}\n(n={N}, q={Q}, α={ALPHA}, {ROUNDS} rounds)",
        fontsize=11, fontweight="bold")
    axes[0].set_ylabel("Average cost (ms)", fontsize=10)
    axes[0].yaxis.grid(True, linestyle="--", alpha=0.5, zorder=0)
    axes[0].set_axisbelow(True)
    axes[0].spines[["top","right"]].set_visible(False)
    for bar, m, e in zip(bars, means, errs):
        axes[0].text(bar.get_x()+bar.get_width()/2,
                     bar.get_height()+e+max(means)*0.01,
                     f"{m:.4f}", ha="center", va="bottom", fontsize=8.5)
    bars[-1].set_edgecolor("#085041")
    bars[-1].set_linewidth(2.5)

    # Right: step-by-step PQSCAAS breakdown
    pq_steps = {
        "Verify\n(ML-DSA)": statistics.mean([jitter(T_DSA) for _ in range(ROUNDS)]),
        "Decap\n(ML-KEM)":  statistics.mean([jitter(T_KEM) for _ in range(ROUNDS)]),
        "KDF":              statistics.mean([jitter(T_KDF) for _ in range(ROUNDS)]),
        "AEAD.Dec\n(sym)":  statistics.mean([jitter(T_SYM) for _ in range(ROUNDS)]),
    }
    step_colors = ["#185FA5", "#1D9E75", "#3B6D11", "#5DCAA5"]
    bars2 = axes[1].bar(list(pq_steps.keys()), list(pq_steps.values()),
                        color=step_colors, width=0.45, zorder=3)
    axes[1].set_title("PQSCAAS — Unsigncrypt step breakdown",
                      fontsize=11, fontweight="bold")
    axes[1].set_ylabel("Average cost (ms)", fontsize=10)
    axes[1].yaxis.grid(True, linestyle="--", alpha=0.5, zorder=0)
    axes[1].set_axisbelow(True)
    axes[1].spines[["top","right"]].set_visible(False)
    for bar, v in zip(bars2, pq_steps.values()):
        axes[1].text(bar.get_x()+bar.get_width()/2,
                     bar.get_height()+max(pq_steps.values())*0.02,
                     f"{v:.4f}", ha="center", va="bottom", fontsize=9)

    plt.tight_layout()
    plt.savefig("results/unsigncrypt_plot.png", dpi=150, bbox_inches="tight")
    print(f"  Saved: results/unsigncrypt_plot.png")

    with open("results/unsigncrypt_raw.json", "w") as f:
        json.dump(data, f)
    print(f"  Saved: results/unsigncrypt_raw.json\n")

    # ── Highlight: PQSCAAS slower than MLCLOOSC in this phase ─
    pq_mean   = statistics.mean(data["PQSCAAS (Ours)"])
    mlcl_mean = statistics.mean(data["MLCLOOSC"])
    diff = (pq_mean - mlcl_mean) / mlcl_mean * 100
    print(f"  NOTE: PQSCAAS is {abs(diff):.1f}% {'slower' if diff>0 else 'faster'} than MLCLOOSC")
    print(f"        (expected — PQSCAAS adds T_dsa + T_kem for stronger auth/confid)")

if __name__ == "__main__":
    run()
