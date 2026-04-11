"""
exp1_keygen.py — คนที่ 1 : Key Generation Phase
=================================================
รับผิดชอบ: วัด computation cost ของ KeyGen ทุก scheme

Formula:
  L-CLSS        : T_trap + T_pre + 2*T_h
  NTRU-IBLRSCS  : T_trap + 2*T_s + T_h
  MLCLOOSC      : T_pre + 2*T_pvm + T_h
  PQSCAAS       : (T_kem + T_dsa + T_seal)/B + T_kdf + T_h

รัน: python exp1_keygen.py
ผลลัพธ์: results/keygen_results.csv + results/keygen_plot.png
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

PHASE = "Key Generation"

# ─────────────────────────────────────────────────────────────
def jitter(cost):
    """เพิ่ม Gaussian noise ±NOISE% เพื่อสะท้อน hardware variance"""
    return max(0, random.gauss(cost, cost * NOISE))

# ─────────────────────────────────────────────────────────────
def keygen_lclss():
    """
    L-CLSS (Yu et al. 2021)
    Steps:
      1. TrapGen(1^n, 1^N, q) → (A, R)   : T_trap
      2. u_i = H1(ID_i)                   : T_h
      3. d_i ← SamplePre(A, R, u_i, s2)  : T_pre
      4. verify Adi = ui                  : T_h
    """
    results = []
    for _ in range(ROUNDS):
        cost = jitter(T_TRAP) + jitter(T_PRE) + 2*jitter(T_H)
        results.append(cost)
    return results

def keygen_ntru():
    """
    NTRU-IBLRSCS (Sinha et al. 2026)
    Steps:
      1. TrapGenNTRU(q, n, sigma_f) → (g, B)  : T_trap
      2. t_i = G1(ID_i)                        : T_h
      3. CGS(MSK, sigma, (n_i,0)) → (s1,s2)   : T_s
      4. s'1, s'2 ← D^sigma_n                 : T_s
    """
    results = []
    for _ in range(ROUNDS):
        cost = jitter(T_TRAP) + 2*jitter(T_S) + jitter(T_H)
        results.append(cost)
    return results

def keygen_mlcloosc():
    """
    MLCLOOSC (Bai et al. 2025)
    Steps:
      1. d_i ← Approx.SamplePreRej(R, A', H1(ID||mpk), s)  : T_pre
      2. b_i = C_i * s_i + e_i                              : T_pvm
      3. verify [Id|A'|(GH-BH)] * d_i = H1(ID||mpk)        : T_pvm + T_h
    """
    results = []
    for _ in range(ROUNDS):
        cost = jitter(T_PRE) + 2*jitter(T_PVM) + jitter(T_H)
        results.append(cost)
    return results

def keygen_pqscaas():
    """
    PQSCAAS (Ours) — inside TEE enclave, batch B
    Steps:
      1. s_u ← {0,1}^lambda                              : ~0
      2. s_KEM = KDF(s_u || 'KEM' || ID || v)            : T_kdf
      3. (PK_KEM, SK_KEM) ← ML-KEM.KeyGen(s_KEM)        : T_kem
      4. (PK_DSA, SK_DSA) ← ML-DSA.KeyGen(s_DSA)        : T_dsa
      5. S_u = Seal(State_u)                             : T_seal
      ★ amortize T_enter+T_exit over batch B users        : /B
    """
    results = []
    for _ in range(ROUNDS):
        amortized = (jitter(T_ENTER) + jitter(T_EXIT)) / B
        cost = amortized + jitter(T_KEM) + jitter(T_DSA) + jitter(T_SEAL) + jitter(T_KDF) + jitter(T_H)
        results.append(cost)
    return results

# ─────────────────────────────────────────────────────────────
def run():
    print(f"{'='*55}")
    print(f"  Experiment 1 — {PHASE}")
    print(f"  Rounds={ROUNDS}, n={N}, q={Q}, Batch B={B}")
    print(f"{'='*55}\n")

    data = {
        "L-CLSS":        keygen_lclss(),
        "NTRU-IBLRSCS":  keygen_ntru(),
        "MLCLOOSC":      keygen_mlcloosc(),
        "PQSCAAS (Ours)":keygen_pqscaas(),
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
    csv_path = "results/keygen_results.csv"
    df.to_csv(csv_path, index=False)
    print(f"\n  Saved: {csv_path}")

    # ── Plot ──────────────────────────────────────────────────
    means = [statistics.mean(data[s]) for s in SCHEMES]
    errs  = [statistics.stdev(data[s]) for s in SCHEMES]

    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(SCHEMES, means, color=COLORS, yerr=errs,
                  capsize=5, width=0.5, zorder=3,
                  error_kw={"linewidth": 1.2})

    ax.set_title(f"{PHASE}\n(n={N}, q={Q}, Batch B={B}, {ROUNDS} rounds)",
                 fontsize=12, fontweight="bold")
    ax.set_ylabel("Average cost (ms)", fontsize=10)
    ax.yaxis.grid(True, linestyle="--", alpha=0.5, zorder=0)
    ax.set_axisbelow(True)
    ax.spines[["top","right"]].set_visible(False)

    for bar, mean, err in zip(bars, means, errs):
        ax.text(bar.get_x() + bar.get_width()/2,
                bar.get_height() + err + max(means)*0.01,
                f"{mean:.4f} ms",
                ha="center", va="bottom", fontsize=9, fontweight="500")

    bars[-1].set_edgecolor("#085041")
    bars[-1].set_linewidth(2.5)

    plt.tight_layout()
    plot_path = "results/keygen_plot.png"
    plt.savefig(plot_path, dpi=150, bbox_inches="tight")
    print(f"  Saved: {plot_path}")

    # save raw for combine step
    with open("results/keygen_raw.json", "w") as f:
        json.dump({k: v for k, v in data.items()}, f)
    print(f"  Saved: results/keygen_raw.json\n")

if __name__ == "__main__":
    run()
