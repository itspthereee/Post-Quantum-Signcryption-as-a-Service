"""
exp2_signcrypt.py — คนที่ 2 : Signcryption — Sender / Client Side
===================================================================
รับผิดชอบ: วัด computation cost ของ Signcryption ฝั่ง sender

Formula:
  L-CLSS        : 3*T_mul + 2*T_add + 2*T_h
  NTRU-IBLRSCS  : 2*alpha*T_s + (alpha+1)*T_mul + 2*T_rs + T_h
  MLCLOOSC      : T_off + T_on  (offline + online, both on sender device)
                  T_off = 2*T_pvm + 2*T_pva + T_h
                  T_on  = T_pvm + T_pva
  PQSCAAS       : T_sym + T_h  (client: AEAD only — zero PQ ops!)

รัน: python exp2_signcrypt.py
ผลลัพธ์: results/signcrypt_results.csv + results/signcrypt_plot.png
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

PHASE = "Signcryption (Sender/Client)"

def jitter(cost):
    return max(0, random.gauss(cost, cost * NOISE))

# ─────────────────────────────────────────────────────────────
def signcrypt_lclss():
    """
    L-CLSS (Yu et al. 2021)
    Steps:
      1. y = [y1,y2,y3]^T ← D3l_sigma          : T_s (DGS)
      2. h = H2([A A 0; 0 B B]*y, m)            : T_mul + T_h
      3. sigma = eps + h; v1 = sigma + B_V*r    : T_mul + T_add
      4. v2 = A^T*w + 2e2                       : T_mul + T_add
      5. v  = (m + b_V*r + H1(...)) mod q       : T_h
    Total: 3*T_mul + 2*T_add + 2*T_h
    """
    results = []
    for _ in range(ROUNDS):
        cost = (3*jitter(T_MUL) + 2*jitter(T_ADD) + 2*jitter(T_H))
        results.append(cost)
    return results

def signcrypt_ntru(alpha=ALPHA):
    """
    NTRU-IBLRSCS (Sinha et al. 2026)
    Steps:
      1. J = n_x + n'_x + G2(event)             : ~0
      2. g_i, g'_i ← D^sigma_n  for i=1..alpha  : alpha * T_s
      3. v = G3(sum(h_i + h'_i*g), V, m, J)     : alpha*T_mul + T_h
      4. z_x = (s1+s'1)*v + h_x                 : T_mul
      5. Rejection sampling on (z_x, z'_x)       : 2*T_rs
      6. g'_i for non-signers                    : alpha*T_s
    Total: 2*alpha*T_s + (alpha+1)*T_mul + 2*T_rs + T_h
    """
    results = []
    for _ in range(ROUNDS):
        cost = (2*alpha*jitter(T_S) +
                (alpha+1)*jitter(T_MUL) +
                2*jitter(T_RS) +
                jitter(T_H))
        results.append(cost)
    return results

def signcrypt_mlcloosc():
    """
    MLCLOOSC (Bai et al. 2025)
    NOTE: offline + online ทั้งคู่อยู่บน sender device เดียวกัน!
    Offline phase (ทำก่อนที่จะรู้ message m):
      c1 = [Id|A'|(GH-BH)]^T * r1 + e1         : T_pvm + T_pva
      c2 = C^T_R * r2 + e2                      : T_pvm + T_pva
      K  = H3(m_bar || IDS || IDR || ...)        : T_h
    Online phase (ทำหลังจากรู้ message m):
      h  ← H2(m || w1 || w2)                    : ~T_h (ไม่นับ)
      z1 = y1 + h*d_S                            : T_pvm
      z2 = y2 + h*s_S                            : T_pva
    Total: T_off + T_on = 3*T_pvm + 3*T_pva + T_h
    """
    results = []
    for _ in range(ROUNDS):
        t_off = 2*jitter(T_PVM) + 2*jitter(T_PVA) + jitter(T_H)
        t_on  = jitter(T_PVM)   + jitter(T_PVA)
        results.append(t_off + t_on)
    return results

def signcrypt_pqscaas():
    """
    PQSCAAS (Ours) — Client side ONLY (zero PQ operations!)
    Steps:
      1. K = KDF(r || H(M))                     : T_kdf + T_h
      2. CT = AEAD.Enc(K, M, AAD)               : T_sym  (O(|M|))
      3. Desc_u = <RID, KH, |CT|, H(CT), Policy>: ~0
    Total: T_sym + T_h
    ★ ML-KEM / ML-DSA ทำที่ server (enclave) ไม่ใช่ client!
    """
    results = []
    for _ in range(ROUNDS):
        cost = jitter(T_SYM) + jitter(T_H)
        results.append(cost)
    return results

# ─────────────────────────────────────────────────────────────
def run():
    print(f"{'='*55}")
    print(f"  Experiment 2 — {PHASE}")
    print(f"  Rounds={ROUNDS}, n={N}, q={Q}, Ring alpha={ALPHA}")
    print(f"{'='*55}\n")

    data = {
        "L-CLSS":        signcrypt_lclss(),
        "NTRU-IBLRSCS":  signcrypt_ntru(),
        "MLCLOOSC":      signcrypt_mlcloosc(),
        "PQSCAAS (Ours)":signcrypt_pqscaas(),
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
    df.to_csv("results/signcrypt_results.csv", index=False)
    print(f"\n  Saved: results/signcrypt_results.csv")

    # ── Plot ──────────────────────────────────────────────────
    means = [statistics.mean(data[s]) for s in SCHEMES]
    errs  = [statistics.stdev(data[s]) for s in SCHEMES]

    fig, axes = plt.subplots(1, 2, figsize=(12, 5),
                             gridspec_kw={"width_ratios": [2, 1]})

    # Left: all schemes
    bars = axes[0].bar(SCHEMES, means, color=COLORS, yerr=errs,
                       capsize=5, width=0.5, zorder=3,
                       error_kw={"linewidth": 1.2})
    axes[0].set_title(f"{PHASE}\n(n={N}, q={Q}, α={ALPHA}, {ROUNDS} rounds)",
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

    # Right: MLCLOOSC & PQSCAAS zoom-in (hard to see on left)
    zoom_labels = ["MLCLOOSC", "PQSCAAS (Ours)"]
    zoom_means  = [statistics.mean(data[s]) for s in zoom_labels]
    zoom_errs   = [statistics.stdev(data[s]) for s in zoom_labels]
    zoom_colors = [COLORS[2], COLORS[3]]

    bars2 = axes[1].bar(zoom_labels, zoom_means, color=zoom_colors,
                        yerr=zoom_errs, capsize=5, width=0.4, zorder=3,
                        error_kw={"linewidth": 1.2})
    axes[1].set_title("Zoom: MLCLOOSC vs PQSCAAS", fontsize=10, fontweight="bold")
    axes[1].set_ylabel("Average cost (ms)", fontsize=10)
    axes[1].yaxis.grid(True, linestyle="--", alpha=0.5, zorder=0)
    axes[1].set_axisbelow(True)
    axes[1].spines[["top","right"]].set_visible(False)
    for bar, m, e in zip(bars2, zoom_means, zoom_errs):
        axes[1].text(bar.get_x()+bar.get_width()/2,
                     bar.get_height()+e+max(zoom_means)*0.02,
                     f"{m:.4f}", ha="center", va="bottom", fontsize=9)
    bars2[-1].set_edgecolor("#085041")
    bars2[-1].set_linewidth(2.5)

    plt.tight_layout()
    plt.savefig("results/signcrypt_plot.png", dpi=150, bbox_inches="tight")
    print(f"  Saved: results/signcrypt_plot.png")

    with open("results/signcrypt_raw.json", "w") as f:
        json.dump(data, f)
    print(f"  Saved: results/signcrypt_raw.json\n")

if __name__ == "__main__":
    run()
