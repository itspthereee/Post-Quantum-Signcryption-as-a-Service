"""
exp3_server.py — คนที่ 3 : Signcryption — Total Cost per Request vs Load
X-axis : Number of requests (100, 200, 400, 800, 1600)
Y-axis : Total signcrypt cost per request (ms)

สิ่งที่กราฟแสดง:
  - L-CLSS / NTRU / MLCLOOSC: ทำ signcrypt เองทั้งหมด ไม่มี batching
    → cost ต่อ request คงที่ ไม่ลดลง = เส้นราบ
  - PQSCAAS: client ทำแค่ AEAD + server amortize ด้วย batch B
    → ยิ่ง request เยอะ ยิ่ง amortize ได้มาก = เส้นลดลงแล้วคงที่
    → total per-request cost ต่ำกว่าทุก scheme ตลอด
"""
import random, statistics, os, json
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import pandas as pd
from config import *

random.seed(SEED)
os.makedirs("results", exist_ok=True)

PHASE    = "Signcryption — Total Cost per Request"
X_LABEL  = "Number of requests"
X_VALUES = [1, 4, 8, 16, 32, 64, 128, 256, 512]

T_AEAD_PER_KB = 0.0012
FILE_SIZE_KB  = 100      # fixed file size for this comparison

def jitter(c): return max(0, random.gauss(c, c*NOISE))

# ── scheme อื่น: ทำ signcrypt ทุกอย่างเอง ไม่มี batch ──────
def total_lclss(_n_req):
    return 3*jitter(T_MUL) + 2*jitter(T_ADD) + 2*jitter(T_H) + FILE_SIZE_KB * jitter(T_AEAD_PER_KB)

def total_ntru(_n_req):
    return (2*ALPHA*jitter(T_S) + (ALPHA+1)*jitter(T_MUL) +
            2*jitter(T_RS) + jitter(T_H) + FILE_SIZE_KB * jitter(T_AEAD_PER_KB))

def total_mlcl(_n_req):
    t_off = 2*jitter(T_PVM) + 2*jitter(T_PVA) + jitter(T_H)
    t_on  = jitter(T_PVM) + jitter(T_PVA)
    return t_off + t_on + FILE_SIZE_KB * jitter(T_AEAD_PER_KB)

# ── PQSCAAS: client (AEAD) + server (amortized batch) ────
def total_pqscaas(n_req):
    # client cost (ต่ำมาก)
    t_client = jitter(T_SYM) + jitter(T_H) + FILE_SIZE_KB * jitter(T_AEAD_PER_KB)

    # server: batch size = min(B, n_req)
    # ยิ่ง n_req เยอะ → ยิ่งเต็ม batch → amortize ดีขึ้น
    effective_b = min(B, n_req)
    t_server = ((jitter(T_ENTER) + jitter(T_EXIT)) / effective_b
                + jitter(T_KEM) + jitter(T_DSA) + jitter(T_KDF))

    return t_client + t_server

FNS = {
    "L-CLSS":         total_lclss,
    "NTRU-IBLRSCS":   total_ntru,
    "MLCLOOSC":       total_mlcl,
    "PQSCAAS (Ours)": total_pqscaas,
}

def run():
    print(f"{'='*60}")
    print(f"  Experiment 3 — {PHASE}")
    print(f"  X = {X_LABEL}: {X_VALUES}")
    print(f"  File size fixed = {FILE_SIZE_KB} KB, Batch B = {B}")
    print(f"  Rounds = {ROUNDS}")
    print(f"{'='*60}\n")

    data  = {s: {r: [FNS[s](r) for _ in range(ROUNDS)] for r in X_VALUES} for s in SCHEMES}
    means = {s: [statistics.mean(data[s][r]) for r in X_VALUES] for s in SCHEMES}
    stds  = {s: [statistics.stdev(data[s][r]) for r in X_VALUES] for s in SCHEMES}

    for s in SCHEMES:
        for r, m, sd in zip(X_VALUES, means[s], stds[s]):
            print(f"  {s:<20} {r:5d} req: {m:8.4f} ± {sd:.5f} ms/req")
        print()

    rows = []
    for s in SCHEMES:
        for r, m, sd in zip(X_VALUES, means[s], stds[s]):
            rows.append({"Scheme":s, "Phase":PHASE, X_LABEL:r,
                         "Mean (ms/req)":round(m,5), "Std Dev":round(sd,6)})
    pd.DataFrame(rows).to_csv("results/server_results.csv", index=False)

    raw = {s: {str(r): data[s][r] for r in X_VALUES} for s in SCHEMES}
    with open("results/server_raw.json","w") as f:
        json.dump({"x_values":X_VALUES,"x_label":X_LABEL,
                   "phase":PHASE,"file_size_kb":FILE_SIZE_KB,"data":raw}, f)

    # ── Plot ────────────────────────────────────────────────
    STYLES = [("L-CLSS","#d62728","o","-"),
              ("NTRU-IBLRSCS","#1f77b4","s","--"),
              ("MLCLOOSC","#ff7f0e","^",":"),
              ("PQSCAAS (Ours)","#2ca02c","D","-.")]

    fig, ax = plt.subplots(figsize=(7, 4.8))
    for name, color, marker, ls in STYLES:
        ax.errorbar(X_VALUES, means[name], yerr=stds[name],
                    label=name, color=color, marker=marker,
                    linestyle=ls, linewidth=1.8, markersize=5,
                    capsize=4, elinewidth=1)

    ax.set_title(
        f"{PHASE}\n"
        f"(n={N}, q={Q}, Batch B={B}, File={FILE_SIZE_KB} KB, {ROUNDS} rounds)",
        fontsize=11, fontweight="bold")
    ax.set_xlabel(X_LABEL, fontsize=10)
    ax.set_ylabel("Total signcrypt cost per request (ms)", fontsize=10)
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xticks(X_VALUES)
    ax.xaxis.set_major_formatter(mticker.ScalarFormatter())
    ax.grid(True, which="both", linestyle="--", alpha=0.5)
    ax.legend(fontsize=9, framealpha=0.9)
    ax.spines[["top","right"]].set_visible(False)

    # annotate จุดที่ PQSCAAS เริ่ม amortize เต็มที่
    b_full_idx = next((i for i,r in enumerate(X_VALUES) if r >= B), None)
    if b_full_idx is not None:
        r_at_b = X_VALUES[b_full_idx]
        m_at_b = means["PQSCAAS (Ours)"][b_full_idx]
        ax.annotate(f"Batch full\n(B={B})",
                    xy=(r_at_b, m_at_b),
                    xytext=(r_at_b*1.3, m_at_b*2.5),
                    fontsize=8, color="#2ca02c",
                    arrowprops=dict(arrowstyle="->", color="#2ca02c", lw=1))

    plt.tight_layout()
    plt.savefig("results/server_plot.png", dpi=150, bbox_inches="tight")
    plt.close()
    print("  Saved: results/server_results.csv")
    print("  Saved: results/server_raw.json")
    print("  Saved: results/server_plot.png\n")

if __name__ == "__main__": run()