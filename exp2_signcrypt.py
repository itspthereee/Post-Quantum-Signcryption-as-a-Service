"""
exp2_signcrypt.py — คนที่ 2 : Signcryption (Sender/Client)
X-axis : Message size |M| in KB (1, 10, 50, 100, 500, 1000, 5000)
Y-axis : Computation cost (ms)

จุดเด่น PQSCAAS: client ทำแค่ AEAD → cost = constant_overhead + O(|M|)
scheme อื่น: มี lattice ops คงที่ + AEAD → constant term สูงกว่ามาก
"""
import random, statistics, os, json
import matplotlib.pyplot as plt
import pandas as pd
from config import *

random.seed(SEED)
os.makedirs("results", exist_ok=True)

PHASE    = "Signcryption (Sender / Client)"
X_LABEL  = "Message size |M| (KB)"
X_VALUES = [1, 10, 50, 100, 500, 1000, 5000]

T_AEAD_PER_KB = 0.0012   # ms per KB — AES-GCM benchmark

def jitter(c): return max(0, random.gauss(c, c*NOISE))

def cost_lclss(kb):
    # lattice constant + AEAD linear
    lattice = 3*jitter(T_MUL) + 2*jitter(T_ADD) + 2*jitter(T_H)
    return lattice + kb * jitter(T_AEAD_PER_KB)

def cost_ntru(kb):
    lattice = 2*ALPHA*jitter(T_S) + (ALPHA+1)*jitter(T_MUL) + 2*jitter(T_RS) + jitter(T_H)
    return lattice + kb * jitter(T_AEAD_PER_KB)

def cost_mlcl(kb):
    t_off = 2*jitter(T_PVM) + 2*jitter(T_PVA) + jitter(T_H)
    t_on  = jitter(T_PVM) + jitter(T_PVA)
    return t_off + t_on + kb * jitter(T_AEAD_PER_KB)

def cost_pqscaas(kb):
    # client: ZERO lattice ops — AEAD only
    return jitter(T_SYM) + jitter(T_H) + kb * jitter(T_AEAD_PER_KB)

FNS = {"L-CLSS":cost_lclss,"NTRU-IBLRSCS":cost_ntru,"MLCLOOSC":cost_mlcl,"PQSCAAS (Ours)":cost_pqscaas}

def run():
    print(f"{'='*60}\n  Experiment 2 — {PHASE}\n  X = {X_LABEL}: {X_VALUES}\n  Rounds = {ROUNDS}, α = {ALPHA}\n{'='*60}\n")

    data  = {s: {kb: [FNS[s](kb) for _ in range(ROUNDS)] for kb in X_VALUES} for s in SCHEMES}
    means = {s: [statistics.mean(data[s][kb]) for kb in X_VALUES] for s in SCHEMES}
    stds  = {s: [statistics.stdev(data[s][kb]) for kb in X_VALUES] for s in SCHEMES}

    for s in SCHEMES:
        for kb, m, sd in zip(X_VALUES, means[s], stds[s]):
            print(f"  {s:<20} {kb:5d} KB: {m:8.4f} ± {sd:.5f} ms")
        print()

    rows = []
    for s in SCHEMES:
        for kb, m, sd in zip(X_VALUES, means[s], stds[s]):
            rows.append({"Scheme":s,"Phase":PHASE, X_LABEL:kb,
                         "Mean (ms)":round(m,5),"Std Dev":round(sd,6)})
    pd.DataFrame(rows).to_csv("results/signcrypt_results.csv", index=False)

    raw = {s: {str(kb): data[s][kb] for kb in X_VALUES} for s in SCHEMES}
    with open("results/signcrypt_raw.json","w") as f:
        json.dump({"x_values":X_VALUES,"x_label":X_LABEL,"phase":PHASE,"data":raw}, f)

    STYLES = [("L-CLSS","#d62728","o","-"),("NTRU-IBLRSCS","#1f77b4","s","--"),
              ("MLCLOOSC","#ff7f0e","^",":"),("PQSCAAS (Ours)","#2ca02c","D","-.")]
    fig, ax = plt.subplots(figsize=(7, 4.8))
    for name, color, marker, ls in STYLES:
        ax.errorbar(X_VALUES, means[name], yerr=stds[name], label=name,
                    color=color, marker=marker, linestyle=ls,
                    linewidth=1.8, markersize=5, capsize=4, elinewidth=1)
    ax.set_title(f"{PHASE}\n(n={N}, q={Q}, α={ALPHA}, {ROUNDS} rounds)", fontsize=11, fontweight="bold")
    ax.set_xlabel(X_LABEL, fontsize=10)
    ax.set_ylabel("Computation cost (ms)", fontsize=10)
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.grid(True, which="both", linestyle="--", alpha=0.5)
    ax.legend(fontsize=9, framealpha=0.9)
    ax.spines[["top","right"]].set_visible(False)
    plt.tight_layout()
    plt.savefig("results/signcrypt_plot.png", dpi=150, bbox_inches="tight")
    plt.close()
    print("  Saved: results/signcrypt_results.csv")
    print("  Saved: results/signcrypt_raw.json")
    print("  Saved: results/signcrypt_plot.png\n")

if __name__ == "__main__": run()