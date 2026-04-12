"""
config.py — Shared parameters for all experiments
==================================================
ทุกคนใช้ไฟล์นี้ร่วมกัน ห้ามแก้ค่าโดยไม่ตกลงกันก่อน
เพื่อให้ผลการทดลองของทุกคน normalize บน n, q เดียวกัน
"""

# ─── Lattice parameters ───────────────────────────────────────
N     = 256     # lattice / polynomial degree
Q     = 3329    # modulus (ML-KEM standard)
ALPHA = 8       # ring size for NTRU-IBLRSCS
B     = 32      # batch size for PQSCAAS enclave

# ─── Experiment settings ──────────────────────────────────────
ROUNDS = 50     # number of simulation rounds (≥50 required)
NOISE  = 0.05   # ±5% Gaussian jitter to simulate hardware variance
SEED   = 42     # random seed for reproducibility

# ─── Operation costs (ms) ─────────────────────────────────────
# Standard lattice
T_TRAP  = 18.50   # TrapGen — trapdoor generation
T_PRE   = 12.80   # SamplePre / Approx.SamplePreRej
T_MUL   = 0.850   # matrix-vector multiplication
T_ADD   = 0.012   # vector addition
T_S     = 0.420   # Discrete Gaussian Sampling (DGS)
T_RS    = 0.180   # Rejection sampling

# Module lattice (faster, NTT-based)
T_PVM   = 0.110   # polynomial vector multiplication
T_PVA   = 0.008   # polynomial vector addition

# NIST PQ standards
T_KEM   = 0.052   # ML-KEM Encap / Decap (Kyber-768)
T_DSA   = 0.085   # ML-DSA Sign / Verify (Dilithium-65)
T_SEAL  = 0.015   # TEE sealing
T_ENTER = 0.080   # TEE enclave entry overhead
T_EXIT  = 0.060   # TEE enclave exit overhead

# Lightweight ops
T_SYM   = 0.003   # AEAD symmetric enc/dec (AES-GCM)
T_KDF   = 0.004   # Key derivation function
T_H     = 0.005   # Hash function (SHA-3/SHAKE)

# ─── Scheme labels ────────────────────────────────────────────
SCHEMES = ["L-CLSS", "NTRU-IBLRSCS", "MLCLOOSC", "PQSCAAS (Ours)"]
COLORS  = ["#E24B4A", "#378ADD", "#BA7517", "#1D9E75"]