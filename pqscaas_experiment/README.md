# PQSCAAS Comparative Experiments

Benchmarking framework for **PQSCAAS** (Post-Quantum Signcryption as a Service) against three state-of-the-art baseline schemes:

- **Sinha 2026** — NTRU-GIBLRSCS (IEEE TCE)
- **Yu 2021** — L-CLSS (IEEE Systems Journal)
- **Bai 2025** — MLCLOOSC (IEEE IoT Journal)

## 🚀 Quick Start

### 1. Install Dependencies (required)

```bash
pip install -r requirements.txt
```

This installs: `numpy`, `pandas`, `matplotlib`, `cryptography`

### 2. Install Real PQ Crypto (optional but recommended)

For REAL ML-KEM-768 and ML-DSA-65 timing:

**Linux/macOS:**
```bash
chmod +x install_liboqs.sh
./install_liboqs.sh
```

**Manual install:**
```bash
# Linux
sudo apt-get install cmake gcc g++ libssl-dev python3-dev
pip install liboqs-python

# macOS
brew install cmake openssl
pip install liboqs-python

# Windows — install CMake + Visual Studio Build Tools first
pip install liboqs-python
```

If liboqs fails to install, **the code automatically falls back to MOCK** (calibrated to NIST benchmarks on AWS EC2 c5.2xlarge).

### 3. Run All 6 Experiments

```bash
python3 run_all_experiments.py
```

Or run individual experiments:

```bash
python3 -m experiments.exp1_keygen
python3 -m experiments.exp2_client_encrypt
python3 -m experiments.exp3_server_signcrypt
python3 -m experiments.exp4_server_load
python3 -m experiments.exp5_end_to_end
python3 -m experiments.exp6_decrypt
```

Or specific ones:
```bash
python3 run_all_experiments.py 1 2 5
```

### Plot the results

After the CSV files are generated, create the figures with:

```bash
python3 plot_results.py
```

This reads the CSV files in `results/` and writes PNG and PDF versions of each chart to `figures/`.

## 📊 The 6 Experiments

| # | Name | X-axis | Y-axis | What it shows |
|---|------|--------|--------|----------------|
| **1** | Key Generation | N users (100-10K) | Total cost (ms) | PQSCAAS scalability via batching + multi-enclave |
| **2** | Client Encryption (AEAD vs Signcryption) | File size (1KB-100MB) | Client cost (ms) | PQSCAAS client is lightweight (AEAD-only) |
| **3** | Server-Side Signcryption | File size (1KB-100MB) | Server cost (ms) | PQSCAAS server cost is ~constant |
| **4** | Server Signcryption Under Load | Arrival rate (10-5000 req/s) | Per-req cost (ms) | Batching amortization at high load |
| **5** | End-to-End (Client+Server) | File size (1KB-100MB) | Total cost (ms) | PQSCAAS (c+s) vs Baselines (client only) |
| **6** | Recipient Decryption | File size (1KB-100MB) | Decrypt cost (ms) | All schemes compared |

## 📁 Project Structure

```
pqscaas_experiment/
├── pqscaas/                    # PQSCAAS scheme
│   ├── crypto_primitives.py    # Real liboqs (with mock fallback)
│   ├── scheme.py               # Phase 2-5 implementations
│   └── __init__.py
├── baselines/
│   ├── sinha2026.py            # NTRU-GIBLRSCS
│   ├── yu2021.py               # L-CLSS
│   ├── bai2025.py              # MLCLOOSC
│   └── __init__.py
├── experiments/
│   ├── exp1_keygen.py
│   ├── exp2_client_encrypt.py
│   ├── exp3_server_signcrypt.py
│   ├── exp4_server_load.py
│   ├── exp5_end_to_end.py
│   ├── exp6_decrypt.py
│   └── __init__.py
├── results/                    # CSV output (auto-created)
├── figures/                    # PNG + PDF plots (auto-created)
├── run_all_experiments.py      # Master runner
├── install_liboqs.sh           # Helper to install real PQ crypto
├── requirements.txt
└── README.md
```

## 🔬 Implementation Details

### Real Cryptography (when liboqs available)

- **ML-KEM-768** (Kyber) via liboqs — NIST FIPS 203
- **ML-DSA-65** (Dilithium) via liboqs — NIST FIPS 204
- **AES-256-GCM** via `cryptography` — with AES-NI
- **SHA-256, HKDF** via `cryptography`

### Mock Cryptography (fallback)

When `liboqs-python` is not available, the framework uses calibrated timing sampled from lognormal distributions based on:

- NIST PQC Round 3/4 reference implementations
- liboqs v0.10 benchmarks on AWS EC2 c5.2xlarge
- Paper-reported timings:
  - Sinha 2026 Table VI (NTRU operations)
  - Bai 2025 Table V (Module-lattice operations)
  - Yu 2021 (LWE operations)

### TEE Operations

Always use mock timing — there is no Python-native SGX. Sealing uses hash-based simulation with calibrated enter/exit/seal/unseal latencies.

## 📈 Expected Results

**Exp 1 (KeyGen @ 10K users):**
- PQSCAAS: ~445 ms (batching + multi-enclave)
- Bai 2025: ~3,750 ms (8×)
- Sinha: ~105,000 ms (236×)
- Yu: ~164,000 ms (369×)

**Exp 2 (Client @ 1KB):**
- PQSCAAS: ~0.1 ms (AEAD-only)
- Bai 2025: ~0.27 ms
- Sinha: ~9.8 ms (90×)
- Yu: ~11.3 ms (100×)

**Exp 5 (End-to-End @ 1MB):**
- PQSCAAS (client+server): ~4.1 ms
- Bai 2025: ~3.9 ms
- Sinha: ~14.8 ms
- Yu: ~14.6 ms

## 🎛️ Customization

Edit parameters in experiment files:

```python
# Exp 1
N_VALUES = [100, 500, 1000, 5000, 10000]   # Users to test
PQSCAAS_BATCH_SIZE = 64                     # Keygen batch size
PQSCAAS_NUM_ENCLAVES = 8                    # Parallel enclaves

# Exp 2, 3, 5, 6
FILE_SIZES = [...]                          # File sizes

# Exp 4
LAMBDA_VALUES = [10, 25, ..., 5000]         # Arrival rates
NUM_ENCLAVES = 8                            # Enclave count
MAX_BATCH = 128                             # Max batch size

# All experiments
NUM_TRIALS = 20                             # Statistical trials
```

## ⏱️ Runtime

- **Mock mode:** ~2-3 minutes total
- **Real crypto:** ~5-10 minutes total (depends on liboqs speed + hardware)

## 🔧 Troubleshooting

### "ModuleNotFoundError: No module named 'experiments'"
Run from project root: `python3 run_all_experiments.py`

### "liboqs-python fails to install"
- Ensure CMake and C compiler are installed
- On Windows: use `conda install -c conda-forge liboqs-python` instead
- Framework auto-falls back to mock — experiments still work

### "AES-GCM decryption fails in mock mode"
This is expected when using fake ciphertexts in mock mode — timing fallback activates automatically.

### High memory usage with 100MB files
Experiments 2, 5, 6 allocate 100MB buffers. If RAM is low, remove the `(100*1024*1024, '100 MB')` entry from `FILE_SIZES`.

## 📝 Outputs

After running, you'll find:

**CSV data:**
```
results/exp1_keygen.csv
results/exp2_client_encrypt.csv
results/exp3_server_signcrypt.csv
results/exp4_server_load.csv
results/exp5_end_to_end.csv
results/exp6_decrypt.csv
```

**Plots (PNG + PDF):**
```
figures/exp1_keygen.png / .pdf
figures/exp2_client_encrypt.png / .pdf
figures/exp3_server_signcrypt.png / .pdf
figures/exp4_server_load.png / .pdf
figures/exp5_end_to_end.png / .pdf
figures/exp6_decrypt.png / .pdf
```

## 🔬 Running on Professor's Server

If you want to run on a more powerful server:

```bash
# 1. Copy files to server
scp -r pqscaas_experiment/ user@server:/path/to/destination/

# 2. SSH in
ssh user@server

# 3. Install & run
cd /path/to/destination/pqscaas_experiment
./install_liboqs.sh
python3 run_all_experiments.py

# 4. Copy results back
scp -r user@server:/path/to/destination/pqscaas_experiment/results/ ./
scp -r user@server:/path/to/destination/pqscaas_experiment/figures/ ./
```

## 📚 References

1. NIST FIPS 203 — Module-Lattice-Based Key Encapsulation Mechanism (ML-KEM)
2. NIST FIPS 204 — Module-Lattice-Based Digital Signature Algorithm (ML-DSA)
3. Open Quantum Safe project — https://openquantumsafe.org/
4. liboqs-python — https://github.com/open-quantum-safe/liboqs-python

## 📄 License

For research use. PQSCAAS paper © Thammasat University SIIT.
