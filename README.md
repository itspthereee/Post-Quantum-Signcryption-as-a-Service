# PQSCAAS Benchmark Simulation

Computation cost comparison between **PQSCAAS (Ours)** and three related schemes:

- L-CLSS (Yu et al. 2021)
- NTRU-IBLRSCS (Sinha et al. 2026)
- MLCLOOSC (Bai et al. 2025)

---

## Team Assignments (1 คน 1 ไฟล์)

| คนที่ | ไฟล์                  | Phase ที่รับผิดชอบ            |
| ----- | --------------------- | ----------------------------- |
| 1     | `exp1_keygen.py`      | Key Generation                |
| 2     | `exp2_signcrypt.py`   | Signcryption (Sender/Client)  |
| 3     | `exp3_server.py`      | Signcryption (Server/Enclave) |
| 4     | `exp4_unsigncrypt.py` | Unsigncryption (Receiver)     |

---

## วิธีรัน

### 1. ติดตั้ง dependencies

```bash
pip install matplotlib pandas
```

### 2. แต่ละคนรัน experiment ของตัวเอง

```bash
python exp1_keygen.py       # คนที่ 1
python exp2_signcrypt.py    # คนที่ 2
python exp3_server.py       # คนที่ 3
python exp4_unsigncrypt.py  # คนที่ 4
```

ผลจะถูก save ไว้ใน `results/` folder

### 3. หลังทุกคนรันครบ — รวม plot สุดท้าย

```bash
python plot_results.py
```

---

## Parameters (ห้ามแก้โดยไม่ตกลงกัน)

ทุกค่าอยู่ใน `config.py`

| Parameter | Value | ความหมาย                      |
| --------- | ----- | ----------------------------- |
| `N`       | 256   | Lattice degree                |
| `Q`       | 3329  | Modulus (ML-KEM standard)     |
| `ALPHA`   | 8     | Ring size (NTRU-IBLRSCS)      |
| `B`       | 32    | Batch size (PQSCAAS enclave)  |
| `ROUNDS`  | 50    | จำนวนรอบ simulation           |
| `NOISE`   | 0.05  | ±5% Gaussian jitter           |
| `SEED`    | 42    | Random seed (reproducibility) |

---

## Computation Cost Formula (ต่อ phase)

### Key Generation

| Scheme       | Formula                                      |
| ------------ | -------------------------------------------- |
| L-CLSS       | T_trap + T_pre + 2·T_h                       |
| NTRU-IBLRSCS | T_trap + 2·T_s + T_h                         |
| MLCLOOSC     | T_pre + 2·T_pvm + T_h                        |
| **PQSCAAS**  | **(T_kem + T_dsa + T_seal)/B + T_kdf + T_h** |

### Signcryption — Sender

| Scheme       | Formula                                  |
| ------------ | ---------------------------------------- |
| L-CLSS       | 3·T_mul + 2·T_add + 2·T_h                |
| NTRU-IBLRSCS | 2α·T_s + (α+1)·T_mul + 2·T_rs + T_h      |
| MLCLOOSC     | T_off + T_on (both on sender device)     |
| **PQSCAAS**  | **T_sym + T_h (zero PQ ops on client!)** |

### Signcryption — Server/Enclave

| Scheme       | Formula                                        |
| ------------ | ---------------------------------------------- |
| L-CLSS       | —                                              |
| NTRU-IBLRSCS | —                                              |
| MLCLOOSC     | —                                              |
| **PQSCAAS**  | **(T_enter+T_exit)/B + T_kem + T_dsa + T_kdf** |

### Unsigncryption — Receiver

| Scheme       | Formula                         |
| ------------ | ------------------------------- |
| L-CLSS       | 2·T_mul + T_add + T_h           |
| NTRU-IBLRSCS | α·T_mul + T_sym + T_h           |
| MLCLOOSC     | T_pvm + T_pva + T_h             |
| **PQSCAAS**  | **T_dsa + T_kem + T_sym + T_h** |

---

## Output Files

```
results/
├── keygen_raw.json          # raw data exp1
├── keygen_results.csv       # summary exp1
├── keygen_plot.png          # plot exp1
├── signcrypt_raw.json
├── signcrypt_results.csv
├── signcrypt_plot.png
├── server_raw.json
├── server_results.csv
├── server_plot.png
├── unsigncrypt_raw.json
├── unsigncrypt_results.csv
├── unsigncrypt_plot.png
├── final_summary.csv        # combined summary
└── final_comparison.png     # final 4-panel figure
```
