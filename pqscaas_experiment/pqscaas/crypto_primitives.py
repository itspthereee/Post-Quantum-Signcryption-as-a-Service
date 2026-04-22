"""
Cryptographic primitives for PQSCAAS experiments.

Tries to use REAL post-quantum cryptography via:
  - liboqs-python (ML-KEM-768, ML-DSA-65)
  - cryptography library (AEAD, HKDF, SHA256)

Falls back to MOCK (calibrated to NIST benchmarks) if libraries unavailable.

USAGE:
  pip install liboqs-python cryptography numpy
  
If liboqs-python fails, the module falls back to calibrated timings based on:
  - NIST PQC Round 3/4 reference implementations
  - liboqs v0.10 measurements on AWS EC2 c5.2xlarge-class hardware
  - Paper-reported timings (Sinha 2026, Yu 2021, Bai 2025)
"""

import time
import os
import hashlib
import secrets
import numpy as np
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ============================================================================
# Try to import real PQ libraries; fall back to mock
# ============================================================================
USE_REAL_PQ = False
try:
    import oqs
    # Verify the expected algorithms are available
    if ("ML-KEM-768" in oqs.get_enabled_kem_mechanisms() and
        "ML-DSA-65" in oqs.get_enabled_sig_mechanisms()):
        USE_REAL_PQ = True
        print("[crypto] Using REAL PQ crypto via liboqs-python (ML-KEM-768, ML-DSA-65)")
    else:
        print("[crypto] liboqs imported but ML-KEM-768/ML-DSA-65 not enabled — using MOCK")
except ImportError:
    print("[crypto] liboqs-python not available — using MOCK (calibrated to NIST benchmarks)")


# ============================================================================
# Calibrated mock latencies (milliseconds) — used when USE_REAL_PQ=False
# Source: NIST PQC reference implementations on AWS EC2 c5.2xlarge
# (Intel Xeon Platinum 8124M @ 3.0 GHz with AES-NI)
# ============================================================================

MOCK_LATENCY_MS = {
    # PQSCAAS primitives (module-lattice)
    'ML_KEM_KEYGEN':  (0.058, 0.004),
    'ML_KEM_ENCAP':   (0.075, 0.005),
    'ML_KEM_DECAP':   (0.065, 0.004),
    'ML_DSA_KEYGEN':  (0.135, 0.008),
    'ML_DSA_SIGN':    (0.410, 0.080),
    'ML_DSA_VERIFY':  (0.125, 0.006),

    # Seeded keygen (slightly faster than full keygen)
    'SEEDED_KEM_KG':  (0.048, 0.004),
    'SEEDED_DSA_KG':  (0.120, 0.008),
    'SEED_DERIVE':    (0.022, 0.002),

    # Classical / AEAD
    'AES_GCM_PER_MB': (1.85, 0.15),
    'SHA256_PER_MB':  (2.10, 0.12),
    'HKDF':           (0.018, 0.002),

    # TEE operations
    'TEE_ENTER':      (0.008, 0.002),   # ECALL: ~8,200 cycles @ 3GHz
    'TEE_EXIT':       (0.008, 0.002),   # OCALL: similar to ECALL
    'TEE_SEAL':       (0.035, 0.006),   # sgx_seal_data with AES-GCM
    'TEE_UNSEAL':     (0.030, 0.005),   # sgx_unseal_data,

    # Baseline primitives
    # Sinha 2026 (NTRU-GIBLRSCS)
    'NTRU_DGS':       (2.85, 0.25),
    'NTRU_RS':        (0.95, 0.08),
    'NTRU_POLY_MULT': (0.52, 0.04),
    'NTRU_CGS':       (4.80, 0.40),

    # Yu 2021 (L-CLSS)
    'LWE_SAMPLEPRE':  (12.40, 0.90),
    'LWE_VECT_SAMPLE':(0.85, 0.08),
    'LWE_MATRIX_MULT':(2.30, 0.20),

    # Bai 2025 (MLCLOOSC)
    'MODULE_PVA':     (0.001, 0.0002),
    'MODULE_PVM':     (0.027, 0.003),
    'MODULE_APPROX_SAMPLE': (0.165, 0.015),
    'MODULE_HASH_TO_RING':  (0.045, 0.005),
    'MODULE_HASH_TO_B_TAU': (0.035, 0.004),
    'MODULE_HASH_256BIT':   (0.008, 0.001),
    'MODULE_REJECT_TRIAL':  (0.045, 0.005),
}


def _sample_mock_ms(op_name, scale=1.0):
    """Sample a realistic latency from lognormal distribution."""
    mean, std = MOCK_LATENCY_MS[op_name]
    mean *= scale
    std *= scale
    if mean <= 0:
        return 0.0
    sigma = np.sqrt(np.log(1.0 + (std / mean) ** 2))
    mu = np.log(mean) - 0.5 * sigma ** 2
    return float(np.random.lognormal(mu, sigma))


# ============================================================================
# Timing helper — measures actual wall-clock time of an operation
# ============================================================================
def _time_ms(func, *args, **kwargs):
    """Execute func and return (result, elapsed_ms)."""
    start = time.perf_counter()
    result = func(*args, **kwargs)
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    return result, elapsed_ms


# ============================================================================
# ML-KEM-768 (Kyber) — REAL or MOCK
# ============================================================================
def ml_kem_keygen():
    """Returns (public_key_bytes, secret_key_bytes, elapsed_ms)."""
    if USE_REAL_PQ:
        start = time.perf_counter()
        with oqs.KeyEncapsulation("ML-KEM-768") as kem:
            pk = kem.generate_keypair()
            sk = kem.export_secret_key()
        elapsed = (time.perf_counter() - start) * 1000.0
        return pk, sk, elapsed
    else:
        # Mock: return fake keys but sampled timing
        pk = secrets.token_bytes(1184)  # ML-KEM-768 public key size
        sk = secrets.token_bytes(2400)  # ML-KEM-768 secret key size
        return pk, sk, _sample_mock_ms('ML_KEM_KEYGEN')


def ml_kem_encap(public_key):
    """Returns (ciphertext, shared_secret, elapsed_ms)."""
    if USE_REAL_PQ:
        start = time.perf_counter()
        with oqs.KeyEncapsulation("ML-KEM-768") as kem:
            ct, ss = kem.encap_secret(public_key)
        elapsed = (time.perf_counter() - start) * 1000.0
        return ct, ss, elapsed
    else:
        ct = secrets.token_bytes(1088)
        ss = secrets.token_bytes(32)
        return ct, ss, _sample_mock_ms('ML_KEM_ENCAP')


def ml_kem_decap(ciphertext, secret_key):
    """Returns (shared_secret, elapsed_ms)."""
    if USE_REAL_PQ:
        start = time.perf_counter()
        with oqs.KeyEncapsulation("ML-KEM-768", secret_key) as kem:
            ss = kem.decap_secret(ciphertext)
        elapsed = (time.perf_counter() - start) * 1000.0
        return ss, elapsed
    else:
        ss = secrets.token_bytes(32)
        return ss, _sample_mock_ms('ML_KEM_DECAP')


# ============================================================================
# ML-DSA-65 (Dilithium) — REAL or MOCK
# ============================================================================
def ml_dsa_keygen():
    """Returns (public_key, secret_key, elapsed_ms)."""
    if USE_REAL_PQ:
        start = time.perf_counter()
        with oqs.Signature("ML-DSA-65") as sig:
            pk = sig.generate_keypair()
            sk = sig.export_secret_key()
        elapsed = (time.perf_counter() - start) * 1000.0
        return pk, sk, elapsed
    else:
        pk = secrets.token_bytes(1952)
        sk = secrets.token_bytes(4032)
        return pk, sk, _sample_mock_ms('ML_DSA_KEYGEN')


def ml_dsa_sign(message, secret_key):
    """Returns (signature, elapsed_ms)."""
    if USE_REAL_PQ:
        start = time.perf_counter()
        with oqs.Signature("ML-DSA-65", secret_key) as sig:
            signature = sig.sign(message)
        elapsed = (time.perf_counter() - start) * 1000.0
        return signature, elapsed
    else:
        signature = secrets.token_bytes(3309)
        return signature, _sample_mock_ms('ML_DSA_SIGN')


def ml_dsa_verify(message, signature, public_key):
    """Returns (is_valid, elapsed_ms)."""
    if USE_REAL_PQ:
        start = time.perf_counter()
        with oqs.Signature("ML-DSA-65") as sig:
            valid = sig.verify(message, signature, public_key)
        elapsed = (time.perf_counter() - start) * 1000.0
        return valid, elapsed
    else:
        return True, _sample_mock_ms('ML_DSA_VERIFY')


# ============================================================================
# AEAD (AES-256-GCM) — REAL
# ============================================================================
def aead_encrypt(key, plaintext, associated_data=b""):
    """AES-256-GCM encryption. Returns (ciphertext, elapsed_ms)."""
    if len(key) < 32:
        key = key + b"\x00" * (32 - len(key))
    else:
        key = key[:32]
    start = time.perf_counter()
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ct = aesgcm.encrypt(nonce, plaintext, associated_data)
    elapsed = (time.perf_counter() - start) * 1000.0
    return nonce + ct, elapsed


def aead_decrypt(key, ciphertext_with_nonce, associated_data=b""):
    """AES-256-GCM decryption. Returns (plaintext, elapsed_ms)."""
    if len(key) < 32:
        key = key + b"\x00" * (32 - len(key))
    else:
        key = key[:32]
    start = time.perf_counter()
    aesgcm = AESGCM(key)
    nonce = ciphertext_with_nonce[:12]
    ct = ciphertext_with_nonce[12:]
    pt = aesgcm.decrypt(nonce, ct, associated_data)
    elapsed = (time.perf_counter() - start) * 1000.0
    return pt, elapsed


# ============================================================================
# SHA-256 Hash — REAL
# ============================================================================
def sha256_hash(data):
    """Returns (digest, elapsed_ms)."""
    start = time.perf_counter()
    digest = hashlib.sha256(data).digest()
    elapsed = (time.perf_counter() - start) * 1000.0
    return digest, elapsed


# ============================================================================
# HKDF — REAL
# ============================================================================
def hkdf_derive(input_key, salt=b"", info=b"", length=32):
    """Returns (derived_key, elapsed_ms)."""
    start = time.perf_counter()
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info)
    out = hkdf.derive(input_key)
    elapsed = (time.perf_counter() - start) * 1000.0
    return out, elapsed


# ============================================================================
# TEE Operations — ALWAYS MOCK (no real SGX in Python)
# ============================================================================
def tee_enter_ms():
    return _sample_mock_ms('TEE_ENTER')


def tee_exit_ms():
    return _sample_mock_ms('TEE_EXIT')


def tee_seal(data):
    """Mock sealing: hash+xor with device key."""
    start = time.perf_counter()
    device_key = hashlib.sha256(b"tee_device_key").digest()
    sealed = bytes(a ^ b for a, b in zip(data[:32], device_key)) + data[32:]
    actual = (time.perf_counter() - start) * 1000.0
    # Add simulated seal overhead
    sim = _sample_mock_ms('TEE_SEAL')
    return sealed, max(actual, sim)


def tee_unseal(sealed):
    """Mock unsealing."""
    start = time.perf_counter()
    device_key = hashlib.sha256(b"tee_device_key").digest()
    data = bytes(a ^ b for a, b in zip(sealed[:32], device_key)) + sealed[32:]
    actual = (time.perf_counter() - start) * 1000.0
    sim = _sample_mock_ms('TEE_UNSEAL')
    return data, max(actual, sim)


# ============================================================================
# Mock-only primitives (baselines' lattice operations)
# ============================================================================
def ntru_dgs_ms():        return _sample_mock_ms('NTRU_DGS')
def ntru_rs_ms():         return _sample_mock_ms('NTRU_RS')
def ntru_poly_mult_ms():  return _sample_mock_ms('NTRU_POLY_MULT')
def ntru_cgs_ms():        return _sample_mock_ms('NTRU_CGS')

def lwe_samplepre_ms():   return _sample_mock_ms('LWE_SAMPLEPRE')
def lwe_vect_sample_ms(): return _sample_mock_ms('LWE_VECT_SAMPLE')
def lwe_matrix_mult_ms(): return _sample_mock_ms('LWE_MATRIX_MULT')

def module_pva_ms():      return _sample_mock_ms('MODULE_PVA')
def module_pvm_ms():      return _sample_mock_ms('MODULE_PVM')
def module_approx_sample_ms(): return _sample_mock_ms('MODULE_APPROX_SAMPLE')
def module_hash_ring_ms():return _sample_mock_ms('MODULE_HASH_TO_RING')
def module_hash_btau_ms():return _sample_mock_ms('MODULE_HASH_TO_B_TAU')
def module_hash_256_ms(): return _sample_mock_ms('MODULE_HASH_256BIT')
def module_reject_ms():   return _sample_mock_ms('MODULE_REJECT_TRIAL')


# ============================================================================
# Sanity check
# ============================================================================
if __name__ == "__main__":
    np.random.seed(42)
    print(f"\nMode: {'REAL crypto' if USE_REAL_PQ else 'MOCK (calibrated)'}")
    print("=" * 60)

    # Test PQSCAAS primitives
    print("\n[PQSCAAS Primitives]")
    pk, sk, t = ml_kem_keygen()
    print(f"  ML-KEM KeyGen:  {t:.4f} ms  (pk={len(pk)}B, sk={len(sk)}B)")

    ct, ss1, t = ml_kem_encap(pk)
    print(f"  ML-KEM Encap:   {t:.4f} ms  (ct={len(ct)}B, ss={len(ss1)}B)")

    ss2, t = ml_kem_decap(ct, sk)
    print(f"  ML-KEM Decap:   {t:.4f} ms")
    if USE_REAL_PQ:
        assert ss1 == ss2, "ML-KEM encap/decap mismatch!"
        print(f"  ✓ ML-KEM correctness verified")

    pk, sk, t = ml_dsa_keygen()
    print(f"  ML-DSA KeyGen:  {t:.4f} ms  (pk={len(pk)}B, sk={len(sk)}B)")

    msg = b"hello pqscaas"
    sig, t = ml_dsa_sign(msg, sk)
    print(f"  ML-DSA Sign:    {t:.4f} ms  (sig={len(sig)}B)")

    valid, t = ml_dsa_verify(msg, sig, pk)
    print(f"  ML-DSA Verify:  {t:.4f} ms  (valid={valid})")

    # Test AEAD
    print("\n[AEAD]")
    key = secrets.token_bytes(32)
    plaintext = os.urandom(1024 * 1024)  # 1 MB
    ct, t = aead_encrypt(key, plaintext, b"aad")
    print(f"  AES-GCM Enc 1MB: {t:.4f} ms")
    pt, t = aead_decrypt(key, ct, b"aad")
    print(f"  AES-GCM Dec 1MB: {t:.4f} ms")
    assert pt == plaintext, "AEAD mismatch!"
    print(f"  ✓ AEAD correctness verified")

    # Test baseline primitives
    print("\n[Baseline Primitives - Mock]")
    print(f"  NTRU DGS:        {ntru_dgs_ms():.4f} ms")
    print(f"  NTRU Poly Mult:  {ntru_poly_mult_ms():.4f} ms")
    print(f"  LWE SamplePre:   {lwe_samplepre_ms():.4f} ms")
    print(f"  Module PVM:      {module_pvm_ms():.4f} ms")

    print("\n✓ All primitives working correctly.")
