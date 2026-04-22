"""
Baseline 2: Yu et al. 2021 - L-CLSS
  Certificateless Signcryption Scheme From Lattice
  IEEE Systems Journal, Vol. 15, No. 2, June 2021

Standard-lattice (LWE/SIS) based. Much heavier than module-lattice.

Signcryption breakdown (Section IV.D):
  - 3 Gaussian vector samples (y_1, y_2, y_3)
  - 1 sample w from chi_B^n
  - h = H_2(...)
  - 3 matrix-vector multiplications (sigma, v_1, v_2)
  - Encoding

Unsigncryption (Section IV.E):
  - Dot products
  - 1 matrix-vector mult for h'
  - Hash + norm check
"""

import secrets
from pqscaas import crypto_primitives as cp


def lclss_per_user_keygen() -> float:
    """
    KGC: Extract with SamplePre (d_i) +
    User: sample t_i, o_i, compute b_i = B_i^T * t_i + 2*o_i
    """
    total_ms = 0.0
    total_ms += cp.lwe_samplepre_ms()      # KGC: SamplePre for d_i
    total_ms += cp.lwe_vect_sample_ms()    # sample t_i
    total_ms += cp.lwe_vect_sample_ms()    # sample o_i
    total_ms += cp.lwe_matrix_mult_ms()    # B_i^T * t_i
    total_ms += 0.015                       # hash H_1(ID_i)
    return total_ms


def lclss_total_keygen(n_users: int, **kwargs) -> float:
    """Sequential keygen."""
    return sum(lclss_per_user_keygen() for _ in range(n_users))


def lclss_signcrypt_core() -> float:
    """Core L-CLSS signcryption (PQ operations)."""
    total_ms = 0.0
    # Gaussian sampling: y_1, y_2, y_3
    total_ms += 3 * cp.lwe_vect_sample_ms()
    # w from chi_B^n
    total_ms += cp.lwe_vect_sample_ms()
    # Matrix-vector multiplications: sigma, v_1, v_2
    total_ms += 3 * cp.lwe_matrix_mult_ms()
    # H_2 hash
    total_ms += 0.040
    # Rejection sampling (1 trial avg)
    total_ms += cp.ntru_rs_ms()
    return total_ms


def lclss_unsigncrypt_core() -> float:
    """Core L-CLSS unsigncryption."""
    total_ms = 0.0
    # Dot products (smaller than full matrix mult)
    total_ms += cp.lwe_matrix_mult_ms() * 0.3
    # Recompute h' for verification
    total_ms += cp.lwe_matrix_mult_ms()
    # Hash + norm check
    total_ms += 0.040
    return total_ms


def lclss_client_signcrypt(message: bytes) -> float:
    """Client performs full signcryption including payload encryption."""
    total_ms = 0.0
    total_ms += lclss_signcrypt_core()

    key = secrets.token_bytes(32)
    _, t = cp.aead_encrypt(key, message, b"lclss_aad")
    total_ms += t

    _, t = cp.sha256_hash(message)
    total_ms += t

    return total_ms


def lclss_decrypt(ciphertext_size: int) -> float:
    """Recipient decryption."""
    total_ms = 0.0
    total_ms += lclss_unsigncrypt_core()

    key = secrets.token_bytes(32)
    try:
        plaintext = secrets.token_bytes(ciphertext_size)
        enc_ct, _ = cp.aead_encrypt(key, plaintext, b"lclss_aad")
        _, t = cp.aead_decrypt(key, enc_ct, b"lclss_aad")
        total_ms += t
    except Exception:
        total_ms += cp._sample_mock_ms('AES_GCM_PER_MB') * (ciphertext_size / (1024*1024))
    return total_ms


if __name__ == "__main__":
    print("Yu 2021 (L-CLSS)")
    print("=" * 50)
    print(f"  Per-user keygen:     {lclss_per_user_keygen():.4f} ms")
    print(f"  Total keygen (1000): {lclss_total_keygen(1000):.2f} ms")
    print(f"  Client signcrypt 1MB: {lclss_client_signcrypt(b'x'*1024*1024):.4f} ms")
    print(f"  Decrypt 1MB:         {lclss_decrypt(1024*1024):.4f} ms")
