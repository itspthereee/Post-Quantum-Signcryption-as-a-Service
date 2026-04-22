"""
Baseline 1: Sinha et al. 2026 - NTRU-GIBLRSCS
  Identity-Based Linkable Ring Signcryption
  IEEE TCE, Vol. 72, No. 1, Feb 2026

Key cost formulas from paper (Table III):
  Sig Gen:    2*alpha*T_SD + (alpha+1)*T_1 + 2*T_RS
  Verify:     alpha*T_1
  Encryption: 2*T_1
  Decryption: T_1

Where:
  T_SD = Discrete Gaussian Sampling
  T_RS = Rejection Sampling
  T_1  = Polynomial multiplication
  alpha = ring size (we use alpha=1 for minimum cost)

Uses MOCK primitives for NTRU operations (no standard Python lib).
"""

import secrets
import time
from pqscaas import crypto_primitives as cp


ALPHA = 1  # Ring size (minimum for fair comparison)


def ntru_per_user_keygen() -> float:
    """Per-user keygen cost at PKG. Uses CGS + 2 DGS."""
    total_ms = 0.0
    total_ms += 0.010  # hash G_1(ID_i)
    total_ms += cp.ntru_cgs_ms()
    total_ms += 2 * cp.ntru_dgs_ms()
    return total_ms


def ntru_total_keygen(n_users: int, **kwargs) -> float:
    """N sequential keygens at PKG (no batching)."""
    return sum(ntru_per_user_keygen() for _ in range(n_users))


def ntru_signcrypt_core() -> float:
    """
    Core NTRU signcryption (PQ operations only).
    Following paper formulas:
      2*alpha*T_SD + (alpha+1)*T_1 + 2*T_RS + 2*T_1 (encap) + hashes
    """
    total_ms = 0.0
    total_ms += 2 * ALPHA * cp.ntru_dgs_ms()
    total_ms += (ALPHA + 1) * cp.ntru_poly_mult_ms()
    total_ms += 2 * cp.ntru_rs_ms()
    total_ms += 2 * cp.ntru_poly_mult_ms()  # encryption
    total_ms += 0.025  # hashes H_3, H_4
    return total_ms


def ntru_unsigncrypt_core() -> float:
    """Core NTRU unsigncryption (PQ operations only)."""
    total_ms = 0.0
    total_ms += cp.ntru_poly_mult_ms()          # decryption
    total_ms += ALPHA * cp.ntru_poly_mult_ms()  # verification
    total_ms += 0.015                            # hash checks
    return total_ms


def ntru_client_signcrypt(message: bytes) -> float:
    """
    CLIENT performs FULL signcryption (no server).
    Includes PQ operations + symmetric encryption of payload.
    """
    total_ms = 0.0

    # PQ signcryption overhead
    total_ms += ntru_signcrypt_core()

    # Must also encrypt the file payload (one-time pad only works for short msgs;
    # realistic extension uses AEAD for file-sized messages)
    key = secrets.token_bytes(32)
    _, t = cp.aead_encrypt(key, message, b"ntru_aad")
    total_ms += t

    # Hash for integrity
    _, t = cp.sha256_hash(message)
    total_ms += t

    return total_ms


def ntru_decrypt(ciphertext_size: int) -> float:
    """Recipient decryption: unsigncrypt + AEAD decrypt."""
    total_ms = 0.0
    total_ms += ntru_unsigncrypt_core()

    # AEAD decrypt (we simulate; actual crypto would need real ct)
    fake_ct = secrets.token_bytes(ciphertext_size + 16)
    key = secrets.token_bytes(32)
    try:
        # Encrypt first to get valid ct for decryption timing
        plaintext = secrets.token_bytes(ciphertext_size)
        enc_ct, _ = cp.aead_encrypt(key, plaintext, b"ntru_aad")
        _, t = cp.aead_decrypt(key, enc_ct, b"ntru_aad")
        total_ms += t
    except Exception:
        # Fallback estimate
        total_ms += cp._sample_mock_ms('AES_GCM_PER_MB') * (ciphertext_size / (1024*1024))
    return total_ms


if __name__ == "__main__":
    print("Sinha 2026 (NTRU-GIBLRSCS)")
    print("=" * 50)
    print(f"  Per-user keygen:     {ntru_per_user_keygen():.4f} ms")
    print(f"  Total keygen (1000): {ntru_total_keygen(1000):.2f} ms")
    print(f"  Client signcrypt 1MB: {ntru_client_signcrypt(b'x'*1024*1024):.4f} ms")
    print(f"  Decrypt 1MB:         {ntru_decrypt(1024*1024):.4f} ms")
