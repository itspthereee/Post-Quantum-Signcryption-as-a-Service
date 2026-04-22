"""
Baseline 3: Bai et al. 2025 - MLCLOOSC
  Module-Lattice-Based Certificateless Online/Offline Signcryption
  IEEE IoT Journal, Vol. 12, No. 14, July 2025

Module-lattice based (like PQSCAAS/Kyber/Dilithium). Stronger baseline
than Sinha or Yu because of efficient module-lattice operations.

Key costs from Table VI:
  OffSigncrypt:  2*T_pva + 4*T_pvm
  OnSigncrypt:   2*T_pva (near-zero)
  UnSigncrypt:   4*T_pva + 4*T_pvm
"""

import secrets
from pqscaas import crypto_primitives as cp


def mlcloosc_per_user_keygen() -> float:
    """PSKExtract (Approx.SamplePreRej) + UKeySet."""
    total_ms = 0.0
    # KGC: PSKExtract
    total_ms += cp.module_approx_sample_ms()
    total_ms += 3 * cp.module_pvm_ms()
    total_ms += cp.module_pva_ms()
    # User: UKeySet
    total_ms += cp.module_pvm_ms()        # verification
    total_ms += 2 * cp.module_pvm_ms()    # b_i = C_i * s_i + e_i
    total_ms += cp.module_pva_ms()
    total_ms += cp.module_hash_ring_ms()  # H_1
    return total_ms


def mlcloosc_total_keygen(n_users: int, **kwargs) -> float:
    """Sequential keygen."""
    return sum(mlcloosc_per_user_keygen() for _ in range(n_users))


def mlcloosc_off_signcrypt() -> float:
    """Offline signcryption: 2*T_pva + 4*T_pvm + H_3."""
    total_ms = 0.0
    total_ms += 4 * cp.module_pvm_ms()
    total_ms += 2 * cp.module_pva_ms()
    total_ms += cp.module_hash_256_ms()
    return total_ms


def mlcloosc_on_signcrypt() -> float:
    """Online signcryption: 2*T_pva + hashes."""
    total_ms = 0.0
    total_ms += cp.module_hash_btau_ms()
    total_ms += 2 * cp.module_pvm_ms()
    total_ms += 2 * cp.module_pva_ms()
    total_ms += cp.module_reject_ms()
    return total_ms


def mlcloosc_unsigncrypt_core() -> float:
    """UnSigncrypt: 4*T_pva + 4*T_pvm."""
    total_ms = 0.0
    total_ms += 4 * cp.module_pvm_ms()
    total_ms += 4 * cp.module_pva_ms()
    total_ms += cp.module_hash_256_ms()
    total_ms += cp.module_hash_btau_ms()
    return total_ms


def mlcloosc_client_signcrypt(message: bytes) -> float:
    """Client performs offline + online signcryption + payload encryption."""
    total_ms = 0.0
    total_ms += mlcloosc_off_signcrypt()
    total_ms += mlcloosc_on_signcrypt()

    key = secrets.token_bytes(32)
    _, t = cp.aead_encrypt(key, message, b"mlcloosc_aad")
    total_ms += t

    _, t = cp.sha256_hash(message)
    total_ms += t

    return total_ms


def mlcloosc_decrypt(ciphertext_size: int) -> float:
    """Recipient unsigncryption + AEAD decrypt."""
    total_ms = 0.0
    total_ms += mlcloosc_unsigncrypt_core()

    key = secrets.token_bytes(32)
    try:
        plaintext = secrets.token_bytes(ciphertext_size)
        enc_ct, _ = cp.aead_encrypt(key, plaintext, b"mlcloosc_aad")
        _, t = cp.aead_decrypt(key, enc_ct, b"mlcloosc_aad")
        total_ms += t
    except Exception:
        total_ms += cp._sample_mock_ms('AES_GCM_PER_MB') * (ciphertext_size / (1024*1024))
    return total_ms


if __name__ == "__main__":
    print("Bai 2025 (MLCLOOSC)")
    print("=" * 50)
    print(f"  Per-user keygen:     {mlcloosc_per_user_keygen():.4f} ms")
    print(f"  Total keygen (1000): {mlcloosc_total_keygen(1000):.2f} ms")
    print(f"  Client signcrypt 1MB: {mlcloosc_client_signcrypt(b'x'*1024*1024):.4f} ms")
    print(f"  Decrypt 1MB:         {mlcloosc_decrypt(1024*1024):.4f} ms")
