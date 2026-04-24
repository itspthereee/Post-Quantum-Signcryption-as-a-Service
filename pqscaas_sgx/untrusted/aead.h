#pragma once
#include <stdint.h>
#include <stddef.h>
#include <vector>
#include <utility>

/* AES-256-GCM encryption (OpenSSL EVP).
 * Returns (nonce[12] || tag[16] || ciphertext, elapsed_ms). */
std::pair<std::vector<uint8_t>, double> aead_encrypt_256(
    const uint8_t *key,   /* 32 bytes */
    const uint8_t *pt,    size_t pt_len,
    const uint8_t *aad,   size_t aad_len
);

/* AES-256-GCM decryption.
 * ct_buf = nonce[12] || tag[16] || ciphertext.
 * Returns (plaintext, elapsed_ms). */
std::pair<std::vector<uint8_t>, double> aead_decrypt_256(
    const uint8_t *key,
    const uint8_t *ct_buf, size_t ct_buf_len,
    const uint8_t *aad,    size_t aad_len
);

/* SHA-256 (OpenSSL) with timing. */
std::pair<std::vector<uint8_t>, double> sha256_hash(
    const uint8_t *data, size_t len
);

/* HKDF-SHA256 (OpenSSL) with timing. */
std::pair<std::vector<uint8_t>, double> hkdf_sha256(
    const uint8_t *ikm,  size_t ikm_len,
    const uint8_t *salt, size_t salt_len,
    const uint8_t *info, size_t info_len,
    size_t out_len
);
