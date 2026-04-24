#include "aead.h"
#include <chrono>
#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <string.h>

using Clock = std::chrono::high_resolution_clock;
static double elapsed_ms(Clock::time_point t0) {
    return std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
}

/* ============================================================================
 * AES-256-GCM encrypt
 * ============================================================================ */

std::pair<std::vector<uint8_t>, double> aead_encrypt_256(
    const uint8_t *key,
    const uint8_t *pt,  size_t pt_len,
    const uint8_t *aad, size_t aad_len
) {
    auto t0 = Clock::now();

    uint8_t nonce[12];
    RAND_bytes(nonce, 12);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, nonce);

    int outl = 0;
    if (aad && aad_len)
        EVP_EncryptUpdate(ctx, nullptr, &outl, aad, (int)aad_len);

    std::vector<uint8_t> ct(pt_len);
    EVP_EncryptUpdate(ctx, ct.data(), &outl, pt, (int)pt_len);
    int final_len = 0;
    EVP_EncryptFinal_ex(ctx, ct.data() + outl, &final_len);

    uint8_t tag[16];
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx);

    /* Pack: nonce(12) | tag(16) | ciphertext */
    std::vector<uint8_t> result(12 + 16 + pt_len);
    memcpy(result.data(),       nonce, 12);
    memcpy(result.data() + 12,  tag,   16);
    memcpy(result.data() + 28,  ct.data(), pt_len);

    return {result, elapsed_ms(t0)};
}

/* ============================================================================
 * AES-256-GCM decrypt
 * ============================================================================ */

std::pair<std::vector<uint8_t>, double> aead_decrypt_256(
    const uint8_t *key,
    const uint8_t *ct_buf, size_t ct_buf_len,
    const uint8_t *aad,    size_t aad_len
) {
    auto t0 = Clock::now();
    if (ct_buf_len < 28) return {{}, elapsed_ms(t0)};

    const uint8_t *nonce = ct_buf;
    const uint8_t *tag   = ct_buf + 12;
    const uint8_t *ct    = ct_buf + 28;
    size_t ct_len        = ct_buf_len - 28;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nonce);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag);

    int outl = 0;
    if (aad && aad_len)
        EVP_DecryptUpdate(ctx, nullptr, &outl, aad, (int)aad_len);

    std::vector<uint8_t> pt(ct_len);
    EVP_DecryptUpdate(ctx, pt.data(), &outl, ct, (int)ct_len);
    EVP_DecryptFinal_ex(ctx, pt.data() + outl, &outl);
    EVP_CIPHER_CTX_free(ctx);

    return {pt, elapsed_ms(t0)};
}

/* ============================================================================
 * SHA-256 (OpenSSL)
 * ============================================================================ */

std::pair<std::vector<uint8_t>, double> sha256_hash(
    const uint8_t *data, size_t len
) {
    auto t0 = Clock::now();
    std::vector<uint8_t> digest(32);
    SHA256(data, len, digest.data());
    return {digest, elapsed_ms(t0)};
}

/* ============================================================================
 * HKDF-SHA256 (OpenSSL 3.x EVP_KDF or legacy HKDF)
 * ============================================================================ */

std::pair<std::vector<uint8_t>, double> hkdf_sha256(
    const uint8_t *ikm,  size_t ikm_len,
    const uint8_t *salt, size_t salt_len,
    const uint8_t *info, size_t info_len,
    size_t out_len
) {
    auto t0 = Clock::now();

    std::vector<uint8_t> okm(out_len);

    /* Use EVP_PKEY_CTX HKDF (OpenSSL 1.1+) */
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    EVP_PKEY_derive_init(pctx);
    EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256());
    if (salt && salt_len)
        EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, (int)salt_len);
    EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm, (int)ikm_len);
    if (info && info_len)
        EVP_PKEY_CTX_add1_hkdf_info(pctx, info, (int)info_len);
    size_t derived = out_len;
    EVP_PKEY_derive(pctx, okm.data(), &derived);
    EVP_PKEY_CTX_free(pctx);

    return {okm, elapsed_ms(t0)};
}
