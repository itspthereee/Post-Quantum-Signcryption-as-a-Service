/*
 * pqscaas_enclave.cpp — ECALL implementations.
 *
 * All timing is wall-clock (via OCALL to get_time_ms), summed per operation.
 * The untrusted side additionally measures total ECALL time with chrono,
 * capturing real entry/exit overhead.
 *
 * Phase logic exactly mirrors pqscaas/scheme.py.
 */

#include "pqscaas_enclave_t.h"
#include "crypto_primitives.h"
#include "sgx_tseal.h"
#include <string.h>

/* Sealed-blob size for a RAW_STATE_SIZE-byte state */
static uint32_t sealed_size() {
    return sgx_calc_sealed_data_size(0, RAW_STATE_SIZE);
}

/* ============================================================================
 * Calibration
 * ============================================================================ */

sgx_status_t ecall_noop() {
    return SGX_SUCCESS;
}

sgx_status_t ecall_calibrate_ops(
    uint32_t n_samples,
    double *seal_ms_out,
    double *unseal_ms_out,
    double *sha256_ms_out,
    double *hkdf_ms_out,
    double *mock_kem_keygen_ms_out,
    double *mock_dsa_keygen_ms_out,
    double *mock_kem_encap_ms_out,
    double *mock_dsa_sign_ms_out
) {
    if (n_samples == 0) n_samples = 8;
    uint32_t ssz = sealed_size();
    uint8_t *sbuf = (uint8_t *)__builtin_alloca(ssz);
    uint8_t raw[RAW_STATE_SIZE];
    uint8_t digest[32];
    uint8_t okm[32];

    double sum_seal=0, sum_unseal=0, sum_sha=0, sum_hkdf=0;
    double sum_kem_kg=0, sum_dsa_kg=0, sum_kem_enc=0, sum_dsa_sign=0;

    for (uint32_t i = 0; i < n_samples; i++) {
        sgx_read_rand(raw, RAW_STATE_SIZE);

        double t;
        uint32_t actual_sz = RAW_STATE_SIZE;

        trusted_seal(raw, RAW_STATE_SIZE, sbuf, ssz, nullptr, &t);
        sum_seal += t;

        trusted_unseal(sbuf, ssz, raw, &actual_sz, &t);
        sum_unseal += t;

        trusted_sha256(raw, RAW_STATE_SIZE, digest, &t);
        sum_sha += t;

        trusted_hkdf(raw, 32, nullptr, 0, (const uint8_t*)"calibrate", 9, okm, 32, &t);
        sum_hkdf += t;

        sum_kem_kg    += trusted_mock_ml_kem_keygen();
        sum_dsa_kg    += trusted_mock_ml_dsa_keygen();
        sum_kem_enc   += trusted_mock_ml_kem_encap();
        sum_dsa_sign  += trusted_mock_ml_dsa_sign();
    }

    double n = (double)n_samples;
    if (seal_ms_out)          *seal_ms_out          = sum_seal    / n;
    if (unseal_ms_out)        *unseal_ms_out        = sum_unseal  / n;
    if (sha256_ms_out)        *sha256_ms_out        = sum_sha     / n;
    if (hkdf_ms_out)          *hkdf_ms_out          = sum_hkdf    / n;
    if (mock_kem_keygen_ms_out) *mock_kem_keygen_ms_out = sum_kem_kg  / n;
    if (mock_dsa_keygen_ms_out) *mock_dsa_keygen_ms_out = sum_dsa_kg  / n;
    if (mock_kem_encap_ms_out)  *mock_kem_encap_ms_out  = sum_kem_enc / n;
    if (mock_dsa_sign_ms_out)   *mock_dsa_sign_ms_out   = sum_dsa_sign/ n;

    return SGX_SUCCESS;
}

/* ============================================================================
 * Phase 2: Key Generation — inside enclave
 * ============================================================================
 *
 * Per-user steps (mirrors scheme.py::phase2_single_user_keygen):
 *   1. sgx_read_rand → s_u
 *   2. HKDF(s_u, "KEM-seed")   → kem_seed
 *   3. HKDF(s_u, "SIG-seed")   → sig_seed
 *   4. mock ML-KEM keygen
 *   5. mock ML-DSA keygen
 *   6. sgx_seal_data(s_u || meta)
 *
 * Enter/exit overhead is measured on the UNTRUSTED side via chrono.
 * inner_ms returns sum of inner operations only.
 */

sgx_status_t ecall_phase2_keygen_single(double *inner_ms) {
    double total = 0.0;

    uint8_t s_u[32];
    sgx_read_rand(s_u, 32);

    uint8_t kem_seed[32], sig_seed[32];
    double t;

    trusted_hkdf(s_u, 32, nullptr, 0, (const uint8_t*)"KEM-seed", 8, kem_seed, 32, &t);
    total += t;

    trusted_hkdf(s_u, 32, nullptr, 0, (const uint8_t*)"SIG-seed", 8, sig_seed, 32, &t);
    total += t;

    total += trusted_mock_ml_kem_keygen();
    total += trusted_mock_ml_dsa_keygen();

    /* Build state = s_u (32B) + random meta (16B) */
    uint8_t state[RAW_STATE_SIZE];
    memcpy(state, s_u, 32);
    sgx_read_rand(state + 32, 16);

    uint32_t ssz = sealed_size();
    uint8_t *sbuf = (uint8_t *)__builtin_alloca(ssz);
    trusted_seal(state, RAW_STATE_SIZE, sbuf, ssz, nullptr, &t);
    total += t;

    if (inner_ms) *inner_ms = total;
    return SGX_SUCCESS;
}

sgx_status_t ecall_phase2_keygen_batch(uint32_t batch_size, double *inner_ms) {
    double total = 0.0;
    uint32_t ssz = sealed_size();
    uint8_t *sbuf = (uint8_t *)__builtin_alloca(ssz);

    for (uint32_t i = 0; i < batch_size; i++) {
        uint8_t s_u[32];
        sgx_read_rand(s_u, 32);

        uint8_t seed[32];
        double t;

        trusted_hkdf(s_u, 32, nullptr, 0, (const uint8_t*)"KEM-seed", 8, seed, 32, &t);
        total += t;
        trusted_hkdf(s_u, 32, nullptr, 0, (const uint8_t*)"SIG-seed", 8, seed, 32, &t);
        total += t;

        total += trusted_mock_ml_kem_keygen();
        total += trusted_mock_ml_dsa_keygen();

        uint8_t state[RAW_STATE_SIZE];
        memcpy(state, s_u, 32);
        sgx_read_rand(state + 32, 16);
        trusted_seal(state, RAW_STATE_SIZE, sbuf, ssz, nullptr, &t);
        total += t;
    }

    if (inner_ms) *inner_ms = total;
    return SGX_SUCCESS;
}

/* ============================================================================
 * Phase 4: Server Signcryption — inside enclave
 * ============================================================================
 *
 * Per-request steps (mirrors scheme.py::phase4_server_signcrypt_single):
 *   1. Generate + seal a state (represents user's existing sealed state)
 *   2. sgx_unseal_data to recover
 *   3. HKDF(state[:32], "SIG-seed")
 *   4. mock ML-KEM Encap with pk_r_kem
 *   5. SHA-256(ciphertext_hash) — we SHA-256 a 32-byte hash placeholder
 *   6. HKDF(K_shared, h_ct) → K_mask
 *   7. XOR W = K_d XOR K_mask (both 32 bytes of rand data)
 *   8. mock ML-DSA Sign
 *   9. sgx_seal_data updated state
 */

static sgx_status_t signcrypt_one(const uint8_t *pk_r_kem, double *inner_ms) {
    (void)pk_r_kem;   /* mock: pk bytes not used, just timing */
    double total = 0.0;
    double t;
    sgx_status_t ret;

    uint32_t ssz = sealed_size();
    uint8_t *sbuf = (uint8_t *)__builtin_alloca(ssz);
    uint8_t state[RAW_STATE_SIZE];

    /* Pre-seal a state so we can unseal it (simulates stored user state) */
    sgx_read_rand(state, RAW_STATE_SIZE);
    ret = trusted_seal(state, RAW_STATE_SIZE, sbuf, ssz, nullptr, &t);
    if (ret != SGX_SUCCESS) return ret;
    total += t;   /* Tseal from previous signcrypt cycle, counted here */

    /* Unseal */
    uint8_t recovered[RAW_STATE_SIZE];
    uint32_t rec_len = RAW_STATE_SIZE;
    trusted_unseal(sbuf, ssz, recovered, &rec_len, &t);
    total += t;

    /* HKDF: derive sig key from seed */
    uint8_t sig_key[32];
    trusted_hkdf(recovered, 32, nullptr, 0, (const uint8_t*)"SIG-seed", 8, sig_key, 32, &t);
    total += t;

    /* Mock ML-KEM Encap */
    total += trusted_mock_ml_kem_encap();

    /* SHA-256 of ciphertext placeholder */
    uint8_t ct_placeholder[32];
    sgx_read_rand(ct_placeholder, 32);
    uint8_t h_ct[32];
    trusted_sha256(ct_placeholder, 32, h_ct, &t);
    total += t;

    /* HKDF: K_mask = HKDF(K_shared, h_ct) — K_shared is 32B random */
    uint8_t K_shared[32];
    sgx_read_rand(K_shared, 32);
    uint8_t K_mask[32];
    trusted_hkdf(K_shared, 32, nullptr, 0, h_ct, 32, K_mask, 32, &t);
    total += t;

    /* XOR W = K_d XOR K_mask — both random, negligible cost */
    uint8_t K_d[32], W[32];
    sgx_read_rand(K_d, 32);
    for (int i = 0; i < 32; i++) W[i] = K_d[i] ^ K_mask[i];

    /* Mock ML-DSA Sign */
    total += trusted_mock_ml_dsa_sign();

    /* Seal updated state */
    sgx_read_rand(state, RAW_STATE_SIZE);
    trusted_seal(state, RAW_STATE_SIZE, sbuf, ssz, nullptr, &t);
    total += t;

    if (inner_ms) *inner_ms += total;
    return SGX_SUCCESS;
}

sgx_status_t ecall_phase4_signcrypt_single(
    const uint8_t *pk_r_kem,
    uint32_t file_size_bytes,
    double *inner_ms
) {
    (void)file_size_bytes;
    if (inner_ms) *inner_ms = 0.0;
    return signcrypt_one(pk_r_kem, inner_ms);
}

sgx_status_t ecall_phase4_signcrypt_batch(
    uint32_t n_requests,
    const uint8_t *pk_r_kem,
    double *inner_ms
) {
    if (inner_ms) *inner_ms = 0.0;
    sgx_status_t ret;
    for (uint32_t i = 0; i < n_requests; i++) {
        ret = signcrypt_one(pk_r_kem, inner_ms);
        if (ret != SGX_SUCCESS) return ret;
    }
    return SGX_SUCCESS;
}

/* ============================================================================
 * Phase 6: Revocation
 * ============================================================================ */

sgx_status_t ecall_phase6_lazy_revoke(uint32_t n_revoked, double *inner_ms) {
    double total = 0.0;
    double t;
    uint8_t uid[32];

    /* Per revoked user: SHA-256(user_id) */
    for (uint32_t i = 0; i < n_revoked; i++) {
        sgx_read_rand(uid, 32);
        uint8_t digest[32];
        trusted_sha256(uid, 32, digest, &t);
        total += t + 0.005;   /* +0.005ms list-append overhead, same as Python */
    }

    /* One-time seal of revocation list */
    uint8_t rev_list[64];
    sgx_read_rand(rev_list, 64);
    uint32_t ssz = sgx_calc_sealed_data_size(0, 64);
    uint8_t *sbuf = (uint8_t *)__builtin_alloca(ssz);
    trusted_seal(rev_list, 64, sbuf, ssz, nullptr, &t);
    total += t;

    if (inner_ms) *inner_ms = total;
    return SGX_SUCCESS;
}

sgx_status_t ecall_phase6_rebind_single(double *inner_ms) {
    double total = 0.0;
    double t;

    uint32_t ssz = sealed_size();
    uint8_t *sbuf = (uint8_t *)__builtin_alloca(ssz);
    uint8_t state[RAW_STATE_SIZE];

    /* Seal then unseal (simulates stored state) */
    sgx_read_rand(state, RAW_STATE_SIZE);
    trusted_seal(state, RAW_STATE_SIZE, sbuf, ssz, nullptr, &t);
    total += t;

    uint8_t recovered[RAW_STATE_SIZE];
    uint32_t rec_len = RAW_STATE_SIZE;
    trusted_unseal(sbuf, ssz, recovered, &rec_len, &t);
    total += t;

    /* SHA-256 of user identity || PK data */
    uint8_t id_data[128];
    sgx_read_rand(id_data, 128);
    uint8_t digest[32];
    trusted_sha256(id_data, 128, digest, &t);
    total += t;

    /* HKDF rebind */
    uint8_t new_key[32];
    trusted_hkdf(digest, 32, nullptr, 0, (const uint8_t*)"REBIND", 6, new_key, 32, &t);
    total += t;

    /* Seal updated state */
    sgx_read_rand(state, RAW_STATE_SIZE);
    trusted_seal(state, RAW_STATE_SIZE, sbuf, ssz, nullptr, &t);
    total += t;

    if (inner_ms) *inner_ms = total;
    return SGX_SUCCESS;
}
