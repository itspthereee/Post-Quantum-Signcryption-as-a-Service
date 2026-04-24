/*
 * baselines.cpp — Three baseline schemes with mock PQ latencies.
 *
 * Lognormal parameters exactly match Python MOCK_LATENCY_MS.
 * AEAD (AES-256-GCM) and SHA-256 use real OpenSSL for untrusted-side ops.
 */

#include "baselines.h"
#include "aead.h"
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/rand.h>

/* ============================================================================
 * Lognormal sampler (untrusted side — same formula as trusted_sample_lognormal)
 * ============================================================================ */

double untrusted_sample_lognormal(double mean_ms, double std_ms) {
    if (mean_ms <= 0.0) return 0.0;
    double cv2   = (std_ms / mean_ms) * (std_ms / mean_ms);
    double sigma = sqrt(log(1.0 + cv2));
    double mu    = log(mean_ms) - 0.5 * sigma * sigma;

    /* Box-Muller with OpenSSL random (avoids rand() bias) */
    uint64_t r1 = 0, r2 = 0;
    RAND_bytes((uint8_t *)&r1, sizeof(r1));
    RAND_bytes((uint8_t *)&r2, sizeof(r2));

    double u1 = ((r1 & 0x000FFFFFFFFFFFFFULL) | 0x0010000000000000ULL)
                / (double)(1ULL << 53);
    double u2 = ((r2 & 0x000FFFFFFFFFFFFFULL) | 0x0010000000000000ULL)
                / (double)(1ULL << 53);

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif
    double z = sqrt(-2.0 * log(u1)) * cos(2.0 * M_PI * u2);
    return exp(mu + sigma * z);
}

/* Helper macros matching Python MOCK_LATENCY_MS */
#define MOCK(m,s) untrusted_sample_lognormal(m, s)

/* NTRU */
static double ntru_dgs()        { return MOCK(2.85, 0.25);  }
static double ntru_rs()         { return MOCK(0.95, 0.08);  }
static double ntru_poly_mult()  { return MOCK(0.52, 0.04);  }
static double ntru_cgs()        { return MOCK(4.80, 0.40);  }

/* LWE */
static double lwe_samplepre()   { return MOCK(12.40, 0.90); }
static double lwe_vect_sample() { return MOCK(0.85,  0.08); }
static double lwe_matrix_mult() { return MOCK(2.30,  0.20); }

/* Module-lattice */
static double mod_pva()         { return MOCK(0.001, 0.0002); }
static double mod_pvm()         { return MOCK(0.027, 0.003);  }
static double mod_approx_sample() { return MOCK(0.165, 0.015); }
static double mod_hash_ring()   { return MOCK(0.045, 0.005);  }
static double mod_hash_btau()   { return MOCK(0.035, 0.004);  }
static double mod_hash_256()    { return MOCK(0.008, 0.001);  }
static double mod_reject()      { return MOCK(0.045, 0.005);  }

/* Real AEAD + SHA-256 (reuse key material per call) */
static double real_aead_encrypt(size_t len) {
    uint8_t key[32];
    RAND_bytes(key, 32);
    std::vector<uint8_t> pt(len, 0xAB);
    auto [ct, ms] = aead_encrypt_256(key, pt.data(), len, (const uint8_t*)"aad", 3);
    return ms;
}

static double real_aead_decrypt(size_t len) {
    uint8_t key[32];
    RAND_bytes(key, 32);
    std::vector<uint8_t> pt(len, 0xAB);
    auto [ct, _ms] = aead_encrypt_256(key, pt.data(), len, (const uint8_t*)"aad", 3);
    auto [_pt, ms] = aead_decrypt_256(key, ct.data(), ct.size(), (const uint8_t*)"aad", 3);
    return ms;
}

static double real_sha256(size_t len) {
    std::vector<uint8_t> data(len, 0xCD);
    auto [_, ms] = sha256_hash(data.data(), len);
    return ms;
}

/* ============================================================================
 * Sinha 2026 — NTRU-GIBLRSCS (alpha=1)
 * ============================================================================ */

double sinha_per_user_keygen() {
    double t = 0.010;   /* hash G_1(ID_i) */
    t += ntru_cgs();
    t += 2.0 * ntru_dgs();
    return t;
}

double sinha_signcrypt_core() {
    double t = 0.0;
    t += 2.0 * 1 * ntru_dgs();      /* 2*alpha*T_SD, alpha=1 */
    t += (1 + 1) * ntru_poly_mult(); /* (alpha+1)*T_1 */
    t += 2.0 * ntru_rs();
    t += 2.0 * ntru_poly_mult();    /* encryption */
    t += 0.025;                      /* hashes H_3, H_4 */
    return t;
}

double sinha_unsigncrypt_core() {
    double t = ntru_poly_mult();        /* decryption */
    t += 1 * ntru_poly_mult();          /* alpha=1 verification */
    t += 0.015;
    return t;
}

double sinha_client_signcrypt(size_t msg_len) {
    double t = sinha_signcrypt_core();
    t += real_aead_encrypt(msg_len);
    t += real_sha256(msg_len);
    return t;
}

double sinha_decrypt(size_t ct_size) {
    double t = sinha_unsigncrypt_core();
    t += real_aead_decrypt(ct_size);
    return t;
}

/* ============================================================================
 * Yu 2021 — L-CLSS
 * ============================================================================ */

double yu_per_user_keygen() {
    double t = lwe_samplepre();
    t += lwe_vect_sample();
    t += lwe_vect_sample();
    t += lwe_matrix_mult();
    t += 0.015;    /* hash H_1(ID_i) */
    return t;
}

double yu_signcrypt_core() {
    double t = 3.0 * lwe_vect_sample();
    t += lwe_vect_sample();            /* w from chi_B^n */
    t += 3.0 * lwe_matrix_mult();
    t += 0.040;
    t += ntru_rs();
    return t;
}

double yu_unsigncrypt_core() {
    double t = lwe_matrix_mult() * 0.3;
    t += lwe_matrix_mult();
    t += 0.040;
    return t;
}

double yu_client_signcrypt(size_t msg_len) {
    double t = yu_signcrypt_core();
    t += real_aead_encrypt(msg_len);
    t += real_sha256(msg_len);
    return t;
}

double yu_decrypt(size_t ct_size) {
    double t = yu_unsigncrypt_core();
    t += real_aead_decrypt(ct_size);
    return t;
}

/* ============================================================================
 * Bai 2025 — MLCLOOSC
 * ============================================================================ */

double bai_per_user_keygen() {
    double t = mod_approx_sample();
    t += 3.0 * mod_pvm();
    t += mod_pva();
    t += mod_pvm();         /* UKeySet verification */
    t += 2.0 * mod_pvm();  /* b_i = C_i*s_i + e_i */
    t += mod_pva();
    t += mod_hash_ring();
    return t;
}

double bai_off_signcrypt() {
    double t = 4.0 * mod_pvm();
    t += 2.0 * mod_pva();
    t += mod_hash_256();
    return t;
}

double bai_on_signcrypt() {
    double t = mod_hash_btau();
    t += 2.0 * mod_pvm();
    t += 2.0 * mod_pva();
    t += mod_reject();
    return t;
}

double bai_unsigncrypt_core() {
    double t = 4.0 * mod_pvm();
    t += 4.0 * mod_pva();
    t += mod_hash_256();
    t += mod_hash_btau();
    return t;
}

double bai_client_signcrypt(size_t msg_len) {
    double t = bai_off_signcrypt() + bai_on_signcrypt();
    t += real_aead_encrypt(msg_len);
    t += real_sha256(msg_len);
    return t;
}

double bai_decrypt(size_t ct_size) {
    double t = bai_unsigncrypt_core();
    t += real_aead_decrypt(ct_size);
    return t;
}
