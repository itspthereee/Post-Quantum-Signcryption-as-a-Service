#pragma once
#include <stdint.h>
#include "sgx_trts.h"
#include "sgx_tcrypto.h"

/* Calibrated lognormal parameters matching Python MOCK_LATENCY_MS.
 * [mean_ms, std_ms] for each operation. */
struct MockLatency { double mean; double std_dev; };

static const MockLatency MOCK_ML_KEM_KEYGEN  = {0.058, 0.004};
static const MockLatency MOCK_ML_KEM_ENCAP   = {0.075, 0.005};
static const MockLatency MOCK_ML_KEM_DECAP   = {0.065, 0.004};
static const MockLatency MOCK_ML_DSA_KEYGEN  = {0.135, 0.008};
static const MockLatency MOCK_ML_DSA_SIGN    = {0.410, 0.080};
static const MockLatency MOCK_ML_DSA_VERIFY  = {0.125, 0.006};
static const MockLatency MOCK_HKDF           = {0.018, 0.002};

/* Baseline mock latencies */
static const MockLatency MOCK_NTRU_DGS        = {2.85,  0.25};
static const MockLatency MOCK_NTRU_RS         = {0.95,  0.08};
static const MockLatency MOCK_NTRU_POLY_MULT  = {0.52,  0.04};
static const MockLatency MOCK_NTRU_CGS        = {4.80,  0.40};
static const MockLatency MOCK_LWE_SAMPLEPRE   = {12.40, 0.90};
static const MockLatency MOCK_LWE_VECT_SAMPLE = {0.85,  0.08};
static const MockLatency MOCK_LWE_MATRIX_MULT = {2.30,  0.20};
static const MockLatency MOCK_MOD_PVA         = {0.001, 0.0002};
static const MockLatency MOCK_MOD_PVM         = {0.027, 0.003};
static const MockLatency MOCK_MOD_APPROX_SAMPLE = {0.165, 0.015};
static const MockLatency MOCK_MOD_HASH_RING   = {0.045, 0.005};
static const MockLatency MOCK_MOD_HASH_BTAU   = {0.035, 0.004};
static const MockLatency MOCK_MOD_HASH_256    = {0.008, 0.001};
static const MockLatency MOCK_MOD_REJECT      = {0.045, 0.005};

/* Raw state size sealed by each user record */
#define RAW_STATE_SIZE  48u

/* Sample from lognormal distribution using Box-Muller + sgx_read_rand.
 * Returns a simulated latency in milliseconds. */
double trusted_sample_lognormal(double mean_ms, double std_ms);

/* HMAC-SHA256 using sgx_sha256 primitives (RFC 2104 manual). */
sgx_status_t trusted_hmac_sha256(
    const uint8_t *key,  uint32_t key_len,
    const uint8_t *msg,  uint32_t msg_len,
    uint8_t mac[32]
);

/* HKDF-SHA256 (RFC 5869) single-block expand, output ≤ 32 bytes.
 * Uses sgx_sha256 internally. Returns elapsed_ms via pointer. */
sgx_status_t trusted_hkdf(
    const uint8_t *ikm,  uint32_t ikm_len,
    const uint8_t *salt, uint32_t salt_len,
    const uint8_t *info, uint32_t info_len,
    uint8_t *okm, uint32_t okm_len,
    double *elapsed_ms
);

/* Real SHA-256 of data, returns elapsed_ms. */
sgx_status_t trusted_sha256(
    const uint8_t *data, uint32_t len,
    uint8_t digest[32],
    double *elapsed_ms
);

/* Real sgx_seal_data; sealed_buf must be at least sgx_calc_sealed_data_size(0, raw_len).
 * Returns elapsed_ms and actual sealed size. */
sgx_status_t trusted_seal(
    const uint8_t *raw, uint32_t raw_len,
    uint8_t *sealed_buf, uint32_t sealed_buf_size,
    uint32_t *sealed_out_size,
    double *elapsed_ms
);

/* Real sgx_unseal_data; fills raw_buf (must be ≥ raw_len) from sealed_buf.
 * Returns elapsed_ms. */
sgx_status_t trusted_unseal(
    const uint8_t *sealed_buf, uint32_t sealed_buf_size,
    uint8_t *raw_buf, uint32_t *raw_len,
    double *elapsed_ms
);

/* Mock ML-KEM keygen (returns lognormal timing). */
double trusted_mock_ml_kem_keygen();

/* Mock ML-KEM encap. */
double trusted_mock_ml_kem_encap();

/* Mock ML-DSA keygen. */
double trusted_mock_ml_dsa_keygen();

/* Mock ML-DSA sign. */
double trusted_mock_ml_dsa_sign();

/* Get monotonic time inside enclave via OCALL (ms). */
double trusted_get_time_ms();
