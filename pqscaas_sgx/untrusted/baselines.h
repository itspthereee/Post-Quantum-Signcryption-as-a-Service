#pragma once
#include <stddef.h>
#include <stdint.h>

/* ============================================================================
 * Untrusted-side lognormal sampler — matches Python MOCK_LATENCY_MS exactly.
 * ============================================================================ */
double untrusted_sample_lognormal(double mean_ms, double std_ms);

/* ============================================================================
 * Baseline 1: Sinha 2026 — NTRU-GIBLRSCS
 * ============================================================================ */
double sinha_per_user_keygen();
double sinha_signcrypt_core();
double sinha_unsigncrypt_core();
/* Full client signcrypt: PQ ops + AEAD encrypt of `msg_len` bytes + SHA-256 */
double sinha_client_signcrypt(size_t msg_len);
/* Recipient decrypt: PQ ops + AEAD decrypt of `ct_size` bytes */
double sinha_decrypt(size_t ct_size);

/* ============================================================================
 * Baseline 2: Yu 2021 — L-CLSS
 * ============================================================================ */
double yu_per_user_keygen();
double yu_signcrypt_core();
double yu_unsigncrypt_core();
double yu_client_signcrypt(size_t msg_len);
double yu_decrypt(size_t ct_size);

/* ============================================================================
 * Baseline 3: Bai 2025 — MLCLOOSC
 * ============================================================================ */
double bai_per_user_keygen();
double bai_off_signcrypt();
double bai_on_signcrypt();
double bai_unsigncrypt_core();
double bai_client_signcrypt(size_t msg_len);
double bai_decrypt(size_t ct_size);
