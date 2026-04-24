#ifndef PQSCAAS_ENCLAVE_T_H__
#define PQSCAAS_ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "stdint.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

sgx_status_t ecall_noop(void);
sgx_status_t ecall_calibrate_ops(uint32_t n_samples, double* seal_ms, double* unseal_ms, double* sha256_ms, double* hkdf_ms, double* mock_kem_keygen_ms, double* mock_dsa_keygen_ms, double* mock_kem_encap_ms, double* mock_dsa_sign_ms);
sgx_status_t ecall_phase2_keygen_single(double* inner_ms);
sgx_status_t ecall_phase2_keygen_batch(uint32_t batch_size, double* inner_ms);
sgx_status_t ecall_phase4_signcrypt_single(const uint8_t* pk_r_kem, uint32_t file_size_bytes, double* inner_ms);
sgx_status_t ecall_phase4_signcrypt_batch(uint32_t n_requests, const uint8_t* pk_r_kem, double* inner_ms);
sgx_status_t ecall_phase6_lazy_revoke(uint32_t n_revoked, double* inner_ms);
sgx_status_t ecall_phase6_rebind_single(double* inner_ms);

sgx_status_t SGX_CDECL ocall_print(const char* msg);
sgx_status_t SGX_CDECL ocall_get_time_ms(double* out_ms);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);
sgx_status_t SGX_CDECL pthread_wait_timeout_ocall(int* retval, unsigned long long waiter, unsigned long long timeout);
sgx_status_t SGX_CDECL pthread_create_ocall(int* retval, unsigned long long self);
sgx_status_t SGX_CDECL pthread_wakeup_ocall(int* retval, unsigned long long waiter);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
