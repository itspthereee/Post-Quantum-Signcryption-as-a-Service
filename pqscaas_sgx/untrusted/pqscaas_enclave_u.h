#ifndef PQSCAAS_ENCLAVE_U_H__
#define PQSCAAS_ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "stdint.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_PRINT_DEFINED__
#define OCALL_PRINT_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print, (const char* msg));
#endif
#ifndef OCALL_GET_TIME_MS_DEFINED__
#define OCALL_GET_TIME_MS_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_get_time_ms, (double* out_ms));
#endif
#ifndef SGX_OC_CPUIDEX_DEFINED__
#define SGX_OC_CPUIDEX_DEFINED__
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
#endif
#ifndef SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
#endif
#ifndef SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
#endif
#ifndef SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
#endif
#ifndef SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));
#endif
#ifndef PTHREAD_WAIT_TIMEOUT_OCALL_DEFINED__
#define PTHREAD_WAIT_TIMEOUT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, pthread_wait_timeout_ocall, (unsigned long long waiter, unsigned long long timeout));
#endif
#ifndef PTHREAD_CREATE_OCALL_DEFINED__
#define PTHREAD_CREATE_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, pthread_create_ocall, (unsigned long long self));
#endif
#ifndef PTHREAD_WAKEUP_OCALL_DEFINED__
#define PTHREAD_WAKEUP_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, pthread_wakeup_ocall, (unsigned long long waiter));
#endif

sgx_status_t ecall_noop(sgx_enclave_id_t eid, sgx_status_t* retval);
sgx_status_t ecall_calibrate_ops(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t n_samples, double* seal_ms, double* unseal_ms, double* sha256_ms, double* hkdf_ms, double* mock_kem_keygen_ms, double* mock_dsa_keygen_ms, double* mock_kem_encap_ms, double* mock_dsa_sign_ms);
sgx_status_t ecall_phase2_keygen_single(sgx_enclave_id_t eid, sgx_status_t* retval, double* inner_ms);
sgx_status_t ecall_phase2_keygen_batch(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t batch_size, double* inner_ms);
sgx_status_t ecall_phase4_signcrypt_single(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* pk_r_kem, uint32_t file_size_bytes, double* inner_ms);
sgx_status_t ecall_phase4_signcrypt_batch(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t n_requests, const uint8_t* pk_r_kem, double* inner_ms);
sgx_status_t ecall_phase6_lazy_revoke(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t n_revoked, double* inner_ms);
sgx_status_t ecall_phase6_rebind_single(sgx_enclave_id_t eid, sgx_status_t* retval, double* inner_ms);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
