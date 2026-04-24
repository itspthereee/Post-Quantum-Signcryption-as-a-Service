#include "pqscaas_enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_noop_t {
	sgx_status_t ms_retval;
} ms_ecall_noop_t;

typedef struct ms_ecall_calibrate_ops_t {
	sgx_status_t ms_retval;
	uint32_t ms_n_samples;
	double* ms_seal_ms;
	double* ms_unseal_ms;
	double* ms_sha256_ms;
	double* ms_hkdf_ms;
	double* ms_mock_kem_keygen_ms;
	double* ms_mock_dsa_keygen_ms;
	double* ms_mock_kem_encap_ms;
	double* ms_mock_dsa_sign_ms;
} ms_ecall_calibrate_ops_t;

typedef struct ms_ecall_phase2_keygen_single_t {
	sgx_status_t ms_retval;
	double* ms_inner_ms;
} ms_ecall_phase2_keygen_single_t;

typedef struct ms_ecall_phase2_keygen_batch_t {
	sgx_status_t ms_retval;
	uint32_t ms_batch_size;
	double* ms_inner_ms;
} ms_ecall_phase2_keygen_batch_t;

typedef struct ms_ecall_phase4_signcrypt_single_t {
	sgx_status_t ms_retval;
	const uint8_t* ms_pk_r_kem;
	uint32_t ms_file_size_bytes;
	double* ms_inner_ms;
} ms_ecall_phase4_signcrypt_single_t;

typedef struct ms_ecall_phase4_signcrypt_batch_t {
	sgx_status_t ms_retval;
	uint32_t ms_n_requests;
	const uint8_t* ms_pk_r_kem;
	double* ms_inner_ms;
} ms_ecall_phase4_signcrypt_batch_t;

typedef struct ms_ecall_phase6_lazy_revoke_t {
	sgx_status_t ms_retval;
	uint32_t ms_n_revoked;
	double* ms_inner_ms;
} ms_ecall_phase6_lazy_revoke_t;

typedef struct ms_ecall_phase6_rebind_single_t {
	sgx_status_t ms_retval;
	double* ms_inner_ms;
} ms_ecall_phase6_rebind_single_t;

typedef struct ms_ocall_print_t {
	const char* ms_msg;
} ms_ocall_print_t;

typedef struct ms_ocall_get_time_ms_t {
	double* ms_out_ms;
} ms_ocall_get_time_ms_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

typedef struct ms_pthread_wait_timeout_ocall_t {
	int ms_retval;
	unsigned long long ms_waiter;
	unsigned long long ms_timeout;
} ms_pthread_wait_timeout_ocall_t;

typedef struct ms_pthread_create_ocall_t {
	int ms_retval;
	unsigned long long ms_self;
} ms_pthread_create_ocall_t;

typedef struct ms_pthread_wakeup_ocall_t {
	int ms_retval;
	unsigned long long ms_waiter;
} ms_pthread_wakeup_ocall_t;

static sgx_status_t SGX_CDECL pqscaas_enclave_ocall_print(void* pms)
{
	ms_ocall_print_t* ms = SGX_CAST(ms_ocall_print_t*, pms);
	ocall_print(ms->ms_msg);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL pqscaas_enclave_ocall_get_time_ms(void* pms)
{
	ms_ocall_get_time_ms_t* ms = SGX_CAST(ms_ocall_get_time_ms_t*, pms);
	ocall_get_time_ms(ms->ms_out_ms);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL pqscaas_enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL pqscaas_enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL pqscaas_enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL pqscaas_enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL pqscaas_enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL pqscaas_enclave_pthread_wait_timeout_ocall(void* pms)
{
	ms_pthread_wait_timeout_ocall_t* ms = SGX_CAST(ms_pthread_wait_timeout_ocall_t*, pms);
	ms->ms_retval = pthread_wait_timeout_ocall(ms->ms_waiter, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL pqscaas_enclave_pthread_create_ocall(void* pms)
{
	ms_pthread_create_ocall_t* ms = SGX_CAST(ms_pthread_create_ocall_t*, pms);
	ms->ms_retval = pthread_create_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL pqscaas_enclave_pthread_wakeup_ocall(void* pms)
{
	ms_pthread_wakeup_ocall_t* ms = SGX_CAST(ms_pthread_wakeup_ocall_t*, pms);
	ms->ms_retval = pthread_wakeup_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[10];
} ocall_table_pqscaas_enclave = {
	10,
	{
		(void*)pqscaas_enclave_ocall_print,
		(void*)pqscaas_enclave_ocall_get_time_ms,
		(void*)pqscaas_enclave_sgx_oc_cpuidex,
		(void*)pqscaas_enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)pqscaas_enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)pqscaas_enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)pqscaas_enclave_sgx_thread_set_multiple_untrusted_events_ocall,
		(void*)pqscaas_enclave_pthread_wait_timeout_ocall,
		(void*)pqscaas_enclave_pthread_create_ocall,
		(void*)pqscaas_enclave_pthread_wakeup_ocall,
	}
};
sgx_status_t ecall_noop(sgx_enclave_id_t eid, sgx_status_t* retval)
{
	sgx_status_t status;
	ms_ecall_noop_t ms;
	status = sgx_ecall(eid, 0, &ocall_table_pqscaas_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_calibrate_ops(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t n_samples, double* seal_ms, double* unseal_ms, double* sha256_ms, double* hkdf_ms, double* mock_kem_keygen_ms, double* mock_dsa_keygen_ms, double* mock_kem_encap_ms, double* mock_dsa_sign_ms)
{
	sgx_status_t status;
	ms_ecall_calibrate_ops_t ms;
	ms.ms_n_samples = n_samples;
	ms.ms_seal_ms = seal_ms;
	ms.ms_unseal_ms = unseal_ms;
	ms.ms_sha256_ms = sha256_ms;
	ms.ms_hkdf_ms = hkdf_ms;
	ms.ms_mock_kem_keygen_ms = mock_kem_keygen_ms;
	ms.ms_mock_dsa_keygen_ms = mock_dsa_keygen_ms;
	ms.ms_mock_kem_encap_ms = mock_kem_encap_ms;
	ms.ms_mock_dsa_sign_ms = mock_dsa_sign_ms;
	status = sgx_ecall(eid, 1, &ocall_table_pqscaas_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_phase2_keygen_single(sgx_enclave_id_t eid, sgx_status_t* retval, double* inner_ms)
{
	sgx_status_t status;
	ms_ecall_phase2_keygen_single_t ms;
	ms.ms_inner_ms = inner_ms;
	status = sgx_ecall(eid, 2, &ocall_table_pqscaas_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_phase2_keygen_batch(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t batch_size, double* inner_ms)
{
	sgx_status_t status;
	ms_ecall_phase2_keygen_batch_t ms;
	ms.ms_batch_size = batch_size;
	ms.ms_inner_ms = inner_ms;
	status = sgx_ecall(eid, 3, &ocall_table_pqscaas_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_phase4_signcrypt_single(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* pk_r_kem, uint32_t file_size_bytes, double* inner_ms)
{
	sgx_status_t status;
	ms_ecall_phase4_signcrypt_single_t ms;
	ms.ms_pk_r_kem = pk_r_kem;
	ms.ms_file_size_bytes = file_size_bytes;
	ms.ms_inner_ms = inner_ms;
	status = sgx_ecall(eid, 4, &ocall_table_pqscaas_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_phase4_signcrypt_batch(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t n_requests, const uint8_t* pk_r_kem, double* inner_ms)
{
	sgx_status_t status;
	ms_ecall_phase4_signcrypt_batch_t ms;
	ms.ms_n_requests = n_requests;
	ms.ms_pk_r_kem = pk_r_kem;
	ms.ms_inner_ms = inner_ms;
	status = sgx_ecall(eid, 5, &ocall_table_pqscaas_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_phase6_lazy_revoke(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t n_revoked, double* inner_ms)
{
	sgx_status_t status;
	ms_ecall_phase6_lazy_revoke_t ms;
	ms.ms_n_revoked = n_revoked;
	ms.ms_inner_ms = inner_ms;
	status = sgx_ecall(eid, 6, &ocall_table_pqscaas_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_phase6_rebind_single(sgx_enclave_id_t eid, sgx_status_t* retval, double* inner_ms)
{
	sgx_status_t status;
	ms_ecall_phase6_rebind_single_t ms;
	ms.ms_inner_ms = inner_ms;
	status = sgx_ecall(eid, 7, &ocall_table_pqscaas_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

