#include "pqscaas_enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

static sgx_status_t SGX_CDECL sgx_ecall_noop(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_noop_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_noop_t* ms = SGX_CAST(ms_ecall_noop_t*, pms);
	ms_ecall_noop_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_noop_t), ms, sizeof(ms_ecall_noop_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	sgx_status_t _in_retval;


	_in_retval = ecall_noop();
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_calibrate_ops(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_calibrate_ops_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_calibrate_ops_t* ms = SGX_CAST(ms_ecall_calibrate_ops_t*, pms);
	ms_ecall_calibrate_ops_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_calibrate_ops_t), ms, sizeof(ms_ecall_calibrate_ops_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	double* _tmp_seal_ms = __in_ms.ms_seal_ms;
	size_t _len_seal_ms = sizeof(double);
	double* _in_seal_ms = NULL;
	double* _tmp_unseal_ms = __in_ms.ms_unseal_ms;
	size_t _len_unseal_ms = sizeof(double);
	double* _in_unseal_ms = NULL;
	double* _tmp_sha256_ms = __in_ms.ms_sha256_ms;
	size_t _len_sha256_ms = sizeof(double);
	double* _in_sha256_ms = NULL;
	double* _tmp_hkdf_ms = __in_ms.ms_hkdf_ms;
	size_t _len_hkdf_ms = sizeof(double);
	double* _in_hkdf_ms = NULL;
	double* _tmp_mock_kem_keygen_ms = __in_ms.ms_mock_kem_keygen_ms;
	size_t _len_mock_kem_keygen_ms = sizeof(double);
	double* _in_mock_kem_keygen_ms = NULL;
	double* _tmp_mock_dsa_keygen_ms = __in_ms.ms_mock_dsa_keygen_ms;
	size_t _len_mock_dsa_keygen_ms = sizeof(double);
	double* _in_mock_dsa_keygen_ms = NULL;
	double* _tmp_mock_kem_encap_ms = __in_ms.ms_mock_kem_encap_ms;
	size_t _len_mock_kem_encap_ms = sizeof(double);
	double* _in_mock_kem_encap_ms = NULL;
	double* _tmp_mock_dsa_sign_ms = __in_ms.ms_mock_dsa_sign_ms;
	size_t _len_mock_dsa_sign_ms = sizeof(double);
	double* _in_mock_dsa_sign_ms = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_seal_ms, _len_seal_ms);
	CHECK_UNIQUE_POINTER(_tmp_unseal_ms, _len_unseal_ms);
	CHECK_UNIQUE_POINTER(_tmp_sha256_ms, _len_sha256_ms);
	CHECK_UNIQUE_POINTER(_tmp_hkdf_ms, _len_hkdf_ms);
	CHECK_UNIQUE_POINTER(_tmp_mock_kem_keygen_ms, _len_mock_kem_keygen_ms);
	CHECK_UNIQUE_POINTER(_tmp_mock_dsa_keygen_ms, _len_mock_dsa_keygen_ms);
	CHECK_UNIQUE_POINTER(_tmp_mock_kem_encap_ms, _len_mock_kem_encap_ms);
	CHECK_UNIQUE_POINTER(_tmp_mock_dsa_sign_ms, _len_mock_dsa_sign_ms);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_seal_ms != NULL && _len_seal_ms != 0) {
		if ( _len_seal_ms % sizeof(*_tmp_seal_ms) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_seal_ms = (double*)malloc(_len_seal_ms)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_seal_ms, 0, _len_seal_ms);
	}
	if (_tmp_unseal_ms != NULL && _len_unseal_ms != 0) {
		if ( _len_unseal_ms % sizeof(*_tmp_unseal_ms) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_unseal_ms = (double*)malloc(_len_unseal_ms)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_unseal_ms, 0, _len_unseal_ms);
	}
	if (_tmp_sha256_ms != NULL && _len_sha256_ms != 0) {
		if ( _len_sha256_ms % sizeof(*_tmp_sha256_ms) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_sha256_ms = (double*)malloc(_len_sha256_ms)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sha256_ms, 0, _len_sha256_ms);
	}
	if (_tmp_hkdf_ms != NULL && _len_hkdf_ms != 0) {
		if ( _len_hkdf_ms % sizeof(*_tmp_hkdf_ms) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_hkdf_ms = (double*)malloc(_len_hkdf_ms)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_hkdf_ms, 0, _len_hkdf_ms);
	}
	if (_tmp_mock_kem_keygen_ms != NULL && _len_mock_kem_keygen_ms != 0) {
		if ( _len_mock_kem_keygen_ms % sizeof(*_tmp_mock_kem_keygen_ms) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_mock_kem_keygen_ms = (double*)malloc(_len_mock_kem_keygen_ms)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_mock_kem_keygen_ms, 0, _len_mock_kem_keygen_ms);
	}
	if (_tmp_mock_dsa_keygen_ms != NULL && _len_mock_dsa_keygen_ms != 0) {
		if ( _len_mock_dsa_keygen_ms % sizeof(*_tmp_mock_dsa_keygen_ms) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_mock_dsa_keygen_ms = (double*)malloc(_len_mock_dsa_keygen_ms)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_mock_dsa_keygen_ms, 0, _len_mock_dsa_keygen_ms);
	}
	if (_tmp_mock_kem_encap_ms != NULL && _len_mock_kem_encap_ms != 0) {
		if ( _len_mock_kem_encap_ms % sizeof(*_tmp_mock_kem_encap_ms) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_mock_kem_encap_ms = (double*)malloc(_len_mock_kem_encap_ms)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_mock_kem_encap_ms, 0, _len_mock_kem_encap_ms);
	}
	if (_tmp_mock_dsa_sign_ms != NULL && _len_mock_dsa_sign_ms != 0) {
		if ( _len_mock_dsa_sign_ms % sizeof(*_tmp_mock_dsa_sign_ms) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_mock_dsa_sign_ms = (double*)malloc(_len_mock_dsa_sign_ms)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_mock_dsa_sign_ms, 0, _len_mock_dsa_sign_ms);
	}
	_in_retval = ecall_calibrate_ops(__in_ms.ms_n_samples, _in_seal_ms, _in_unseal_ms, _in_sha256_ms, _in_hkdf_ms, _in_mock_kem_keygen_ms, _in_mock_dsa_keygen_ms, _in_mock_kem_encap_ms, _in_mock_dsa_sign_ms);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_seal_ms) {
		if (memcpy_verw_s(_tmp_seal_ms, _len_seal_ms, _in_seal_ms, _len_seal_ms)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_unseal_ms) {
		if (memcpy_verw_s(_tmp_unseal_ms, _len_unseal_ms, _in_unseal_ms, _len_unseal_ms)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_sha256_ms) {
		if (memcpy_verw_s(_tmp_sha256_ms, _len_sha256_ms, _in_sha256_ms, _len_sha256_ms)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_hkdf_ms) {
		if (memcpy_verw_s(_tmp_hkdf_ms, _len_hkdf_ms, _in_hkdf_ms, _len_hkdf_ms)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_mock_kem_keygen_ms) {
		if (memcpy_verw_s(_tmp_mock_kem_keygen_ms, _len_mock_kem_keygen_ms, _in_mock_kem_keygen_ms, _len_mock_kem_keygen_ms)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_mock_dsa_keygen_ms) {
		if (memcpy_verw_s(_tmp_mock_dsa_keygen_ms, _len_mock_dsa_keygen_ms, _in_mock_dsa_keygen_ms, _len_mock_dsa_keygen_ms)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_mock_kem_encap_ms) {
		if (memcpy_verw_s(_tmp_mock_kem_encap_ms, _len_mock_kem_encap_ms, _in_mock_kem_encap_ms, _len_mock_kem_encap_ms)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_mock_dsa_sign_ms) {
		if (memcpy_verw_s(_tmp_mock_dsa_sign_ms, _len_mock_dsa_sign_ms, _in_mock_dsa_sign_ms, _len_mock_dsa_sign_ms)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_seal_ms) free(_in_seal_ms);
	if (_in_unseal_ms) free(_in_unseal_ms);
	if (_in_sha256_ms) free(_in_sha256_ms);
	if (_in_hkdf_ms) free(_in_hkdf_ms);
	if (_in_mock_kem_keygen_ms) free(_in_mock_kem_keygen_ms);
	if (_in_mock_dsa_keygen_ms) free(_in_mock_dsa_keygen_ms);
	if (_in_mock_kem_encap_ms) free(_in_mock_kem_encap_ms);
	if (_in_mock_dsa_sign_ms) free(_in_mock_dsa_sign_ms);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_phase2_keygen_single(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_phase2_keygen_single_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_phase2_keygen_single_t* ms = SGX_CAST(ms_ecall_phase2_keygen_single_t*, pms);
	ms_ecall_phase2_keygen_single_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_phase2_keygen_single_t), ms, sizeof(ms_ecall_phase2_keygen_single_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	double* _tmp_inner_ms = __in_ms.ms_inner_ms;
	size_t _len_inner_ms = sizeof(double);
	double* _in_inner_ms = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_inner_ms, _len_inner_ms);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_inner_ms != NULL && _len_inner_ms != 0) {
		if ( _len_inner_ms % sizeof(*_tmp_inner_ms) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_inner_ms = (double*)malloc(_len_inner_ms)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_inner_ms, 0, _len_inner_ms);
	}
	_in_retval = ecall_phase2_keygen_single(_in_inner_ms);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_inner_ms) {
		if (memcpy_verw_s(_tmp_inner_ms, _len_inner_ms, _in_inner_ms, _len_inner_ms)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_inner_ms) free(_in_inner_ms);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_phase2_keygen_batch(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_phase2_keygen_batch_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_phase2_keygen_batch_t* ms = SGX_CAST(ms_ecall_phase2_keygen_batch_t*, pms);
	ms_ecall_phase2_keygen_batch_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_phase2_keygen_batch_t), ms, sizeof(ms_ecall_phase2_keygen_batch_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	double* _tmp_inner_ms = __in_ms.ms_inner_ms;
	size_t _len_inner_ms = sizeof(double);
	double* _in_inner_ms = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_inner_ms, _len_inner_ms);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_inner_ms != NULL && _len_inner_ms != 0) {
		if ( _len_inner_ms % sizeof(*_tmp_inner_ms) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_inner_ms = (double*)malloc(_len_inner_ms)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_inner_ms, 0, _len_inner_ms);
	}
	_in_retval = ecall_phase2_keygen_batch(__in_ms.ms_batch_size, _in_inner_ms);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_inner_ms) {
		if (memcpy_verw_s(_tmp_inner_ms, _len_inner_ms, _in_inner_ms, _len_inner_ms)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_inner_ms) free(_in_inner_ms);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_phase4_signcrypt_single(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_phase4_signcrypt_single_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_phase4_signcrypt_single_t* ms = SGX_CAST(ms_ecall_phase4_signcrypt_single_t*, pms);
	ms_ecall_phase4_signcrypt_single_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_phase4_signcrypt_single_t), ms, sizeof(ms_ecall_phase4_signcrypt_single_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const uint8_t* _tmp_pk_r_kem = __in_ms.ms_pk_r_kem;
	size_t _len_pk_r_kem = 1184 * sizeof(uint8_t);
	uint8_t* _in_pk_r_kem = NULL;
	double* _tmp_inner_ms = __in_ms.ms_inner_ms;
	size_t _len_inner_ms = sizeof(double);
	double* _in_inner_ms = NULL;
	sgx_status_t _in_retval;

	if (sizeof(*_tmp_pk_r_kem) != 0 &&
		1184 > (SIZE_MAX / sizeof(*_tmp_pk_r_kem))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_pk_r_kem, _len_pk_r_kem);
	CHECK_UNIQUE_POINTER(_tmp_inner_ms, _len_inner_ms);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_pk_r_kem != NULL && _len_pk_r_kem != 0) {
		if ( _len_pk_r_kem % sizeof(*_tmp_pk_r_kem) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_pk_r_kem = (uint8_t*)malloc(_len_pk_r_kem);
		if (_in_pk_r_kem == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_pk_r_kem, _len_pk_r_kem, _tmp_pk_r_kem, _len_pk_r_kem)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_inner_ms != NULL && _len_inner_ms != 0) {
		if ( _len_inner_ms % sizeof(*_tmp_inner_ms) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_inner_ms = (double*)malloc(_len_inner_ms)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_inner_ms, 0, _len_inner_ms);
	}
	_in_retval = ecall_phase4_signcrypt_single((const uint8_t*)_in_pk_r_kem, __in_ms.ms_file_size_bytes, _in_inner_ms);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_inner_ms) {
		if (memcpy_verw_s(_tmp_inner_ms, _len_inner_ms, _in_inner_ms, _len_inner_ms)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_pk_r_kem) free(_in_pk_r_kem);
	if (_in_inner_ms) free(_in_inner_ms);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_phase4_signcrypt_batch(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_phase4_signcrypt_batch_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_phase4_signcrypt_batch_t* ms = SGX_CAST(ms_ecall_phase4_signcrypt_batch_t*, pms);
	ms_ecall_phase4_signcrypt_batch_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_phase4_signcrypt_batch_t), ms, sizeof(ms_ecall_phase4_signcrypt_batch_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const uint8_t* _tmp_pk_r_kem = __in_ms.ms_pk_r_kem;
	size_t _len_pk_r_kem = 1184 * sizeof(uint8_t);
	uint8_t* _in_pk_r_kem = NULL;
	double* _tmp_inner_ms = __in_ms.ms_inner_ms;
	size_t _len_inner_ms = sizeof(double);
	double* _in_inner_ms = NULL;
	sgx_status_t _in_retval;

	if (sizeof(*_tmp_pk_r_kem) != 0 &&
		1184 > (SIZE_MAX / sizeof(*_tmp_pk_r_kem))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_pk_r_kem, _len_pk_r_kem);
	CHECK_UNIQUE_POINTER(_tmp_inner_ms, _len_inner_ms);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_pk_r_kem != NULL && _len_pk_r_kem != 0) {
		if ( _len_pk_r_kem % sizeof(*_tmp_pk_r_kem) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_pk_r_kem = (uint8_t*)malloc(_len_pk_r_kem);
		if (_in_pk_r_kem == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_pk_r_kem, _len_pk_r_kem, _tmp_pk_r_kem, _len_pk_r_kem)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_inner_ms != NULL && _len_inner_ms != 0) {
		if ( _len_inner_ms % sizeof(*_tmp_inner_ms) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_inner_ms = (double*)malloc(_len_inner_ms)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_inner_ms, 0, _len_inner_ms);
	}
	_in_retval = ecall_phase4_signcrypt_batch(__in_ms.ms_n_requests, (const uint8_t*)_in_pk_r_kem, _in_inner_ms);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_inner_ms) {
		if (memcpy_verw_s(_tmp_inner_ms, _len_inner_ms, _in_inner_ms, _len_inner_ms)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_pk_r_kem) free(_in_pk_r_kem);
	if (_in_inner_ms) free(_in_inner_ms);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_phase6_lazy_revoke(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_phase6_lazy_revoke_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_phase6_lazy_revoke_t* ms = SGX_CAST(ms_ecall_phase6_lazy_revoke_t*, pms);
	ms_ecall_phase6_lazy_revoke_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_phase6_lazy_revoke_t), ms, sizeof(ms_ecall_phase6_lazy_revoke_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	double* _tmp_inner_ms = __in_ms.ms_inner_ms;
	size_t _len_inner_ms = sizeof(double);
	double* _in_inner_ms = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_inner_ms, _len_inner_ms);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_inner_ms != NULL && _len_inner_ms != 0) {
		if ( _len_inner_ms % sizeof(*_tmp_inner_ms) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_inner_ms = (double*)malloc(_len_inner_ms)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_inner_ms, 0, _len_inner_ms);
	}
	_in_retval = ecall_phase6_lazy_revoke(__in_ms.ms_n_revoked, _in_inner_ms);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_inner_ms) {
		if (memcpy_verw_s(_tmp_inner_ms, _len_inner_ms, _in_inner_ms, _len_inner_ms)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_inner_ms) free(_in_inner_ms);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_phase6_rebind_single(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_phase6_rebind_single_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_phase6_rebind_single_t* ms = SGX_CAST(ms_ecall_phase6_rebind_single_t*, pms);
	ms_ecall_phase6_rebind_single_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_phase6_rebind_single_t), ms, sizeof(ms_ecall_phase6_rebind_single_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	double* _tmp_inner_ms = __in_ms.ms_inner_ms;
	size_t _len_inner_ms = sizeof(double);
	double* _in_inner_ms = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_inner_ms, _len_inner_ms);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_inner_ms != NULL && _len_inner_ms != 0) {
		if ( _len_inner_ms % sizeof(*_tmp_inner_ms) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_inner_ms = (double*)malloc(_len_inner_ms)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_inner_ms, 0, _len_inner_ms);
	}
	_in_retval = ecall_phase6_rebind_single(_in_inner_ms);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_inner_ms) {
		if (memcpy_verw_s(_tmp_inner_ms, _len_inner_ms, _in_inner_ms, _len_inner_ms)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_inner_ms) free(_in_inner_ms);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[8];
} g_ecall_table = {
	8,
	{
		{(void*)(uintptr_t)sgx_ecall_noop, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_calibrate_ops, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_phase2_keygen_single, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_phase2_keygen_batch, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_phase4_signcrypt_single, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_phase4_signcrypt_batch, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_phase6_lazy_revoke, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_phase6_rebind_single, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[10][8];
} g_dyn_entry_table = {
	10,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print(const char* msg)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_msg = msg ? strlen(msg) + 1 : 0;

	ms_ocall_print_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(msg, _len_msg);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (msg != NULL) ? _len_msg : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_t));
	ocalloc_size -= sizeof(ms_ocall_print_t);

	if (msg != NULL) {
		if (memcpy_verw_s(&ms->ms_msg, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_msg % sizeof(*msg) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, msg, _len_msg)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_msg);
		ocalloc_size -= _len_msg;
	} else {
		ms->ms_msg = NULL;
	}

	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_get_time_ms(double* out_ms)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_out_ms = sizeof(double);

	ms_ocall_get_time_ms_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_get_time_ms_t);
	void *__tmp = NULL;

	void *__tmp_out_ms = NULL;

	CHECK_ENCLAVE_POINTER(out_ms, _len_out_ms);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (out_ms != NULL) ? _len_out_ms : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_get_time_ms_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_get_time_ms_t));
	ocalloc_size -= sizeof(ms_ocall_get_time_ms_t);

	if (out_ms != NULL) {
		if (memcpy_verw_s(&ms->ms_out_ms, sizeof(double*), &__tmp, sizeof(double*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_out_ms = __tmp;
		if (_len_out_ms % sizeof(*out_ms) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_out_ms, 0, _len_out_ms);
		__tmp = (void *)((size_t)__tmp + _len_out_ms);
		ocalloc_size -= _len_out_ms;
	} else {
		ms->ms_out_ms = NULL;
	}

	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (out_ms) {
			if (memcpy_s((void*)out_ms, _len_out_ms, __tmp_out_ms, _len_out_ms)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(int);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	void *__tmp_cpuinfo = NULL;

	CHECK_ENCLAVE_POINTER(cpuinfo, _len_cpuinfo);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (cpuinfo != NULL) ? _len_cpuinfo : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));
	ocalloc_size -= sizeof(ms_sgx_oc_cpuidex_t);

	if (cpuinfo != NULL) {
		if (memcpy_verw_s(&ms->ms_cpuinfo, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_cpuinfo = __tmp;
		if (_len_cpuinfo % sizeof(*cpuinfo) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		ocalloc_size -= _len_cpuinfo;
	} else {
		ms->ms_cpuinfo = NULL;
	}

	if (memcpy_verw_s(&ms->ms_leaf, sizeof(ms->ms_leaf), &leaf, sizeof(leaf))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_subleaf, sizeof(ms->ms_subleaf), &subleaf, sizeof(subleaf))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (cpuinfo) {
			if (memcpy_s((void*)cpuinfo, _len_cpuinfo, __tmp_cpuinfo, _len_cpuinfo)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);

	if (memcpy_verw_s(&ms->ms_self, sizeof(ms->ms_self), &self, sizeof(self))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);

	if (memcpy_verw_s(&ms->ms_waiter, sizeof(ms->ms_waiter), &waiter, sizeof(waiter))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);

	if (memcpy_verw_s(&ms->ms_waiter, sizeof(ms->ms_waiter), &waiter, sizeof(waiter))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_self, sizeof(ms->ms_self), &self, sizeof(self))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(void*);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(waiters, _len_waiters);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (waiters != NULL) ? _len_waiters : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);

	if (waiters != NULL) {
		if (memcpy_verw_s(&ms->ms_waiters, sizeof(const void**), &__tmp, sizeof(const void**))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_waiters % sizeof(*waiters) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, waiters, _len_waiters)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		ocalloc_size -= _len_waiters;
	} else {
		ms->ms_waiters = NULL;
	}

	if (memcpy_verw_s(&ms->ms_total, sizeof(ms->ms_total), &total, sizeof(total))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(6, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL pthread_wait_timeout_ocall(int* retval, unsigned long long waiter, unsigned long long timeout)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_pthread_wait_timeout_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_pthread_wait_timeout_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_pthread_wait_timeout_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_pthread_wait_timeout_ocall_t));
	ocalloc_size -= sizeof(ms_pthread_wait_timeout_ocall_t);

	if (memcpy_verw_s(&ms->ms_waiter, sizeof(ms->ms_waiter), &waiter, sizeof(waiter))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_timeout, sizeof(ms->ms_timeout), &timeout, sizeof(timeout))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(7, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL pthread_create_ocall(int* retval, unsigned long long self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_pthread_create_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_pthread_create_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_pthread_create_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_pthread_create_ocall_t));
	ocalloc_size -= sizeof(ms_pthread_create_ocall_t);

	if (memcpy_verw_s(&ms->ms_self, sizeof(ms->ms_self), &self, sizeof(self))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(8, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL pthread_wakeup_ocall(int* retval, unsigned long long waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_pthread_wakeup_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_pthread_wakeup_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_pthread_wakeup_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_pthread_wakeup_ocall_t));
	ocalloc_size -= sizeof(ms_pthread_wakeup_ocall_t);

	if (memcpy_verw_s(&ms->ms_waiter, sizeof(ms->ms_waiter), &waiter, sizeof(waiter))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(9, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

