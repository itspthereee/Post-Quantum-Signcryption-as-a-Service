#pragma once
#include "sgx_urts.h"

/* All 8 experiments. Each saves results/<name>.csv and results/<name>.json.
 * eid: initialized SGX enclave ID. */

void exp1_phase4_vs_filesize(sgx_enclave_id_t eid);
void exp2_signcrypt_batch_vs_requests(sgx_enclave_id_t eid);
void exp3_phase5_vs_filesize(sgx_enclave_id_t eid);
void exp4_unsigncrypt_vs_requests(sgx_enclave_id_t eid);
void exp5_signcrypt_throughput(sgx_enclave_id_t eid);
void exp6_unsigncrypt_throughput(sgx_enclave_id_t eid);
void exp7_revocation(sgx_enclave_id_t eid);
void exp8_keygen_vs_users(sgx_enclave_id_t eid);

/* Calibrate ECALL enter/exit overhead (mean of n_samples noop ECALLs). */
double calibrate_ecall_overhead_ms(sgx_enclave_id_t eid, int n_samples = 20);
