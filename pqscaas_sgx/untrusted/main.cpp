/*
 * main.cpp — PQSCAAS SGX experiment runner.
 *
 * Usage:
 *   ./pqscaas_experiments               # run all 8 experiments
 *   ./pqscaas_experiments --exp 1 3 7   # run selected experiments
 *   ./pqscaas_experiments --calibrate   # print SGX primitive timings only
 *
 * Build: make SGX_MODE=SIM
 * Requires: source /opt/intel/sgxsdk/environment
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <set>

#include "sgx_urts.h"
#include "pqscaas_enclave_u.h"
#include "experiments.h"

/* OCALL implementations ------------------------------------------------------ */

void ocall_print(const char *msg) {
    printf("[enclave] %s\n", msg);
}

void ocall_get_time_ms(double *ms) {
    using Clock = std::chrono::high_resolution_clock;
    *ms = std::chrono::duration<double, std::milli>(
        Clock::now().time_since_epoch()).count();
}

/* Enclave init --------------------------------------------------------------- */

static sgx_enclave_id_t create_enclave(const char *enclave_path) {
    sgx_enclave_id_t eid = 0;
    sgx_launch_token_t token = {0};
    int updated = 0;

    sgx_status_t ret = sgx_create_enclave(
        enclave_path,
        SGX_DEBUG_FLAG,   /* 1 = debug, 0 = production */
        &token, &updated,
        &eid, nullptr
    );
    if (ret != SGX_SUCCESS) {
        fprintf(stderr, "ERROR: sgx_create_enclave failed (0x%04x)\n"
                        "       Is the SGX SDK environment sourced?\n"
                        "       Run: source /opt/intel/sgxsdk/environment\n",
                (unsigned)ret);
        exit(1);
    }
    printf("[main] Enclave created (eid=%lu, sim=%s)\n",
           (unsigned long)eid,
#ifdef SGX_SIM
           "true"
#else
           "false"
#endif
    );
    return eid;
}

/* Calibration printout ------------------------------------------------------- */

static void run_calibrate(sgx_enclave_id_t eid) {
    printf("\n=== SGX Primitive Calibration (n=20 samples) ===\n");

    double ecall_oh = calibrate_ecall_overhead_ms(eid, 20);
    printf("  ECALL entry+exit overhead:  %.4f ms\n", ecall_oh);

    sgx_status_t cal_ret = SGX_SUCCESS;
    double seal_ms, unseal_ms, sha_ms, hkdf_ms,
           kem_kg_ms, dsa_kg_ms, kem_enc_ms, dsa_sign_ms;
    sgx_status_t call_status = ecall_calibrate_ops(eid, &cal_ret, 20,
        &seal_ms, &unseal_ms, &sha_ms, &hkdf_ms,
        &kem_kg_ms, &dsa_kg_ms, &kem_enc_ms, &dsa_sign_ms);
    if (call_status != SGX_SUCCESS || cal_ret != SGX_SUCCESS) {
        fprintf(stderr, "ERROR: ecall_calibrate_ops failed (call=0x%04x, enclave=0x%04x)\n",
                (unsigned)call_status, (unsigned)cal_ret);
        exit(1);
    }

    printf("  sgx_seal_data (48B):        %.4f ms  [REAL]\n",   seal_ms);
    printf("  sgx_unseal_data (48B):      %.4f ms  [REAL]\n",   unseal_ms);
    printf("  sgx_sha256_msg (48B):       %.4f ms  [REAL]\n",   sha_ms);
    printf("  HKDF-SHA256:                %.4f ms  [REAL]\n",   hkdf_ms);
    printf("  ML-KEM-768 keygen (mock):   %.4f ms  [MOCK lognormal]\n", kem_kg_ms);
    printf("  ML-DSA-65  keygen (mock):   %.4f ms  [MOCK lognormal]\n", dsa_kg_ms);
    printf("  ML-KEM-768 encap  (mock):   %.4f ms  [MOCK lognormal]\n", kem_enc_ms);
    printf("  ML-DSA-65  sign   (mock):   %.4f ms  [MOCK lognormal]\n", dsa_sign_ms);
    printf("================================================\n\n");
}

/* Main ----------------------------------------------------------------------- */

int main(int argc, char *argv[]) {
    /* Parse arguments */
    bool do_calibrate   = false;
    std::set<int> selected_exps;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--calibrate") == 0) {
            do_calibrate = true;
        } else if (strcmp(argv[i], "--exp") == 0) {
            while (i + 1 < argc && argv[i + 1][0] != '-') {
                i++;
                selected_exps.insert(atoi(argv[i]));
            }
        }
    }

    /* Select all 8 if none specified */
    if (selected_exps.empty() && !do_calibrate)
        for (int e = 1; e <= 8; e++) selected_exps.insert(e);

    /* Initialize enclave */
    sgx_enclave_id_t eid = create_enclave("pqscaas_enclave.signed.so");

    if (do_calibrate) {
        run_calibrate(eid);
    }

    /* Create results directory */
    system("mkdir -p results figures");

    using Clock = std::chrono::high_resolution_clock;
    auto t_start = Clock::now();

    auto run = [&](int exp_id, auto fn) {
        if (selected_exps.count(exp_id)) {
            auto t0 = Clock::now();
            fn(eid);
            double secs = std::chrono::duration<double>(Clock::now() - t0).count();
            printf("[main] Experiment %d completed in %.1f s\n\n", exp_id, secs);
        }
    };

    run(1, exp1_phase4_vs_filesize);
    run(2, exp2_signcrypt_batch_vs_requests);
    run(3, exp3_phase5_vs_filesize);
    run(4, exp4_unsigncrypt_vs_requests);
    run(5, exp5_signcrypt_throughput);
    run(6, exp6_unsigncrypt_throughput);
    run(7, exp7_revocation);
    run(8, exp8_keygen_vs_users);

    double total_secs = std::chrono::duration<double>(Clock::now() - t_start).count();
    printf("[main] All experiments done in %.1f s\n", total_secs);
    printf("[main] Run: python3 plot_all.py  to generate figures\n");

    sgx_destroy_enclave(eid);
    return 0;
}
