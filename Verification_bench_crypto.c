/* =====================================================
   bench_crypto.c
   IITI SOC 2026 - PS8: Real (non-simulated) performance benchmark
   Member 4: Protocol Hardening & Performance Engineering

   Outputs purely JSON for the wrapper script to format into tables.
   ===================================================== */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <math.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#define AES_KEY_SIZE 32
#define HMAC_KEY_SIZE 32
#define NONCE_SIZE 12
#define TAG_SIZE 16
#define PAYLOAD_SIZE 256
#define AAD_SIZE 16

#define NUM_PACKETS_LATENCY 100
#define NUM_PACKETS_THROUGHPUT 1000

static uint8_t session_key[AES_KEY_SIZE] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
};
static uint8_t hmac_key[HMAC_KEY_SIZE] = {
    0x2f,0x2e,0x2d,0x2c,0x2b,0x2a,0x29,0x28,
    0x27,0x26,0x25,0x24,0x23,0x22,0x21,0x20,
    0x1f,0x1e,0x1d,0x1c,0x1b,0x1a,0x19,0x18,
    0x17,0x16,0x15,0x14,0x13,0x12,0x11,0x10
};

/* ---- timing helper ---- */
static double now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e6 + ts.tv_nsec / 1e3;
}

/* ---- real AES-256-GCM encrypt ---- */
static int aes_gcm_encrypt(uint8_t *pt, int pt_len, uint8_t *aad, int aad_len,
                            uint8_t *nonce, uint8_t *ct, uint8_t *tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, ct_len = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, session_key, nonce);
    EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len);
    EVP_EncryptUpdate(ctx, ct, &len, pt, pt_len);
    ct_len = len;
    EVP_EncryptFinal_ex(ctx, ct + len, &len);
    ct_len += len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag);
    EVP_CIPHER_CTX_free(ctx);
    return ct_len;
}

static void hmac_sha256(uint8_t *data, int len, uint8_t *out) {
    unsigned int out_len = 0;
    HMAC(EVP_sha256(), hmac_key, HMAC_KEY_SIZE, data, len, out, &out_len);
}

/* ---- stats helpers ---- */
typedef struct { double min, max, mean, median, stdev, p95, p99; } Stats;

static int cmp_d(const void *a, const void *b) {
    double da = *(const double*)a, db = *(const double*)b;
    return (da > db) - (da < db);
}

static Stats compute_stats(double *v, int n) {
    Stats s = {0};
    double *sorted = malloc(n * sizeof(double));
    memcpy(sorted, v, n * sizeof(double));
    qsort(sorted, n, sizeof(double), cmp_d);

    double sum = 0;
    s.min = sorted[0]; s.max = sorted[n-1];
    for (int i = 0; i < n; i++) sum += v[i];
    s.mean = sum / n;
    s.median = (n % 2) ? sorted[n/2] : (sorted[n/2-1] + sorted[n/2]) / 2.0;

    double sq = 0;
    for (int i = 0; i < n; i++) sq += (v[i]-s.mean)*(v[i]-s.mean);
    s.stdev = (n > 1) ? sqrt(sq/(n-1)) : 0;

    s.p95 = sorted[(int)(n*0.95)];
    s.p99 = sorted[(int)(n*0.99)];
    free(sorted);
    return s;
}

int main(void) {
    uint8_t plaintext[PAYLOAD_SIZE], ciphertext[PAYLOAD_SIZE], tag[TAG_SIZE];
    uint8_t nonce[NONCE_SIZE], aad[AAD_SIZE], hmac_out[32];
    RAND_bytes(plaintext, PAYLOAD_SIZE);
    RAND_bytes(nonce, NONCE_SIZE);
    RAND_bytes(aad, AAD_SIZE);

    /* ---------- LATENCY ---------- */
    double lat_base[NUM_PACKETS_LATENCY], lat_hard[NUM_PACKETS_LATENCY];
    uint8_t scratch[PAYLOAD_SIZE];

    for (int i = 0; i < NUM_PACKETS_LATENCY; i++) {
        double t0 = now_us();
        memcpy(scratch, plaintext, PAYLOAD_SIZE);
        double t1 = now_us();
        lat_base[i] = t1 - t0;
    }
    for (int i = 0; i < NUM_PACKETS_LATENCY; i++) {
        double t0 = now_us();
        aes_gcm_encrypt(plaintext, PAYLOAD_SIZE, aad, AAD_SIZE, nonce, ciphertext, tag);
        uint8_t hmac_in[AAD_SIZE + TAG_SIZE + PAYLOAD_SIZE];
        memcpy(hmac_in, aad, AAD_SIZE);
        memcpy(hmac_in + AAD_SIZE, tag, TAG_SIZE);
        memcpy(hmac_in + AAD_SIZE + TAG_SIZE, ciphertext, PAYLOAD_SIZE);
        hmac_sha256(hmac_in, sizeof(hmac_in), hmac_out);
        double t1 = now_us();
        lat_hard[i] = t1 - t0;
    }
    
    Stats sb = compute_stats(lat_base, NUM_PACKETS_LATENCY);
    Stats sh = compute_stats(lat_hard, NUM_PACKETS_LATENCY);
    double latency_overhead_pct = (sh.mean - sb.mean) / sb.mean * 100.0;

    /* ---------- THROUGHPUT ---------- */
    double t0 = now_us();
    for (int i = 0; i < NUM_PACKETS_THROUGHPUT; i++) memcpy(scratch, plaintext, PAYLOAD_SIZE);
    double t1 = now_us();
    double base_time_sec = (t1 - t0) / 1e6;
    double base_pps = NUM_PACKETS_THROUGHPUT / base_time_sec;

    t0 = now_us();
    for (int i = 0; i < NUM_PACKETS_THROUGHPUT; i++) {
        aes_gcm_encrypt(plaintext, PAYLOAD_SIZE, aad, AAD_SIZE, nonce, ciphertext, tag);
        uint8_t hmac_in[AAD_SIZE + TAG_SIZE + PAYLOAD_SIZE];
        memcpy(hmac_in, aad, AAD_SIZE);
        memcpy(hmac_in + AAD_SIZE, tag, TAG_SIZE);
        memcpy(hmac_in + AAD_SIZE + TAG_SIZE, ciphertext, PAYLOAD_SIZE);
        hmac_sha256(hmac_in, sizeof(hmac_in), hmac_out);
    }
    t1 = now_us();
    double hard_time_sec = (t1 - t0) / 1e6;
    double hard_pps = NUM_PACKETS_THROUGHPUT / hard_time_sec;

    /* ---------- OUTPUT JSON ---------- */
    printf("{\n");
    printf("  \"latency\": {\n");
    printf("    \"baseline\": {\"mean_us\": %.4f},\n", sb.mean);
    printf("    \"hardened\": {\"mean_us\": %.4f},\n", sh.mean);
    printf("    \"overhead_percent\": %.4f\n", latency_overhead_pct);
    printf("  },\n");
    printf("  \"throughput\": {\n");
    printf("    \"baseline\": {\"packets_per_second\": %.4f, \"total_time_sec\": %.6f},\n", base_pps, base_time_sec);
    printf("    \"hardened\": {\"packets_per_second\": %.4f, \"total_time_sec\": %.6f}\n", hard_pps, hard_time_sec);
    printf("  },\n");
    printf("  \"jitter\": {\n");
    printf("    \"baseline_stdev_us\": %.4f,\n", sb.stdev);
    printf("    \"hardened_stdev_us\": %.4f\n", sh.stdev);
    printf("  }\n");
    printf("}\n");

    return 0;
}
