/* =====================================================
   bench_crypto.c
   IITI SOC 2026 - PS8: Real performance benchmark
   Domain 4: Protocol Hardening & Performance Engineering

   UPDATED TO MATCH PROPOSAL:
   - AES-128-CBC encryption (instead of AES-256-GCM)
   - CRC-32 integrity check 
   - HMAC-SHA-256 authentication
   - 32-bit sequence counter validation
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

#define AES_KEY_SIZE 16   // AES-128
#define HMAC_KEY_SIZE 32  // SHA-256
#define IV_SIZE 16        // CBC Block Size
#define PAYLOAD_SIZE 256
#define HEADER_SIZE 16    // Magic(4) + Type(1) + Len(2) + Seq(4) + Padding(5)

#define NUM_PACKETS_LATENCY 100
#define NUM_PACKETS_THROUGHPUT 1000
#define NUM_ITER_OVERHEAD 1000
#define NUM_ITER_SEQ 100000

static uint8_t session_key[AES_KEY_SIZE] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
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

/* ---- real AES-128-CBC encrypt ---- */
static int aes_cbc_encrypt(uint8_t *pt, int pt_len, uint8_t *iv, uint8_t *ct) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, ct_len = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, session_key, iv);
    EVP_EncryptUpdate(ctx, ct, &len, pt, pt_len);
    ct_len = len;
    EVP_EncryptFinal_ex(ctx, ct + len, &len);
    ct_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return ct_len;
}

static void hmac_sha256(uint8_t *data, int len, uint8_t *out) {
    unsigned int out_len = 0;
    HMAC(EVP_sha256(), hmac_key, HMAC_KEY_SIZE, data, len, out, &out_len);
}

/* ---- CRC-32 Implementation ---- */
static uint32_t crc32_for_byte(uint32_t r) {
    for(int j = 0; j < 8; ++j)
        r = (r & 1? 0: (uint32_t)0xEDB88320L) ^ r >> 1;
    return r ^ (uint32_t)0xFF000000L;
}

static uint32_t calculate_crc32(const void *data, size_t n_bytes) {
    uint32_t crc = 0;
    static uint32_t table[256];
    static int initialized = 0;
    if(!initialized) {
        for(size_t i = 0; i < 256; ++i) table[i] = crc32_for_byte(i);
        initialized = 1;
    }
    for(size_t i = 0; i < n_bytes; ++i)
        crc = table[(uint8_t)crc ^ ((uint8_t*)data)[i]] ^ crc >> 8;
    return crc;
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
    uint8_t plaintext[PAYLOAD_SIZE], ciphertext[PAYLOAD_SIZE + 16]; 
    uint8_t iv[IV_SIZE], header[HEADER_SIZE], hmac_out[32];
    RAND_bytes(plaintext, PAYLOAD_SIZE);
    RAND_bytes(iv, IV_SIZE);
    RAND_bytes(header, HEADER_SIZE);

    /* ---------- LATENCY: baseline vs hardened ---------- */
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
        // 1. Encrypt Payload
        int ct_len = aes_cbc_encrypt(plaintext, PAYLOAD_SIZE, iv, ciphertext);
        
        // 2. Calculate CRC-32 (Fast Integrity)
        uint32_t crc_val = calculate_crc32(ciphertext, ct_len);
        
        // 3. Calculate HMAC (Cryptographic Integrity) over header + ciphertext
        uint8_t hmac_in[HEADER_SIZE + PAYLOAD_SIZE + 16];
        memcpy(hmac_in, header, HEADER_SIZE);
        memcpy(hmac_in + HEADER_SIZE, ciphertext, ct_len);
        hmac_sha256(hmac_in, HEADER_SIZE + ct_len, hmac_out);
        
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
    double base_mbps = (NUM_PACKETS_THROUGHPUT * PAYLOAD_SIZE * 8 / 1e6) / base_time_sec;

    t0 = now_us();
    for (int i = 0; i < NUM_PACKETS_THROUGHPUT; i++) {
        int ct_len = aes_cbc_encrypt(plaintext, PAYLOAD_SIZE, iv, ciphertext);
        calculate_crc32(ciphertext, ct_len);
        uint8_t hmac_in[HEADER_SIZE + PAYLOAD_SIZE + 16];
        memcpy(hmac_in, header, HEADER_SIZE);
        memcpy(hmac_in + HEADER_SIZE, ciphertext, ct_len);
        hmac_sha256(hmac_in, HEADER_SIZE + ct_len, hmac_out);
    }
    t1 = now_us();
    double hard_time_sec = (t1 - t0) / 1e6;
    double hard_pps = NUM_PACKETS_THROUGHPUT / hard_time_sec;
    double hard_mbps = (NUM_PACKETS_THROUGHPUT * PAYLOAD_SIZE * 8 / 1e6) / hard_time_sec;
    double throughput_reduction_pct = (base_pps - hard_pps) / base_pps * 100.0;

    /* ---------- PER-MECHANISM OVERHEAD ---------- */
    double aes_times[NUM_ITER_OVERHEAD], hmac_times[NUM_ITER_OVERHEAD], crc_times[NUM_ITER_OVERHEAD];
    for (int i = 0; i < NUM_ITER_OVERHEAD; i++) {
        double a = now_us();
        aes_cbc_encrypt(plaintext, PAYLOAD_SIZE, iv, ciphertext);
        aes_times[i] = now_us() - a;
    }
    for (int i = 0; i < NUM_ITER_OVERHEAD; i++) {
        double a = now_us();
        calculate_crc32(ciphertext, PAYLOAD_SIZE);
        crc_times[i] = now_us() - a;
    }
    for (int i = 0; i < NUM_ITER_OVERHEAD; i++) {
        uint8_t hmac_in[HEADER_SIZE + PAYLOAD_SIZE];
        memcpy(hmac_in, header, HEADER_SIZE);
        memcpy(hmac_in + HEADER_SIZE, ciphertext, PAYLOAD_SIZE);
        double a = now_us();
        hmac_sha256(hmac_in, sizeof(hmac_in), hmac_out);
        hmac_times[i] = now_us() - a;
    }
    
    double *seq_times = malloc(NUM_ITER_SEQ * sizeof(double));
    uint32_t window[1000]; int widx = 0;
    for (int i = 0; i < NUM_ITER_SEQ; i++) {
        double a = now_us();
        int found = 0;
        for (int j = 0; j < widx; j++) if (window[j] == (uint32_t)i) { found = 1; break; }
        if (!found && widx < 1000) window[widx++] = (uint32_t)i;
        seq_times[i] = now_us() - a;
    }
    
    Stats aes_s = compute_stats(aes_times, NUM_ITER_OVERHEAD);
    Stats hmac_s = compute_stats(hmac_times, NUM_ITER_OVERHEAD);
    Stats crc_s = compute_stats(crc_times, NUM_ITER_OVERHEAD);
    Stats seq_s = compute_stats(seq_times, NUM_ITER_SEQ);
    free(seq_times);
    double total_crypto_overhead_us = aes_s.mean + hmac_s.mean + crc_s.mean;

    /* ---------- OUTPUT JSON ---------- */
    printf("{\n");
    printf("  \"methodology\": \"real measurements via clock_gettime(CLOCK_MONOTONIC) measuring AES-128-CBC, CRC-32, and HMAC-SHA256 calls\",\n");
    printf("  \"payload_size_bytes\": %d,\n", PAYLOAD_SIZE);
    printf("  \"latency\": {\n");
    printf("    \"baseline\": {\"min_us\": %.4f, \"max_us\": %.4f, \"mean_us\": %.4f, \"median_us\": %.4f, \"stdev_us\": %.4f, \"p95_us\": %.4f, \"p99_us\": %.4f},\n",
           sb.min, sb.max, sb.mean, sb.median, sb.stdev, sb.p95, sb.p99);
    printf("    \"hardened\": {\"min_us\": %.4f, \"max_us\": %.4f, \"mean_us\": %.4f, \"median_us\": %.4f, \"stdev_us\": %.4f, \"p95_us\": %.4f, \"p99_us\": %.4f},\n",
           sh.min, sh.max, sh.mean, sh.median, sh.stdev, sh.p95, sh.p99);
    printf("    \"overhead_percent\": %.4f\n", latency_overhead_pct);
    printf("  },\n");
    printf("  \"throughput\": {\n");
    printf("    \"baseline\": {\"packets_per_second\": %.4f, \"mbps\": %.4f, \"total_time_sec\": %.6f},\n",
           base_pps, base_mbps, base_time_sec);
    printf("    \"hardened\": {\"packets_per_second\": %.4f, \"mbps\": %.4f, \"total_time_sec\": %.6f},\n",
           hard_pps, hard_mbps, hard_time_sec);
    printf("    \"reduction_percent\": %.4f\n", throughput_reduction_pct);
    printf("  },\n");
    printf("  \"overhead\": {\n");
    printf("    \"aes\": {\"mechanism\": \"AES-128-CBC Encryption\", \"avg_time_us\": %.4f, \"min_time_us\": %.4f, \"max_time_us\": %.4f},\n",
           aes_s.mean, aes_s.min, aes_s.max);
    printf("    \"crc\": {\"mechanism\": \"CRC-32 Integrity\", \"avg_time_us\": %.4f, \"min_time_us\": %.4f, \"max_time_us\": %.4f},\n",
           crc_s.mean, crc_s.min, crc_s.max);
    printf("    \"hmac\": {\"mechanism\": \"HMAC-SHA256 Verification\", \"avg_time_us\": %.4f, \"min_time_us\": %.4f, \"max_time_us\": %.4f},\n",
           hmac_s.mean, hmac_s.min, hmac_s.max);
    printf("    \"sequence\": {\"mechanism\": \"Sequence Counter Validation\", \"avg_time_us\": %.4f, \"min_time_us\": %.4f, \"max_time_us\": %.4f},\n",
           seq_s.mean, seq_s.min, seq_s.max);
    printf("    \"total_crypto_overhead_us\": %.4f\n", total_crypto_overhead_us);
    printf("  },\n");
    printf("  \"jitter\": {\n");
    printf("    \"baseline_stdev_us\": %.4f,\n", sb.stdev);
    printf("    \"hardened_stdev_us\": %.4f\n", sh.stdev);
    printf("  }\n");
    printf("}\n");

    return 0;
}
