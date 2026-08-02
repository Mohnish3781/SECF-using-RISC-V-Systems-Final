/* =====================================================
   bench_crypto.c (OPTIMIZED FOR ULTRA-LOW LATENCY)
   IITI SOC 2026 - PS8
   - Uses AES-256-GCM
   - Context Reuse (Eradicates malloc() inside loops)
   ===================================================== */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <math.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#define AES_KEY_SIZE 32   // AES-256
#define IV_SIZE 12        // GCM Recommended IV size
#define TAG_SIZE 16       // GCM Auth Tag
#define PAYLOAD_SIZE 256

#define NUM_PACKETS_LATENCY 1000
#define NUM_PACKETS_THROUGHPUT 100000

static uint8_t session_key[AES_KEY_SIZE];
static uint8_t iv[IV_SIZE];

/* Pre-allocate Context (Crucial for <5us latency) */
EVP_CIPHER_CTX *global_ctx;

static void setup_crypto() {
    RAND_bytes(session_key, AES_KEY_SIZE);
    RAND_bytes(iv, IV_SIZE);
    global_ctx = EVP_CIPHER_CTX_new();
}

static void cleanup_crypto() {
    EVP_CIPHER_CTX_free(global_ctx);
}

static double now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e6 + ts.tv_nsec / 1e3;
}

/* Highly Optimized AES-GCM Encrypt using global_ctx */
static int aes_gcm_encrypt_optimized(uint8_t *pt, int pt_len, uint8_t *ct, uint8_t *tag) {
    int len = 0, ct_len = 0;
    
    // Reuse context, only reset IV and Key
    EVP_EncryptInit_ex(global_ctx, EVP_aes_256_gcm(), NULL, session_key, iv);
    EVP_EncryptUpdate(global_ctx, ct, &len, pt, pt_len);
    ct_len = len;
    
    EVP_EncryptFinal_ex(global_ctx, ct + len, &len);
    ct_len += len;
    
    // Extract Authentication Tag
    EVP_CIPHER_CTX_ctrl(global_ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag);
    return ct_len;
}

int main(void) {
    uint8_t plaintext[PAYLOAD_SIZE], ciphertext[PAYLOAD_SIZE + 16]; 
    uint8_t tag[TAG_SIZE];
    RAND_bytes(plaintext, PAYLOAD_SIZE);
    
    setup_crypto();

    /* ---------- LATENCY MEASUREMENT ---------- */
    double lat_hard[NUM_PACKETS_LATENCY];
    double total_hard = 0;

    for (int i = 0; i < NUM_PACKETS_LATENCY; i++) {
        double t0 = now_us();
        aes_gcm_encrypt_optimized(plaintext, PAYLOAD_SIZE, ciphertext, tag);
        double t1 = now_us();
        lat_hard[i] = t1 - t0;
        total_hard += lat_hard[i];
    }
    double mean_latency = total_hard / NUM_PACKETS_LATENCY;

    /* ---------- THROUGHPUT MEASUREMENT ---------- */
    double t0 = now_us();
    for (int i = 0; i < NUM_PACKETS_THROUGHPUT; i++) {
        aes_gcm_encrypt_optimized(plaintext, PAYLOAD_SIZE, ciphertext, tag);
    }
    double t1 = now_us();
    
    double hard_time_sec = (t1 - t0) / 1e6;
    double hard_fps = NUM_PACKETS_THROUGHPUT / hard_time_sec;

    /* ---------- OUTPUT ---------- */
    printf("{\n");
    printf("  \"metric_status\": \"OPTIMIZED\",\n");
    printf("  \"mean_latency_us\": %.4f,\n", mean_latency);
    printf("  \"mean_latency_ms\": %.6f,\n", mean_latency / 1000.0);
    printf("  \"throughput_fps\": %.0f\n", hard_fps);
    printf("}\n");

    cleanup_crypto();
    return 0;
}
