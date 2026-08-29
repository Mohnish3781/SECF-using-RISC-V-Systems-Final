#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_timer.h"
#include "mbedtls/gcm.h"

void app_main() {
    printf("Starting ESP32 Hardware Crypto Benchmark...\n");
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    unsigned char key[32] = {0};
    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);

    unsigned char iv[12] = {0};
    unsigned char plaintext[256] = "BENCHMARK_PAYLOAD";
    unsigned char ciphertext[256];
    unsigned char tag[16];

    int64_t start = esp_timer_get_time();
    for(int i = 0; i < 10000; i++) {
        mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, 256, iv, 12, NULL, 0, plaintext, ciphertext, 16, tag);
    }
    int64_t end = esp_timer_get_time();
    
    printf("10,000 AES-256-GCM hardware operations took %lld us\n", (end - start));
    mbedtls_gcm_free(&gcm);
}
