#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/uart.h"
#include "esp_random.h"
#include "mbedtls/gcm.h"
#include "mbedtls/md.h"
#include "packet.h" // Ensure 317-byte packed struct

#define UART_NUM UART_NUM_2
#define TX_PIN 17
#define RX_PIN 16

const unsigned char AES_KEY[32] = "01234567890123456789012345678901"; // 256-bit key
const unsigned char HMAC_KEY[32] = "10987654321098765432109876543210";

void app_main() {
    uart_config_t uart_config = {
        .baud_rate = 115200,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE
    };
    uart_driver_install(UART_NUM, 2048, 0, 0, NULL, 0);
    uart_param_config(UART_NUM, &uart_config);
    uart_set_pin(UART_NUM, TX_PIN, RX_PIN, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);

    Packet pkt;
    memset(&pkt, 0, sizeof(Packet));
    pkt.header = MAGIC_HEADER;
    pkt.srcID = 1;
    pkt.destID = 2;
    pkt.type = 1;
    pkt.seq = 1;
    
    char *message = "CONFIDENTIAL HARDWARE PAYLOAD";
    pkt.length = strlen(message);
    
    // Hardware RNG for 12-byte Nonce
    esp_fill_random(pkt.nonce, 12);
    
    // HMAC-SHA256 over sequence and payload (using salt buffer for HMAC)
    mbedtls_md_context_t md_ctx;
    mbedtls_md_init(&md_ctx);
    mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    mbedtls_md_hmac_starts(&md_ctx, HMAC_KEY, 32);
    mbedtls_md_hmac_update(&md_ctx, (const unsigned char *)&pkt.seq, sizeof(pkt.seq));
    mbedtls_md_hmac_update(&md_ctx, (const unsigned char *)message, pkt.length);
    unsigned char full_hmac[32];
    mbedtls_md_hmac_finish(&md_ctx, full_hmac);
    memcpy(pkt.salt, full_hmac, 16); // Truncate to 16 bytes for struct
    mbedtls_md_free(&md_ctx);

    // Hardware Accelerated AES-256-GCM
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, AES_KEY, 256);
    mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, pkt.length,
                              pkt.nonce, 12, 
                              (const unsigned char*)&pkt.header, 12, // AAD
                              (const unsigned char*)message, pkt.payload,
                              16, pkt.tag);
    mbedtls_gcm_free(&gcm);

    uart_write_bytes(UART_NUM, (const char*)&pkt, sizeof(Packet));
    printf("[+] Hardened Encrypted Packet Dispatched (AES-256-GCM)\n");
}
