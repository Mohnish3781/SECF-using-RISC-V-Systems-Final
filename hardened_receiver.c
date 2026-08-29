#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/uart.h"
#include "mbedtls/gcm.h"
#include "mbedtls/md.h"
#include "packet.h"

#define UART_NUM UART_NUM_2
#define TX_PIN 17
#define RX_PIN 16

const unsigned char AES_KEY[32] = "01234567890123456789012345678901"; 
const unsigned char HMAC_KEY[32] = "10987654321098765432109876543210";
uint32_t expected_seq = 1;

void app_main() {
    uart_config_t uart_config = { /* Same as Sender */
        .baud_rate = 115200, .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE, .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE
    };
    uart_driver_install(UART_NUM, 1024, 0, 0, NULL, 0);
    uart_param_config(UART_NUM, &uart_config);
    uart_set_pin(UART_NUM, TX_PIN, RX_PIN, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);

    Packet pkt;
    printf("[*] Hardened Hardware Receiver Listening...\n");

    while (1) {
        int len = uart_read_bytes(UART_NUM, (uint8_t*)&pkt, sizeof(Packet), portMAX_DELAY);
        if (len < sizeof(Packet)) continue;
        
        if (pkt.seq < expected_seq) {
            printf("[!] Anti-Replay: Stale packet dropped (Seq: %lu)\n", pkt.seq);
            continue;
        }

        unsigned char decrypted[256] = {0};
        mbedtls_gcm_context gcm;
        mbedtls_gcm_init(&gcm);
        mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, AES_KEY, 256);
        
        int ret = mbedtls_gcm_auth_decrypt(&gcm, pkt.length,
                                           pkt.nonce, 12,
                                           (const unsigned char*)&pkt.header, 12, // AAD
                                           pkt.tag, 16,
                                           pkt.payload, decrypted);
        mbedtls_gcm_free(&gcm);

        if (ret != 0) {
            printf("[!] AES-GCM Auth Failed! Integrity Tampering Detected.\n");
            continue;
        }
        
        printf("[+] Verified SECF Packet: %s (Seq: %lu)\n", decrypted, pkt.seq);
        expected_seq = pkt.seq + 1;
    }
}
