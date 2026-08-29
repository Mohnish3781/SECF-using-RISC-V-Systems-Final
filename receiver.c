#include <stdio.h>
#include <stdint.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/uart.h"
#include "packet.h"

// ESP32 Hardware mappings
#define UART_NUM UART_NUM_2
#define TX_PIN 17
#define RX_PIN 16
#define BUF_SIZE 1024

void app_main() {
    Packet pkt;
    
    // Configure ESP32 Hardware UART
    uart_config_t uart_config = {
        .baud_rate = 115200,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE
    };
    uart_driver_install(UART_NUM, BUF_SIZE, 0, 0, NULL, 0);
    uart_param_config(UART_NUM, &uart_config);
    uart_set_pin(UART_NUM, TX_PIN, RX_PIN, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);

    printf("[*] Receiver Node Online. Listening continuously on UART%d...\n", UART_NUM);

    while (1) {
        // Read directly from the ESP32 RX buffer with a FreeRTOS delay instead of POSIX read()
        int bytes_read = uart_read_bytes(UART_NUM, (uint8_t*)&pkt, sizeof(Packet), portMAX_DELAY);

        if (bytes_read < (int)sizeof(Packet)) {
            continue;
        }

        uint16_t checksum = 0;
        for (int i = 0; i < pkt.length && i < MAX_PAYLOAD; i++) {
            checksum += pkt.payload[i];
        }

        if (pkt.header != MAGIC_HEADER) {
            printf("\n[X] Invalid Header (0x%X) - Skipping...\n", pkt.header);
            continue; 
        }

        if (checksum != pkt.checksum) {
            printf("\n[X] Checksum Error! Calculated: %u, Received: %u - Skipping...\n", checksum, pkt.checksum);
            continue; 
        }

        printf("\n===== Packet Received =====\n");
        printf("Header      : 0x%X\n", pkt.header);
        printf("Source ID   : %d\n", pkt.srcID);
        printf("Destination : %d\n", pkt.destID);
        printf("Type        : %d\n", pkt.type);
        printf("Length      : %d\n", pkt.length);
        printf("Payload     : %s\n", pkt.payload);
        printf("Checksum    : %u\n", pkt.checksum);
        printf("Sequence    : %u\n", pkt.seq);
        fflush(stdout); 
    }
}
