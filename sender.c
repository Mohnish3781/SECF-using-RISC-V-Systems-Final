#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/uart.h"
#include "packet.h" // Ensures packed structs

#define UART_NUM UART_NUM_2
#define TX_PIN 17
#define RX_PIN 16

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
    uart_driver_install(UART_NUM, 2048, 0, 0, NULL, 0);
    uart_param_config(UART_NUM, &uart_config);
    uart_set_pin(UART_NUM, TX_PIN, RX_PIN, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);

    // Build Packet Frame
    pkt.header = MAGIC_HEADER;
    pkt.srcID = 1;
    pkt.destID = 2;
    pkt.type = 1;
    pkt.seq = 1;
    strcpy((char*)pkt.payload, "HELLO FROM NODE A");
    pkt.length = strlen((char*)pkt.payload);
    pkt.checksum = 0;

    for(int i = 0; i < pkt.length; i++) {
        pkt.checksum += pkt.payload[i];
    }

    // Transmit over UART
    uart_write_bytes(UART_NUM, (const char*)&pkt, sizeof(Packet));
    printf("[*] Packet Sent via hardware UART\n");
}
