#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>

#define MAGIC_HEADER 0xABCD1234
#define MAX_PAYLOAD 256

/* 
 * CRITICAL: Force 1-byte alignment for hardware UART transmission.
 * This guarantees the struct is exactly 317 bytes over the wire, 
 * matching the Python struct.unpack("<IBBBHII12s16s16s256s") format.
 */
#pragma pack(push, 1)
typedef struct {
    uint32_t header;       // 4 bytes  - Magic Identifier
    uint8_t  type;         // 1 byte   - Packet Type Tag
    uint8_t  srcID;        // 1 byte   - Source Node
    uint8_t  destID;       // 1 byte   - Destination Node
    uint16_t length;       // 2 bytes  - Payload Length
    uint32_t seq;          // 4 bytes  - Monotonic Sequence Counter
    uint32_t timestamp;    // 4 bytes  - Transmission Time
    uint8_t  nonce[12];    // 12 bytes - AES-GCM IV
    uint8_t  salt[16];     // 16 bytes - HMAC-SHA256 Integrity Hash
    uint8_t  tag[16];      // 16 bytes - AES-GCM Auth Tag
    uint8_t  payload[MAX_PAYLOAD]; // 256 bytes - Ciphertext
} Packet;
#pragma pack(pop)

#endif
