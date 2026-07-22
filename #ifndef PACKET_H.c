#ifndef PACKET_H
#define PACKET_H
#pragma pack(push,1)
#include <stdint.h>

#define MAGIC_HEADER 0xABCD1234

#define MAX_PAYLOAD 256
#define NONCE_SIZE 12
#define SALT_SIZE 16
#define TAG_SIZE 16

typedef struct
{
    uint32_t header;

    uint8_t type;

    uint8_t src_id;

    uint8_t dest_id;

    uint16_t length;

    uint32_t seq;

    uint32_t timestamp;

    uint8_t nonce[NONCE_SIZE];

    uint8_t salt[SALT_SIZE];

    uint8_t tag[TAG_SIZE];

    uint8_t payload[MAX_PAYLOAD];

} Packet;

#endif
#pragma pack(pop)