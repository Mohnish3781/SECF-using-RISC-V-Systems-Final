#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>

/* OpenSSL includes for cryptography */
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

/* =====================================================
   PACKET STRUCTURE DEFINITION (Must match packet.h)
   ===================================================== */

#pragma pack(push, 1)

#define MAGIC_HEADER 0xABCD1234
#define MAX_PAYLOAD 256
#define NONCE_SIZE 12
#define SALT_SIZE 16
#define TAG_SIZE 16
#define AES_KEY_SIZE 32
#define HMAC_KEY_SIZE 32

typedef struct {
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

#pragma pack(pop)

/* =====================================================
   GLOBAL CRYPTOGRAPHIC STATE & TRACKING
   ===================================================== */

/* Session key for AES-256-GCM (must match sender) */
static uint8_t session_key[AES_KEY_SIZE] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

/* HMAC key for authentication (must match sender) */
static uint8_t hmac_key[HMAC_KEY_SIZE] = {
    0x2f, 0x2e, 0x2d, 0x2c, 0x2b, 0x2a, 0x29, 0x28,
    0x27, 0x26, 0x25, 0x24, 0x23, 0x22, 0x21, 0x20,
    0x1f, 0x1e, 0x1d, 0x1c, 0x1b, 0x1a, 0x19, 0x18,
    0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x10
};

/* Replay protection: track seen sequence numbers */
#define MAX_SEQUENCE_WINDOW 1000
static uint32_t sequence_window[MAX_SEQUENCE_WINDOW];
static int sequence_index = 0;
static uint32_t last_seq = 0;

/* Statistics tracking */
typedef struct {
    int total_received;
    int total_valid;
    int auth_failures;
    int replay_detections;
    int malformed_packets;
    int decryption_errors;
    uint64_t total_bytes_decrypted;
} ReceiverStats;

static ReceiverStats stats = {0};


/* =====================================================
   CRYPTOGRAPHIC FUNCTIONS
   ===================================================== */

int aes_gcm_decrypt(
    uint8_t *ciphertext, int ciphertext_len,
    uint8_t *aad, int aad_len,
    uint8_t *nonce,
    uint8_t *tag,
    uint8_t *plaintext
) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx) return -1;
    
    int len = 0;
    int plaintext_len = 0;
    
    if(EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, session_key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    if(EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    if(EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;
    
    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    if(EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        stats.auth_failures++;
        return -1;
    }
    plaintext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

int verify_hmac_sha256(
    uint8_t *data, int data_len,
    uint8_t *expected_hmac
) {
    unsigned int hmac_len = 0;
    uint8_t computed_hmac[32];
    
    HMAC(
        EVP_sha256(),
        hmac_key, HMAC_KEY_SIZE,
        data, data_len,
        computed_hmac, &hmac_len
    );
    
    if(memcmp(computed_hmac, expected_hmac, TAG_SIZE) != 0) {
        return -1; 
    }
    return 0;
}

/* =====================================================
   REPLAY PROTECTION
   ===================================================== */

int check_sequence_counter(uint32_t seq) {
    for(int i = 0; i < sequence_index; i++) {
        if(sequence_window[i] == seq) {
            stats.replay_detections++;
            return -1;
        }
    }
    
    if(sequence_index < MAX_SEQUENCE_WINDOW) {
        sequence_window[sequence_index] = seq;
        sequence_index++;
    } else {
        memmove(sequence_window, sequence_window + 1, 
                (MAX_SEQUENCE_WINDOW - 1) * sizeof(uint32_t));
        sequence_window[MAX_SEQUENCE_WINDOW - 1] = seq;
    }
    
    last_seq = seq;
    return 0; 
}

/* =====================================================
   PACKET VALIDATION
   ===================================================== */

int validate_packet_header(Packet *pkt) {
    if(pkt->header != MAGIC_HEADER || pkt->type != 1 || pkt->length > MAX_PAYLOAD || pkt->src_id == 0 || pkt->dest_id == 0) {
        stats.malformed_packets++;
        return -1;
    }
    return 0;
}

int process_secure_packet(Packet *pkt, char *plaintext_out) {
    printf("\n==================================================\n");
    printf("[*] Encrypted Frame Received. Processing...\n");
    
    if(validate_packet_header(pkt) != 0) {
        printf("\033[91m[-] Dropping frame: Invalid Header\033[0m\n");
        return -1;
    }
    
    if(check_sequence_counter(pkt->seq) != 0) {
        printf("\033[91m[!] THREAT DETECTED: Replay Attack (Sequence %u). Frame dropped.\033[0m\n", pkt->seq);
        return -1;
    }
    
    uint8_t aad_buffer[32];
    int aad_pos = 0;
    memcpy(aad_buffer + aad_pos, &pkt->header, 4); aad_pos += 4;
    memcpy(aad_buffer + aad_pos, &pkt->type, 1); aad_pos += 1;
    memcpy(aad_buffer + aad_pos, &pkt->src_id, 1); aad_pos += 1;
    memcpy(aad_buffer + aad_pos, &pkt->dest_id, 1); aad_pos += 1;
    memcpy(aad_buffer + aad_pos, &pkt->length, 2); aad_pos += 2;
    memcpy(aad_buffer + aad_pos, &pkt->seq, 4); aad_pos += 4;
    memcpy(aad_buffer + aad_pos, &pkt->timestamp, 4); aad_pos += 4;
    
    uint8_t hmac_input[16 + TAG_SIZE + MAX_PAYLOAD];
    int pos = 0;
    memcpy(hmac_input + pos, aad_buffer, aad_pos); pos += aad_pos;
    memcpy(hmac_input + pos, pkt->tag, TAG_SIZE); pos += TAG_SIZE;
    memcpy(hmac_input + pos, pkt->payload, pkt->length); pos += pkt->length;

    if (verify_hmac_sha256(hmac_input, pos, pkt->salt) != 0) {
        printf("\033[91m[!] THREAT DETECTED: Authentication Failed! Frame was forged or tampered.\033[0m\n");
        stats.auth_failures++;
        return -1;
    }

    uint8_t decrypted[MAX_PAYLOAD];
    int plaintext_len = aes_gcm_decrypt(
        pkt->payload, pkt->length, aad_buffer, aad_pos,
        pkt->nonce, pkt->tag, decrypted
    );
    
    if(plaintext_len < 0) {
        printf("\033[91m[!] THREAT DETECTED: Authentication Failed! Frame was forged or tampered.\033[0m\n");
        stats.decryption_errors++;
        return -1;
    }
    
    memcpy(plaintext_out, decrypted, plaintext_len);
    plaintext_out[plaintext_len] = '\0';
    stats.total_bytes_decrypted += plaintext_len;
    
    printf("\033[92m[+] Authentication Verified! Payload Decrypted Successfully.\033[0m\n");
    printf("  ├── Sequence    : %u\n", pkt->seq);
    printf("  ├── Timestamp   : %u\n", pkt->timestamp);
    printf("  ├── Source ID   : %d\n", pkt->src_id);
    printf("  └── Message     : %s\n", plaintext_out);
    
    return plaintext_len;
}

/* =====================================================
   MAIN RECEIVER LOOP
   ===================================================== */

int main(int argc, char *argv[]) {
    printf("[*] Secure Receiver Node (Hardened) Online.\n");
    
    const char *pipe_from_attacker = "/tmp/secure_attacker_to_nodeB";
    mkfifo(pipe_from_attacker, 0666);
    
    printf("[*] Listening continuously on %s...\n", pipe_from_attacker);
    
    Packet pkt;
    char plaintext_buffer[MAX_PAYLOAD + 1];
    
    /* Outer loop ensures the terminal stays open and receiver continuously listens */
    while(1) {
        int fd = open(pipe_from_attacker, O_RDONLY);
        if(fd < 0) {
            usleep(100000);
            continue;
        }
        
        /* Inner loop reads data until the pipe is closed by sender */
        while(1) {
            ssize_t bytes_read = read(fd, &pkt, sizeof(Packet));
            
            if(bytes_read == 0) {
                break; /* Pipe closed, break to outer loop to reopen */
            }
            
            if(bytes_read < 0) {
                break;
            }
            
            if(bytes_read != sizeof(Packet)) {
                continue; /* Ignore fragmented bytes */
            }
            
            stats.total_received++;
            
            int result = process_secure_packet(&pkt, plaintext_buffer);
            
            if(result >= 0) {
                stats.total_valid++;
            }
        }
        close(fd);
    }
    
    return 0;
}
