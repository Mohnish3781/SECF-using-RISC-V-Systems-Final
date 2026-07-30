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
   UTILITY FUNCTIONS
   ===================================================== */

/**
 * Print hex buffer for debugging
 */
void print_hex(const char *label, uint8_t *data, int len) {
    printf("%s: ", label);
    for(int i = 0; i < len && i < 32; i++) {
        printf("%02x", data[i]);
    }
    if(len > 32) printf("...");
    printf("\n");
}

/**
 * Get current timestamp
 */
uint32_t get_timestamp(void) {
    return (uint32_t)time(NULL);
}

/**
 * Format timestamp for display
 */
char *format_time(uint32_t timestamp) {
    static char buffer[32];
    time_t t = (time_t)timestamp;
    struct tm *tm_info = localtime(&t);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", tm_info);
    return buffer;
}

/* =====================================================
   CRYPTOGRAPHIC FUNCTIONS
   ===================================================== */

/**
 * AES-256-GCM Decryption with Additional Authenticated Data (AAD)
 * 
 * Decrypts ciphertext with AES-256 in GCM mode
 * AAD includes: header, type, src_id, dest_id, length, seq, timestamp
 * Verifies authentication tag
 */
int aes_gcm_decrypt(
    uint8_t *ciphertext, int ciphertext_len,
    uint8_t *aad, int aad_len,
    uint8_t *nonce,
    uint8_t *tag,
    uint8_t *plaintext
) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx) {
        fprintf(stderr, "[-] Failed to create cipher context\n");
        return -1;
    }
    
    int len = 0;
    int plaintext_len = 0;
    
    /* Initialize cipher context with AES-256-GCM */
    if(EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, session_key, nonce) != 1) {
        fprintf(stderr, "[-] EVP_DecryptInit_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    /* Set AAD (Additional Authenticated Data) */
    if(EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len) != 1) {
        fprintf(stderr, "[-] Failed to set AAD\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    /* Decrypt ciphertext */
    if(EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        fprintf(stderr, "[-] EVP_DecryptUpdate failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;
    
    /* Set expected authentication tag */
    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag) != 1) {
        fprintf(stderr, "[-] Failed to set GCM tag for verification\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    /* Finalize decryption and verify tag */
    if(EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        fprintf(stderr, "[-] Authentication tag verification FAILED!\n");
        EVP_CIPHER_CTX_free(ctx);
        stats.auth_failures++;
        return -1;
    }
    plaintext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    
    return plaintext_len;
}

/**
 * Verify HMAC-SHA256 over packet header
 * (Additional verification layer)
 */
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
    
    /* Compare first TAG_SIZE bytes */
    if(memcmp(computed_hmac, expected_hmac, TAG_SIZE) != 0) {
        return -1;  /* HMAC verification failed */
    }
    
    return 0;
}

/* =====================================================
   REPLAY PROTECTION
   ===================================================== */

/**
 * Check if sequence number has been seen before (replay detection)
 * Returns: 0 if valid (new), -1 if replay detected
 */
int check_sequence_counter(uint32_t seq) {
    /* Check if sequence number already processed */
    for(int i = 0; i < sequence_index; i++) {
        if(sequence_window[i] == seq) {
            fprintf(stderr, "[-] REPLAY ATTACK DETECTED! Sequence %u already seen\n", seq);
            stats.replay_detections++;
            return -1;  /* Replay detected */
        }
    }
    
    /* Add to sequence window */
    if(sequence_index < MAX_SEQUENCE_WINDOW) {
        sequence_window[sequence_index] = seq;
        sequence_index++;
    } else {
        /* Shift window: remove oldest, add new */
        memmove(sequence_window, sequence_window + 1, 
                (MAX_SEQUENCE_WINDOW - 1) * sizeof(uint32_t));
        sequence_window[MAX_SEQUENCE_WINDOW - 1] = seq;
    }
    
    last_seq = seq;
    return 0;  /* New sequence number, valid */
}

/* =====================================================
   PACKET VALIDATION
   ===================================================== */

/**
 * Validate packet structure and headers
 */
int validate_packet_header(Packet *pkt) {
    /* Check magic header */
    if(pkt->header != MAGIC_HEADER) {
        fprintf(stderr, "[-] Invalid magic header: 0x%08x\n", pkt->header);
        stats.malformed_packets++;
        return -1;
    }
    
    /* Check packet type */
    if(pkt->type != 1) {
        fprintf(stderr, "[-] Unknown packet type: %d\n", pkt->type);
        stats.malformed_packets++;
        return -1;
    }
    
    /* Check payload length */
    if(pkt->length > MAX_PAYLOAD) {
        fprintf(stderr, "[-] Payload length exceeds maximum: %d > %d\n", pkt->length, MAX_PAYLOAD);
        stats.malformed_packets++;
        return -1;
    }
    
    /* Check source and destination */
    if(pkt->src_id == 0 || pkt->dest_id == 0) {
        fprintf(stderr, "[-] Invalid node IDs\n");
        stats.malformed_packets++;
        return -1;
    }
    
    return 0;
}

/**
 * Process received encrypted packet
 * Performs all security validations and decryption
 */
int process_secure_packet(Packet *pkt, char *plaintext_out) {
    printf("\n");
    printf("========== PACKET RECEIVED ==========\n");
    printf("Header       : 0x%08x\n", pkt->header);
    printf("Type         : %d\n", pkt->type);
    printf("Source       : Node %d\n", pkt->src_id);
    printf("Destination  : Node %d\n", pkt->dest_id);
    printf("Length       : %d bytes\n", pkt->length);
    printf("Timestamp    : %s\n", format_time(pkt->timestamp));
    printf("Sequence No. : %u\n", pkt->seq);
    
    printf("\n[STAGE 1] Header Validation\n");
    printf("          -----------\n");
    
    /* Validate packet header */
    if(validate_packet_header(pkt) != 0) {
        fprintf(stderr, "[-] Header validation FAILED\n");
        return -1;
    }
    printf("[✓] Magic header valid\n");
    printf("[✓] Packet structure valid\n");
    printf("[✓] Payload length valid\n");
    
    /* Check timestamp (optional: reject too old packets) */
    uint32_t current_time = get_timestamp();
    if(current_time - pkt->timestamp > 3600) {  /* 1 hour */
        printf("[!] Warning: Packet is quite old (age: %u seconds)\n", 
               current_time - pkt->timestamp);
    }
    
    printf("\n[STAGE 2] Replay Protection Validation\n");
    printf("          --------------------------------\n");
    
    /* Check for replay attacks */
    if(check_sequence_counter(pkt->seq) != 0) {
        fprintf(stderr, "[-] Replay protection check FAILED\n");
        return -1;
    }
    printf("[✓] Sequence counter is NEW (not replayed)\n");
    printf("[✓] Last accepted sequence: %u\n", last_seq);
    
    printf("\n[STAGE 3a] HMAC-SHA256 Verification\n");
    printf("          ----------------------------\n");
    
    /* Build AAD (same as sender) */
    uint8_t aad_buffer[32];
    int aad_pos = 0;
    
    memcpy(aad_buffer + aad_pos, &pkt->header, 4);
    aad_pos += 4;
    memcpy(aad_buffer + aad_pos, &pkt->type, 1);
    aad_pos += 1;
    memcpy(aad_buffer + aad_pos, &pkt->src_id, 1);
    aad_pos += 1;
    memcpy(aad_buffer + aad_pos, &pkt->dest_id, 1);
    aad_pos += 1;
    memcpy(aad_buffer + aad_pos, &pkt->length, 2);
    aad_pos += 2;
    memcpy(aad_buffer + aad_pos, &pkt->seq, 4);
    aad_pos += 4;
    memcpy(aad_buffer + aad_pos, &pkt->timestamp, 4);
    aad_pos += 4;
    
    printf("[*] Nonce  : ");
    print_hex("", pkt->nonce, NONCE_SIZE);
    printf("[*] Auth Tag: ");
    print_hex("", pkt->tag, 8);

    /* === LAYER 1 OF 2: Verify HMAC-SHA256 (independent of GCM tag) === */
    {
        uint8_t hmac_input[16 + TAG_SIZE + MAX_PAYLOAD];
        int pos = 0;
        memcpy(hmac_input + pos, aad_buffer, aad_pos); pos += aad_pos;
        memcpy(hmac_input + pos, pkt->tag, TAG_SIZE); pos += TAG_SIZE;
        memcpy(hmac_input + pos, pkt->payload, pkt->length); pos += pkt->length;

        if (verify_hmac_sha256(hmac_input, pos, pkt->salt) != 0) {
            fprintf(stderr, "[-] HMAC-SHA256 verification FAILED (independent of GCM tag)\n");
            stats.auth_failures++;
            return -1;
        }
        printf("[✓] HMAC-SHA256 Verified (second, independent auth layer)\n");
    }

    printf("\n[STAGE 3b] AES-256-GCM Decryption & Tag Verification\n");
    printf("          -------------------------------------------\n");

    /* Decrypt with AES-256-GCM (includes tag verification) */
    uint8_t decrypted[MAX_PAYLOAD];
    int plaintext_len = aes_gcm_decrypt(
        pkt->payload,
        pkt->length,
        aad_buffer,
        aad_pos,
        pkt->nonce,
        pkt->tag,
        decrypted
    );
    
    if(plaintext_len < 0) {
        fprintf(stderr, "[-] Decryption/Authentication FAILED\n");
        stats.decryption_errors++;
        return -1;
    }
    
    printf("[✓] AES-256-GCM Decryption SUCCESS\n");
    printf("[✓] Authentication Tag Verified\n");
    printf("[✓] Decrypted %d bytes\n", plaintext_len);
    
    /* Copy plaintext to output */
    memcpy(plaintext_out, decrypted, plaintext_len);
    plaintext_out[plaintext_len] = '\0';
    
    stats.total_bytes_decrypted += plaintext_len;
    
    printf("\n[RESULT] SECURE MESSAGE\n");
    printf("          ---------------\n");
    printf("Decrypted Payload: \"%s\"\n", plaintext_out);
    
    printf("\n=====================================\n");
    printf("[✓] PACKET VALID AND AUTHENTICATED\n");
    printf("=====================================\n");
    
    return plaintext_len;
}

/* =====================================================
   MAIN RECEIVER LOOP
   ===================================================== */

int main(int argc, char *argv[]) {
    printf("\n");
    printf("========================================================\n");
    printf("  SECURE EMBEDDED COMMUNICATION FRAMEWORK - HARDENED RECEIVER\n");
    printf("  IITI SOC 2026 - Problem Statement 8\n");
    printf("  Member 4: Protocol Hardening & Performance Engineering\n");
    printf("========================================================\n\n");
    
    printf("[*] Initializing cryptographic engine...\n");
    printf("    Algorithm: AES-256-GCM\n");
    printf("    Authentication: HMAC-SHA256\n");
    printf("    Replay Protection: 32-bit Sequence Counter\n");
    printf("    Max Sequence Window: %d packets\n\n", MAX_SEQUENCE_WINDOW);
    
    const char *pipe_from_attacker = "/tmp/secure_nodeA_to_attacker";
    mkfifo(pipe_from_attacker, 0666);
    
    printf("[*] Server active on secure channel: %s\n", pipe_from_attacker);
    printf("[*] Listening continuously for incoming encrypted packets...\n");
    printf("    (Press Ctrl+C to stop listening)\n\n");
    
    Packet pkt;
    char plaintext_buffer[MAX_PAYLOAD + 1];
    int packet_count = 0;
    
    /* Infinite listener loop: keeps the terminal running indefinitely */
    while(1) {
        /* open() will block until a sender/writer connects to the FIFO */
        int fd = open(pipe_from_attacker, O_RDONLY);
        if(fd < 0) {
            perror("[-] Failed to open pipe");
            sleep(1);
            continue;
        }
        
        /* Receive and process packets from the connected sender */
        while(1) {
            ssize_t bytes_read = read(fd, &pkt, sizeof(Packet));
            
            if(bytes_read == 0) {
                /* Sender disconnected/closed pipe */
                printf("\n[*] Sender disconnected. Waiting for next batch...\n");
                break;
            }
            
            if(bytes_read < 0) {
                perror("[-] Read error");
                break;
            }
            
            if(bytes_read != sizeof(Packet)) {
                fprintf(stderr, "[-] Incomplete packet: %ld / %zu bytes\n", bytes_read, sizeof(Packet));
                stats.malformed_packets++;
                continue;
            }
            
            packet_count++;
            stats.total_received++;
            
            printf("\n\n");
            printf("****** PACKET %d ******\n", packet_count);
            
            /* Process security validations */
            int result = process_secure_packet(&pkt, plaintext_buffer);
            
            if(result >= 0) {
                stats.total_valid++;
            }
        }
        
        close(fd);
        
        /* Display continuous running stats summary on sender disconnect */
        printf("\n========================================================\n");
        printf("RUNNING STATS SUMMARY\n");
        printf("========================================================\n");
        printf("Total Packets Received         : %d\n", stats.total_received);
        printf("Valid/Decrypted Packets       : %d\n", stats.total_valid);
        printf("Failed Packets                : %d\n", stats.total_received - stats.total_valid);
        printf("Authentication Failures       : %d\n", stats.auth_failures);
        printf("Replay Attacks Detected       : %d\n", stats.replay_detections);
        printf("Malformed Packets             : %d\n", stats.malformed_packets);
        printf("Decryption Errors             : %d\n", stats.decryption_errors);
        printf("Total Bytes Decrypted         : %lu bytes\n", stats.total_bytes_decrypted);
        printf("========================================================\n");
        printf("[*] Listening for next sender connection...\n\n");
    }
    
    return 0;
}
