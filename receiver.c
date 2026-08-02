#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#include "packet.h"

int main() {
    Packet pkt;
    const char *pipe_path = "/tmp/attacker_to_nodeB";

    // Initialize pipeline if it doesn't exist
    if (mkfifo(pipe_path, 0666) == -1 && errno != EEXIST) {
        perror("[-] Pipe Creation Error");
        return 1;
    }

    printf("[*] Receiver Node Online. Listening continuously on %s...\n", pipe_path);

    while (1) {
        int fd = open(pipe_path, O_RDONLY);
        if (fd < 0) {
            perror("[-] Pipe Open Error");
            return 1;
        }

        while (1) {
            ssize_t bytes_read = read(fd, &pkt, sizeof(Packet));

            if (bytes_read == 0) {
                break; // Break inner loop to re-open pipe and wait for next transmission
            }

            if (bytes_read < (ssize_t)sizeof(Packet)) {
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

        close(fd);
    }

    return 0;
}
