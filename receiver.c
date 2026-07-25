#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>

#include "packet.h"

int main() {
    Packet pkt;

    printf("[*] Receiver Node Online. Listening continuously on /tmp/attacker_to_nodeB...\n");

    while (1) {
        int fd = open("/tmp/attacker_to_nodeB", O_RDONLY);
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
                continue; // Use 'continue' instead of 'return 0' so receiver stays open
            }

            if (checksum != pkt.checksum) {
                printf("\n[X] Checksum Error! Calculated: %u, Received: %u - Skipping...\n", checksum, pkt.checksum);
                continue; // Stay alive even on malformed frames
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
            fflush(stdout); // Flush buffer immediately to show log on screen
        }

        close(fd);
    }

    return 0;
}
