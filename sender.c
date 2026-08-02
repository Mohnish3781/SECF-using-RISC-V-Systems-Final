#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#include "packet.h"

int main() {
    Packet pkt;
    const char *pipe_path = "/tmp/nodeA_to_attacker";

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

    // Initialize pipeline if it doesn't exist
    if (mkfifo(pipe_path, 0666) == -1 && errno != EEXIST) {
        perror("[-] Pipe Creation Error");
        return 1;
    }

    int fd = open(pipe_path, O_WRONLY);
    if (fd < 0) {
        perror("[-] Pipe Open Error");
        return 1;
    }

    write(fd, &pkt, sizeof(Packet));
    close(fd);

    printf("Packet Sent\n");

    return 0;
}
