#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include "packet.h"

int main() {

    Packet pkt;

    pkt.header = MAGIC_HEADER;
    pkt.srcID = 1;
    pkt.destID = 2;
    pkt.type = 1;
    pkt.seq = 1;
    strcpy((char*)pkt.payload, "HELLO FROM NODE A");
    pkt.length = strlen((char*)pkt.payload);

    int fd = open("/tmp/nodeA_to_attacker", O_WRONLY);
    pkt.checksum = 0;

    for(int i = 0; i < pkt.length; i++)
    {
        pkt.checksum += pkt.payload[i];
    }
    write(fd, &pkt, sizeof(Packet));

    close(fd);

    printf("Packet Sent\n");

    return 0;
}
