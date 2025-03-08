#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include "dns.h"

int main()
{
    // Disable output buffering
    setbuf(stdout, nullptr);
    setbuf(stderr, nullptr);

    struct sockaddr_in client_address;

    const int udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_socket == -1)
    {
        printf("Socket creation failed: %s...\n", strerror(errno));
        return 1;
    }

    // Since the tester restarts your program quite often, setting REUSE_PORT
    // ensures that we don't run into 'Address already in use' errors
    constexpr int reuse = 1;
    if (setsockopt(udp_socket, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0)
    {
        printf("SO_REUSEPORT failed: %s \n", strerror(errno));
        return 1;
    }

    struct sockaddr_in serv_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(2053),
        .sin_addr = {htonl(INADDR_ANY)},
    };

    if (bind(udp_socket, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) != 0)
    {
        printf("Bind failed: %s \n", strerror(errno));
        return 1;
    }

    char buffer[512];
    socklen_t client_addr_len = sizeof(client_address);

    while (true)
    {
        // Receive data
        const ssize_t bytes_read = recvfrom(udp_socket, buffer, sizeof(buffer), 0, (struct sockaddr*)&client_address,
                                            &client_addr_len);
        if (bytes_read == -1)
        {
            perror("Error receiving data");
            break;
        }

        buffer[bytes_read] = '\0';
        printf("Received %zu bytes: %s\n", bytes_read, buffer);

        struct dns_header* header = (struct dns_header*)buffer;

        printf("DNS Header:\n");
        printf("ID: %d, ", htons(header->id));
        printf("Flags: %b, ", header->flags);
        printf("QR: %d, ", (header->flags & DNS_FLAG_QR) >> 15);
        printf("Opcode: %d, ", (header->flags & DNS_FLAG_OPCODE) >> 11);
        printf("AA: %d, ", (header->flags & DNS_FLAG_AA) >> 10);
        printf("TC: %d, ", (header->flags & DNS_FLAG_TC) >> 9);
        printf("RD: %d, ", (header->flags & DNS_FLAG_RD) >> 8);
        printf("RA: %d, ", (header->flags & DNS_FLAG_RA) >> 7);
        printf("Z: %d, ", (header->flags & DNS_FLAG_Z) >> 4);
        printf("RCODE: %d, ", (header->flags & DNS_FLAG_RCODE));

        printf("QDCount: %d, ", ntohs(header->qdcount));
        printf("ANCount: %d\n", ntohs(header->ancount));

        // Set QR flag to 1
        header->flags |= DNS_FLAG_QR;

        printf("DNS Header Reply:\n");
        printf("ID: %d, ", htons(header->id));
        printf("Flags: %b, ", header->flags);
        printf("QR: %d, ", (header->flags & DNS_FLAG_QR) == DNS_FLAG_QR);
        printf("Opcode: %d, ", (header->flags & DNS_FLAG_OPCODE) >> 11);
        printf("AA: %d, ", (header->flags & DNS_FLAG_AA) == DNS_FLAG_AA);
        printf("TC: %d, ", (header->flags & DNS_FLAG_TC) == DNS_FLAG_TC);
        printf("RD: %d, ", (header->flags & DNS_FLAG_RD) == DNS_FLAG_RD);
        printf("RA: %d, ", (header->flags & DNS_FLAG_RA) == DNS_FLAG_RA);
        printf("Z: %d, ", (header->flags & DNS_FLAG_Z) >> 4);
        printf("RCODE: %d, ", (header->flags & DNS_FLAG_RCODE));

        printf("QDCount: %d, ", ntohs(header->qdcount));
        printf("ANCount: %d\n", ntohs(header->ancount));

        // Send response
        if (sendto(udp_socket, header, sizeof(struct dns_header), 0, (struct sockaddr*)&client_address,
                   sizeof(client_address)) == -1)
        {
            perror("Failed to send response");
        }
    }

    close(udp_socket);

    return 0;
}
