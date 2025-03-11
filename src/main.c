#include <assert.h>
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
        // ReSharper disable once CppPrintfExtraArg
        // ReSharper disable once CppPrintfBadFormat
        printf("Received %zu bytes: %032b\n", bytes_read, *(uint32_t*)buffer);

        printf("Parsing request...\n");
        struct dns_message message = {0};
        parse_message(buffer, &message);

        // Prepare response
        message.header.qr = DNS_QR_RESPONSE;
        message.header.ancount = message.header.qdcount;

        if (message.header.opcode == DNS_OPCODE_QUERY)
        {
            // Set RCODE to 0
            message.header.rcode = DNS_RCODE_NO_ERROR;
        }
        else
        {
            // Set RCODE to 4
            message.header.rcode = DNS_RCODE_NOT_IMPLEMENTED;
        }

        char response[512];
        const int response_size = pack_message(message, &response);

        static_assert(sizeof(struct dns_header) == 12, "Incorrect DNS header size");

        printf("Parsing response...\n");
        struct dns_message reply_message = {0};
        parse_message(response, &reply_message);

        // Send response
        if (sendto(udp_socket, response, response_size, 0, (struct sockaddr*)&client_address,
                   sizeof(client_address)) == -1)
        {
            perror("Failed to send response");
        }

        if (message.questions != NULL)
        {
            free(message.questions);
        }

        if (message.answers != NULL)
        {
            free(message.answers);
        }
    }

    close(udp_socket);

    return 0;
}

