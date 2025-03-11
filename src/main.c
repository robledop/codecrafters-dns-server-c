#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include "dns.h"

int main(const int argc, char* argv[])
{
    static_assert(sizeof(struct dns_header) == 12, "Incorrect DNS header size");
    struct sockaddr_in resolver_addr = {};

    if (argc == 3 && strcmp(argv[1], "--resolver") == 0)
    {
        char* resolver = argv[2];

        const char* ip_address_str = strtok(resolver, ":");
        const char* port_str = strtok(nullptr, ":");
        if (ip_address_str == nullptr || port_str == nullptr)
        {
            fprintf(stderr, "Invalid resolver address\n");
            return 1;
        }

        uint32_t ip_address = 0;
        if (inet_pton(AF_INET, ip_address_str, &ip_address) != 1)
        {
            fprintf(stderr, "Invalid IP address\n");
            return 1;
        }

        const uint16_t resolver_port = strtol(port_str, nullptr, 10);

        resolver_addr = (struct sockaddr_in){
            .sin_family = AF_INET,
            .sin_port = htons(resolver_port),
            .sin_addr = {ip_address},
        };
    }

    printf("\033[0;31m" "Forwarding requests to %s:%d" "\033[0m"
           "\n", inet_ntoa(resolver_addr.sin_addr), ntohs(resolver_addr.sin_port));

    struct dns_pool_item* request_pool = nullptr;
    struct dns_pool_item* response_pool = nullptr;

    // Disable output buffering
    setbuf(stdout, nullptr);
    setbuf(stderr, nullptr);

    struct sockaddr_in* client_address = malloc(sizeof(struct sockaddr_in));

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
    socklen_t client_addr_len = sizeof(struct sockaddr_in);

    while (true)
    {
        // Receive data
        const ssize_t bytes_read = recvfrom(udp_socket, buffer, sizeof(buffer), 0, (struct sockaddr*)client_address,
                                            &client_addr_len);
        if (bytes_read == -1)
        {
            perror("Error receiving data");
            break;
        }

        buffer[bytes_read] = '\0';

        printf(TERM_FORE_RED "Received message from %s:%d" TERM_RESET "\n",
               inet_ntoa(client_address->sin_addr),
               ntohs(client_address->sin_port));

        printf("Parsing message...\n");
        struct dns_message* message = malloc(sizeof(struct dns_message));
        parse_message(buffer, message);

        if (message->header.qr == DNS_QR_RESPONSE)
        {
            printf("Received response from %s:%d\n",
                   inet_ntoa(client_address->sin_addr),
                   ntohs(client_address->sin_port));

            struct dns_pool_item* original_request = dns_pool_find(request_pool, message->header.id);

            assert(original_request != nullptr);

            printf("Original request ID: %d, Address: %s:%d found\n", htons(original_request->message->header.id),
                   inet_ntoa(original_request->address->sin_addr),
                   ntohs(original_request->address->sin_port));
            printf("Request pool:\n");
            dns_pool_print(request_pool);

            // The request has more than one question. We need to break it into
            // multiple queries and then combine the responses from the forwarder
            // into a single response back to the client
            if (ntohs(original_request->message->header.qdcount) > 1)
            {
                struct dns_pool_item* existing_response = dns_pool_find(response_pool, message->header.id);

                if (existing_response)
                {
                    printf("Enqueued response Id: %d, found\n", ntohs(existing_response->message->header.id));


                    existing_response->message->questions = realloc(
                        existing_response->message->questions,
                        sizeof(struct dns_question) * ntohs(existing_response->message->header.qdcount)
                    );

                    printf("message->header.qdcount: %d\n", ntohs(message->header.qdcount));
                    memcpy(
                        existing_response->message->questions + (sizeof(struct dns_question) * ntohs(
                            message->header.qdcount)),
                        message->questions + ntohs(message->header.qdcount) - 1,
                        sizeof(struct dns_question) * ntohs(message->header.qdcount));

                    memcpy(existing_response->message->answers + (sizeof(struct dns_question) * ntohs(
                               existing_response->message->header.ancount)),
                           message->answers,
                           sizeof(struct dns_record) * ntohs(message->header.ancount));

                    existing_response->message->header.ancount = htons(
                        ntohs(existing_response->message->header.ancount) + 1);

                    if (existing_response->message->header.ancount == original_request->message->header.qdcount)
                    {
                        printf(TERM_FORE_RED "Sending COMBINED response to %s:%d" TERM_RESET "\n",
                               inet_ntoa(existing_response->address->sin_addr),
                               ntohs(existing_response->address->sin_port));

                        char response[512];
                        const int response_size = pack_message(existing_response->message, &response);

                        // Just for debugging //////////////////
                        struct dns_message reply_message = {0};
                        parse_message(response, &reply_message);
                        ////////////////////////////////////////

                        // Send response
                        if (sendto(udp_socket, response, response_size, 0,
                                   (struct sockaddr*)existing_response->address,
                                   sizeof(struct sockaddr_in)) == -1)
                        {
                            perror("Failed to send response");
                        }

                        dns_pool_remove(&response_pool, existing_response->message->header.id);
                        dns_pool_remove(&request_pool, original_request->message->header.id);
                    }
                }
                else
                {
                    struct dns_pool_item* current_response = malloc(sizeof(struct dns_pool_item));

                    memcpy(current_response, original_request, sizeof(struct dns_pool_item));
                    current_response->message->header.qr = 1;
                    current_response->message->header.ancount = htons(1);
                    current_response->next = nullptr;

                    current_response->message->answers = malloc(
                        sizeof(struct dns_record) * ntohs(original_request->message->header.ancount));

                    memcpy(current_response->message->answers, message->answers,
                           sizeof(struct dns_record) * ntohs(message->header.ancount));


                    printf("Adding %s:%d to response pool\n",
                           inet_ntoa(current_response->address->sin_addr),
                           ntohs(current_response->address->sin_port));

                    dns_pool_add(&response_pool, current_response);
                }
            }
            else
            {
                char response[512];
                const int response_size = pack_message(message, &response);

                printf("Parsing response...\n");
                struct dns_message reply_message = {0};
                parse_message(response, &reply_message);

                printf(TERM_FORE_RED "Response received. Sending it to %s:%d" TERM_RESET "\n",
                       inet_ntoa(original_request->address->sin_addr),
                       ntohs(original_request->address->sin_port));

                // Send response
                if (sendto(udp_socket, response, response_size, 0, (struct sockaddr*)original_request->address,
                           sizeof(struct sockaddr_in)) == -1)
                {
                    perror("Failed to send response");
                }

                dns_pool_remove(&response_pool, original_request->message->header.id);
                dns_pool_remove(&request_pool, original_request->message->header.id);
            }
        }


        if (message->header.qr == DNS_QR_QUERY)
        {
            printf(TERM_FORE_RED "Query received. Forwarding it to %s:%d" TERM_RESET"\n",
                   inet_ntoa(resolver_addr.sin_addr),
                   ntohs(resolver_addr.sin_port));

            struct dns_pool_item* current_request = malloc(sizeof(struct dns_pool_item));
            memset(current_request, 0, sizeof(struct dns_pool_item));
            current_request->address = malloc(sizeof(struct sockaddr_in));
            memcpy(current_request->address, client_address, sizeof(struct sockaddr_in));
            current_request->message = malloc(sizeof(struct dns_message));
            memcpy(current_request->message, message, sizeof(struct dns_message));

            dns_pool_add(&request_pool, current_request);

            if (ntohs(message->header.qdcount) > 1)
            {
                printf(TERM_FORE_YELLOW "Splitting request into multiple queries\n" TERM_RESET);
                for (int i = 0; i < ntohs(message->header.qdcount); i++)
                {
                    struct dns_message* split_message = malloc(sizeof(struct dns_message));
                    memset(split_message, 0, sizeof(struct dns_message));

                    memcpy(&split_message->header, &message->header, sizeof(struct dns_header));
                    split_message->header.qdcount = htons(1);
                    split_message->questions = malloc(sizeof(struct dns_question));
                    memcpy(split_message->questions, &message->questions[i], sizeof(struct dns_question));

                    char forwarded_query[512];
                    const int forwarded_query_size = pack_message(split_message, &forwarded_query);

                    printf("Parsing forwarded query...\n");
                    struct dns_message reply_message = {0};
                    parse_message(forwarded_query, &reply_message);

                    if (sendto(udp_socket, forwarded_query, forwarded_query_size, 0, (struct sockaddr*)&resolver_addr,
                               sizeof(resolver_addr)) == -1)
                    {
                        perror("Failed to forward request");
                    }
                }
            }
            else
            {
                char forwarded_query[512];
                const int forwarded_query_size = pack_message(message, &forwarded_query);

                printf("Parsing forwarded query...\n");
                struct dns_message reply_message = {0};
                parse_message(forwarded_query, &reply_message);

                if (sendto(udp_socket, forwarded_query, forwarded_query_size, 0, (struct sockaddr*)&resolver_addr,
                           sizeof(resolver_addr)) == -1)
                {
                    perror("Failed to forward request");
                }
            }
        }


        // if (message->questions != NULL)
        // {
        //     free(message->questions);
        // }
        //
        // if (message->answers != NULL)
        // {
        //     free(message->answers);
        // }
    }

    close(udp_socket);

    return 0;
}


void dns_pool_add(struct dns_pool_item** pool, struct dns_pool_item* item)
{
    if (*pool == nullptr)
    {
        *pool = item;
        return;
    }


    struct dns_pool_item* current = *pool;
    while (current->next != nullptr)
    {
        current = current->next;
    }

    current->next = item;
}

struct dns_pool_item* dns_pool_find(struct dns_pool_item* pool, uint16_t id)
{
    struct dns_pool_item* current = pool;
    while (current != nullptr)
    {
        if (current->message->header.id == id)
        {
            return current;
        }

        current = current->next;
    }

    return nullptr;
}

void dns_pool_remove(struct dns_pool_item** pool, uint16_t id)
{
    if (*pool == nullptr)
    {
        return;
    }

    if ((*pool)->message->header.id == id)
    {
        struct dns_pool_item* next = (*pool)->next;
        free(*pool);
        *pool = next;
        return;
    }

    struct dns_pool_item* current = *pool;
    while (current->next != nullptr)
    {
        if (current->next->message->header.id == id)
        {
            struct dns_pool_item* next = current->next->next;
            free(current->next);
            current->next = next;
            return;
        }

        current = current->next;
    }
}

void dns_pool_print(struct dns_pool_item* pool)
{
    struct dns_pool_item* current = pool;
    while (current != nullptr)
    {
        printf("ID: %d, ", htons(current->message->header.id));
        printf("Port: %d\n", ntohs(current->address->sin_port));
        current = current->next;
    }
}
