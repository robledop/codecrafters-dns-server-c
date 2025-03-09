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
        printf("Received %zu bytes: %s\n", bytes_read, buffer);

        struct dns_header header = {0};
        memcpy(&header, buffer, sizeof(struct dns_header));

        printf("Parsing request...\n");
        struct dns_message message = {0};
        parse_message(buffer, &message);

        // Prepare response
        SET_QR_FLAG(message.header, 1);
        message.header.ancount = 1 << 8;

        char response[512];
        pack_message(message, &response);

        printf("Parsing response...\n");
        struct dns_message reply_message = {0};
        parse_message(response, &reply_message);

        // Send response
        if (sendto(udp_socket, response, sizeof(struct dns_message), 0, (struct sockaddr*)&client_address,
                   sizeof(client_address)) == -1)
        {
            perror("Failed to send response");
        }

        free(message.questions);
    }

    close(udp_socket);

    return 0;
}

struct dns_question* parse_questions(char* buffer, int qdcount, int* questions_length)
{
    struct dns_question* questions = malloc(sizeof(struct dns_question) * qdcount);
    memset(questions, 0, sizeof(struct dns_question) * qdcount);

    for (int i = 0; i < qdcount; i++)
    {
        struct q_name* q_name = decode_domain_name((char*)(buffer + HEADER_SIZE + *questions_length));
        memcpy(questions[i].qname, q_name->name, 256);

        questions[i].qtype = (*(uint16_t*)(buffer + HEADER_SIZE + q_name->qname_length));
        questions[i].qclass = (*(uint16_t*)(buffer + HEADER_SIZE + q_name->qname_length + 2));

        *questions_length += q_name->qname_length + 4;
        free(q_name);
    }

    return questions;
}


struct dns_record* parse_answers(char* buffer, int questions_length, int ancount, int* answers_length)
{
    struct dns_record* answers = malloc(sizeof(struct dns_record) * ancount);
    memset(answers, 0, sizeof(struct dns_record) * ancount);

    for (int i = 0; i < ancount; i++)
    {
        struct q_name* q_name = decode_domain_name((char*)(buffer + HEADER_SIZE + *answers_length));
        memcpy(answers[i].name, q_name->name, 256);

        answers[i].type = (*(uint16_t*)(buffer + HEADER_SIZE + questions_length + q_name->qname_length));
        answers[i].class = (*(uint16_t*)(buffer + HEADER_SIZE + questions_length + q_name->qname_length + 2));
        
        answers[i].ttl = (*(uint32_t*)(buffer + HEADER_SIZE + questions_length + q_name->qname_length + 4)) >> 24
            | (*(uint32_t*)(buffer + HEADER_SIZE + questions_length + q_name->qname_length + 5)) >> 16
            | (*(uint32_t*)(buffer + HEADER_SIZE + questions_length + q_name->qname_length + 6)) >> 8
            | (*(uint32_t*)(buffer + HEADER_SIZE + questions_length + q_name->qname_length + 7));

        answers[i].rdlength = (*(uint16_t*)(buffer + HEADER_SIZE + questions_length + q_name->qname_length + 8)) >> 8
            | (*(uint16_t*)(buffer + HEADER_SIZE + questions_length + q_name->qname_length + 9));

        answers[i].rdata[0] = buffer[HEADER_SIZE + questions_length + q_name->qname_length + 10];
        answers[i].rdata[1] = buffer[HEADER_SIZE + questions_length + q_name->qname_length + 11];
        answers[i].rdata[2] = buffer[HEADER_SIZE + questions_length + q_name->qname_length + 12];
        answers[i].rdata[3] = buffer[HEADER_SIZE + questions_length + q_name->qname_length + 13];

        *answers_length += q_name->qname_length + 4;
        free(q_name);
    }

    return answers;
}

int encode_question(
    const char domain_name[256],
    const uint16_t qtype,
    const uint16_t qclass,
    char encoded_domain_name[static 256]
)
{
    if (encoded_domain_name == NULL)
    {
        return -1;
    }

    char* domain_name_copy = strdup(domain_name);

    const char* token = strtok(domain_name_copy, ".");

    int i = 0;
    while (token != nullptr)
    {
        const int len = (int)strlen(token);
        encoded_domain_name[i] = (char)len;
        i += 1;
        strcpy(encoded_domain_name + i, token);
        i += len;
        token = strtok(nullptr, ".");
    }

    encoded_domain_name[i++] = '\0';

    encoded_domain_name[i++] = (char)(qtype >> 8);
    encoded_domain_name[i++] = (char)(qtype & 0xff);
    encoded_domain_name[i++] = (char)(qclass >> 8);
    encoded_domain_name[i++] = (char)(qclass & 0xff);

    free(domain_name_copy);

    return i;
}

int encode_record(
    const char* domain_name,
    const uint16_t qtype,
    const uint16_t qclass,
    uint32_t ttl,
    uint16_t rdlength,
    uint8_t data[static 1],
    char encoded_record[static 256]
)
{
    if (encoded_record == NULL)
    {
        return -1;
    }

    char* domain_name_copy = strdup(domain_name);


    int size = encode_question(domain_name_copy, qtype, qclass, encoded_record);

    uint32_t ttl_be = htonl(ttl);
    uint16_t rdlength_be = htons(rdlength);

    // TTL 4-byte big-endian
    encoded_record[size] = (char)(ttl_be >> 24);
    encoded_record[size + 1] = (char)(ttl_be >> 16);
    encoded_record[size + 2] = (char)(ttl_be >> 8);
    encoded_record[size + 3] = (char)(ttl_be & 0xff);

    // RDLength 2-byte big-endian
    encoded_record[size + 4] = (char)(rdlength_be >> 8);
    encoded_record[size + 5] = (char)(rdlength_be & 0xff);

    // Data 4-byte big-endian
    memcpy(encoded_record + size + 6, data, rdlength);

    free(domain_name_copy);

    return size + 6 + rdlength;
}

struct q_name* decode_domain_name(const char* buffer)
{
    struct q_name* q_name = malloc(sizeof(struct q_name));
    memset(q_name, 0, sizeof(struct q_name));

    int i = 0;
    while (buffer[i] != 0)
    {
        const int len = (int)buffer[i];

        const bool is_pointer = (len & 0b11000000) == 0b11000000;

        if (is_pointer)
        {
            q_name->offset = (len & 0b00111111) << 8 | buffer[i + 1];
            i += 2;
        }
        else
        {
            i += 1;
            char* part = malloc(len + 1);
            memcpy(part, buffer + i, len);

            strcat(q_name->name, part);
            free(part);

            i += len;
        }

        if (buffer[i] != 0)
        {
            strcat(q_name->name, ".");
        }
    }

    q_name->name[i - 1] = '\0';
    q_name->qname_length = i + 1;

    return q_name;
}

void pack_message(struct dns_message message, char (*response)[512])
{
    memset(response, 0, 512);
    memcpy(*response, &message.header, sizeof(struct dns_header));

    // Copy questions
    if (message.questions != NULL)
    {
        int questions_length = 0;
        for (int i = 0; i < ntohs(message.header.qdcount); i++)
        {
            char* encoded_domain_name = malloc(256);
            memset(encoded_domain_name, 0, 256);

            const int size = encode_question(
                message.questions[i].qname,
                htons(message.questions[i].qtype),
                htons(message.questions[i].qclass),
                encoded_domain_name);

            memcpy(
                &(*response)[HEADER_SIZE],
                encoded_domain_name,
                size
            );

            free(encoded_domain_name);

            questions_length += size;
        }

        // Add answers
        int answers_length = 0;
        for (int i = 0; i < ntohs(message.header.qdcount); i++)
        {
            uint8_t data[4] = {8, 8, 8, 8};

            char* encoded_record = malloc(256);
            memset(encoded_record, 0, 256);

            const int record_size = encode_record(
                message.questions[i].qname,
                htons(message.questions[i].qtype),
                htons(message.questions[i].qclass),
                60,
                sizeof(data),
                data,
                encoded_record
            );

            memcpy(&(*response)[HEADER_SIZE + questions_length + answers_length], &encoded_record,
                   record_size);

            free(encoded_record);

            answers_length += record_size;
        }
    }
}

void parse_message(char* buffer, struct dns_message* message)
{
    struct dns_header header = {0};
    memcpy(&header, buffer, sizeof(struct dns_header));

    message->header = header;
    int reply_questions_length = 0;
    message->questions = parse_questions(buffer, htons(message->header.qdcount),
                                         &reply_questions_length);
    printf("Questions length: %d\n", reply_questions_length);

    int reply_answers_length = 0;
    message->answers = parse_answers(buffer, reply_questions_length, htons(message->header.ancount),
                                     &reply_answers_length);
    printf("Answers length: %d\n", reply_answers_length);

    printf("ID: %d, ", htons(message->header.id));
    printf("Flags: %b, ", message->header.flags);
    printf("QR: %d, ", (message->header.flags & DNS_FLAG_QR) == DNS_FLAG_QR);
    printf("Opcode: %d, ", (message->header.flags & DNS_FLAG_OPCODE) >> 11);
    printf("AA: %d, ", (message->header.flags & DNS_FLAG_AA) == DNS_FLAG_AA);
    printf("TC: %d, ", (message->header.flags & DNS_FLAG_TC) == DNS_FLAG_TC);
    printf("RD: %d, ", (message->header.flags & DNS_FLAG_RD) == DNS_FLAG_RD);
    printf("RA: %d, ", (message->header.flags & DNS_FLAG_RA) == DNS_FLAG_RA);
    printf("Z: %d, ", (message->header.flags & DNS_FLAG_Z) >> 4);
    printf("RCODE: %d, ", (message->header.flags & DNS_FLAG_RCODE));

    printf("QDCount: %d, ", ntohs(message->header.qdcount));
    printf("ANCount: %d\n", ntohs(message->header.ancount));

    for (int i = 0; i < ntohs(message->header.qdcount); i++)
    {
        printf("Question %d: ", i);
        printf("QName: %s, ", message->questions[i].qname);
        printf("QType: %d, ", ntohs(message->questions[i].qtype));
        printf("QClass: %d\n", ntohs(message->questions[i].qclass));
    }

    for (int i = 0; i < ntohs(header.ancount); i++)
    {
        printf("Answer %d: ", i);
        printf("Name: %s, ", message->answers[i].name);
        printf("Type: %d, ", ntohs(message->answers[i].type));
        printf("Class: %d ", ntohs(message->answers[i].class));
        printf("TTL: %d, ", ntohl(message->answers[i].ttl));
        printf("RDLength: %d, ", ntohs(message->answers[i].rdlength));
        printf("RData: %d.%d.%d.%d\n",
               message->answers[i].rdata[3],
               message->answers[i].rdata[2],
               message->answers[i].rdata[1],
               message->answers[i].rdata[0]);
    }
}
