#include "dns.h"

struct dns_question* parse_questions(char* buffer, int qdcount, int* questions_length)
{
    struct dns_question* questions = malloc(sizeof(struct dns_question) * qdcount);
    memset(questions, 0, sizeof(struct dns_question) * qdcount);

    for (int i = 0; i < qdcount; i++)
    {
        struct q_name* q_name = decode_domain_name((char*)(buffer + HEADER_SIZE + *questions_length));
        memcpy(questions[i].qname, q_name->name, 256);

        // We have a compressed label
        if (q_name->offset > 0)
        {
            struct q_name* q_name_compressed = decode_domain_name((char*)(buffer + q_name->offset));
            memcpy(questions[i].qname + strlen(q_name->name), q_name_compressed->name, 256);
            q_name->qname_length -= 1;
            free(q_name_compressed);
        }

        questions[i].qtype = (*(uint16_t*)(buffer + HEADER_SIZE + *questions_length + q_name->qname_length));
        questions[i].qclass = (*(uint16_t*)(buffer + HEADER_SIZE + *questions_length + q_name->qname_length + 2));

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

        answers[i].ttl = *(uint32_t*)(buffer + HEADER_SIZE + questions_length + q_name->qname_length + 4);

        answers[i].rdlength = *(uint16_t*)(buffer + HEADER_SIZE + questions_length + q_name->qname_length + 8);

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
    char encoded_question[static 256]
)
{
    if (encoded_question == NULL)
    {
        return -1;
    }

    char* domain_name_copy = strdup(domain_name);

    const char* token = strtok(domain_name_copy, ".");

    int i = 0;
    while (token != nullptr)
    {
        const int len = (int)strlen(token);
        encoded_question[i] = (char)len;
        i += 1;
        strcpy(encoded_question + i, token);
        i += len;
        token = strtok(nullptr, ".");
    }

    encoded_question[i++] = '\0';

    encoded_question[i++] = (char)(qtype >> 8);
    encoded_question[i++] = (char)(qtype & 0xff);
    encoded_question[i++] = (char)(qclass >> 8);
    encoded_question[i++] = (char)(qclass & 0xff);

    free(domain_name_copy);

    return i;
}

int encode_record(
    const char* domain_name,
    const uint16_t qtype,
    const uint16_t qclass,
    const uint32_t ttl,
    const uint16_t rdlength,
    uint8_t data[static 1],
    char encoded_record[static 256]
)
{
    if (encoded_record == NULL)
    {
        return -1;
    }

    char* domain_name_copy = strdup(domain_name);

    const int size = encode_question(domain_name_copy, qtype, qclass, encoded_record);

    const uint32_t ttl_be = htonl(ttl);
    const uint16_t rdlength_be = htons(rdlength);

    // TTL 4-byte big-endian
    memcpy(encoded_record + size, &ttl_be, sizeof(ttl_be));

    // RDLength 2-byte big-endian
    memcpy(encoded_record + size + sizeof(ttl_be), &rdlength_be, sizeof(rdlength_be));

    // Data 4-byte big-endian
    memcpy(encoded_record + size + sizeof(ttl_be) + sizeof(rdlength_be), data, rdlength);

    free(domain_name_copy);

    return size + 6 + rdlength;
}

struct q_name* decode_domain_name(const char* buffer)
{
    struct q_name* q_name = malloc(sizeof(struct q_name));
    memset(q_name, 0, sizeof(struct q_name));
    memset(q_name->name, 0, 256);

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

            memcpy(q_name->name + q_name->qname_length, buffer + i, len);

            q_name->qname_length += len;

            i += len;
        }

        if (buffer[i] != 0)
        {
            strcat(q_name->name, ".");
            q_name->qname_length += 1;
        }
    }

    q_name->qname_length = i + 1;

    return q_name;
}

int pack_message(struct dns_message* message, char (*output)[512])
{
    memset(output, 0, 512);
    memcpy(*output, &(message->header), sizeof(struct dns_header));

    int questions_length = 0;
    int answers_length = 0;

    // Copy questions
    if (message->questions != NULL)
    {
        for (int i = 0; i < ntohs(message->header.qdcount); i++)
        {
            char* encoded_domain_name = malloc(256);
            memset(encoded_domain_name, 0, 256);

            const int size = encode_question(
                message->questions[i].qname,
                htons(message->questions[i].qtype),
                htons(message->questions[i].qclass),
                encoded_domain_name);

            memcpy(
                &(*output)[HEADER_SIZE + questions_length],
                encoded_domain_name,
                size
            );

            free(encoded_domain_name);

            questions_length += size;
        }
    }

    // Add answers
    for (int i = 0; i < ntohs(message->header.ancount); i++)
    {
        char* encoded_record = malloc(256);
        memset(encoded_record, 0, 256);

        const int record_size = encode_record(
            message->answers[i].name,
            htons(message->answers[i].type),
            htons(message->answers[i].class),
            htonl(message->answers[i].ttl),
            sizeof(message->answers[i].rdata),
            message->answers[i].rdata,
            encoded_record
        );

        memcpy(
            &(*output)[HEADER_SIZE + questions_length + answers_length],
            encoded_record,
            record_size
        );

        free(encoded_record);

        answers_length += record_size;
    }

    return HEADER_SIZE + questions_length + answers_length;
}

int parse_message(char* buffer, struct dns_message* message_out)
{
    struct dns_header header = {0};
    memcpy(&header, buffer, sizeof(struct dns_header));

    message_out->header = header;
    int reply_questions_length = 0;
    message_out->questions = parse_questions(buffer, htons(message_out->header.qdcount),
                                             &reply_questions_length);

    int reply_answers_length = 0;
    message_out->answers = parse_answers(buffer, reply_questions_length, ntohs(message_out->header.ancount),
                                         &reply_answers_length);

    printf("ID: %d, ", htons(message_out->header.id));

    printf("QR: %d, ", message_out->header.qr);
    printf("Opcode: %d, ", message_out->header.opcode);
    printf("AA: %d, ", message_out->header.aa);
    printf("TC: %d, ", message_out->header.tc);
    printf("RD: %d, ", message_out->header.rd);
    printf("RA: %d, ", message_out->header.ra);
    printf("Z: %d, ", message_out->header.z);
    printf("RCODE: %d, ", message_out->header.rcode);

    printf("QDCount: %d, ", ntohs(message_out->header.qdcount));
    printf("ANCount: %d\n", ntohs(message_out->header.ancount));

    for (int i = 0; i < ntohs(message_out->header.qdcount); i++)
    {
        printf("Question %d: ", i);
        printf("QName: %s, ", message_out->questions[i].qname);
        printf("QType: %d, ", ntohs(message_out->questions[i].qtype));
        printf("QClass: %d\n", ntohs(message_out->questions[i].qclass));
    }

    for (int i = 0; i < ntohs(header.ancount); i++)
    {
        printf("Answer %d: ", i);
        printf("Name: %s, ", message_out->answers[i].name);
        printf("Type: %d, ", ntohs(message_out->answers[i].type));
        printf("Class: %d ", ntohs(message_out->answers[i].class));
        printf("TTL: %d, ", ntohl(message_out->answers[i].ttl));
        printf("RDLength: %d, ", ntohs(message_out->answers[i].rdlength));
        printf("RData: %d.%d.%d.%d\n",
               message_out->answers[i].rdata[0],
               message_out->answers[i].rdata[1],
               message_out->answers[i].rdata[2],
               message_out->answers[i].rdata[3]);
    }

    return HEADER_SIZE + reply_questions_length + reply_answers_length;
}
