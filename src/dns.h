#pragma once

#include <stdint.h>

#define HEADER_SIZE 12

#define DNS_FLAG_QR     (1 << 7)
#define DNS_FLAG_OPCODE (0b1111 << 11)
#define DNS_FLAG_AA     (1 << 10)
#define DNS_FLAG_TC     (1 << 9)
#define DNS_FLAG_RD     (1 << 8)
#define DNS_FLAG_RA     (1 << 7)
#define DNS_FLAG_Z      (0b111 << 4)
#define DNS_FLAG_RCODE  (0b1111)

struct dns_header
{
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} __attribute__((packed));

struct dns_question
{
    char qname[256];
    uint16_t qtype;
    uint16_t qclass;
};

struct dns_record
{
    char name[256];
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;
};

struct dns_message
{
    struct dns_header header;
    struct dns_question* questions;
    struct dns_record* answers;
    struct dns_record* authorities;
    struct dns_record* additionals;
};

struct q_name
{
    char name[256];
    int qname_length;
    int offset;
};

#define SET_QR_FLAG(header, value) header.flags = (header.flags & ~DNS_FLAG_QR) | (value << 7)


struct dns_question* parse_questions(char* buffer, int qdcount, int* questions_length);
struct q_name* decode_domain_name(const char* buffer);
int encode_domain_name(char* domain_name, ushort qtype, ushort qclass, char encoded_domain_name[static 256]);
void pack_message(struct dns_message message, char (*response)[512]);

