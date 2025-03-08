#pragma once

#include <stdint.h>

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
    char* qname;
    uint16_t qtype;
    uint16_t qclass;
};

struct dns_record
{
    char* name;
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
