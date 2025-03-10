#pragma once

#include <stdint.h>

#define HEADER_SIZE 12

// ###############################################
// # QR | OPCODE | AA | TC | RD | RA | Z | RCODE |
// # 1  | 4      | 1  | 1  | 1  | 1  | 3 | 4     | 
// ###############################################

#define DNS_FLAG_QR 0x8000
#define DNS_FLAG_OPCODE 0x7800
#define DNS_FLAG_AA 0x0400
#define DNS_FLAG_TC 0x0200
#define DNS_FLAG_RD 0x0100
#define DNS_FLAG_RA 0x0080
#define DNS_FLAG_Z 0x0070
#define DNS_FLAG_RCODE 0x000f

struct dns_header
{
    uint16_t id;
    uint32_t rd : 1;
    uint32_t tc : 1;
    uint32_t aa : 1;
    uint32_t opcode : 4;
    uint32_t qr : 1;
    uint32_t rcode : 4;
    uint32_t z : 3;
    uint32_t ra : 1;
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
    uint8_t rdata[4];
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
struct dns_record* parse_answers(char* buffer, int questions_length, int ancount, int* answers_length);
struct q_name* decode_domain_name(const char* buffer);
int encode_question(const char* domain_name, uint16_t qtype, uint16_t qclass, char encoded_question[static 256]);
int encode_record(
    const char domain_name[256],
    uint16_t qtype,
    uint16_t qclass,
    uint32_t ttl,
    uint16_t rdlength,
    uint8_t data[static 1],
    char encoded_record[static 256]
);
int pack_message(struct dns_message message, char (*output)[512]);
int parse_message(char* buffer, struct dns_message* message_out);
