/**
 * Contains constants, structs, enums and function definitions.
 * Packet formats are as specified in RFC6887 - PCP.
 * http://tools.ietf.org/html/rfc6887
 */

#ifndef PACKETS_PCP_H
#define PACKETS_PCP_H

#define MAX_STRING_LEN 256
#define MAX_PAYLOAD_LEN 1100
#define MIN_MAP_PKT_LEN 60
#define MIN_PEER_PKT_LEN 80
#define MIN_ANNOUNCE_PKT_LEN 24
#define PACKED  __attribute__((packed))

#define PCP_VERSION 2
#define RESPONSE_RESERVED_SIZE 3
#define MAPPING_NONCE_SIZE 3
#define MAP_OPCODE 1
#define PEER_OPCODE 2
#define ANNOUNCE_OPCODE 3
#define PCP_SERVER_LISTENING_PORT 5351

/* Macros for assigning R value of r_opcode in headers
 * Example usage: "header.r_opcode = R_REQUEST(MAP_OPCODE)" */
#define R_REQUEST(opcode) (opcode & ~(1 << 7))
#define R_RESPONSE(opcode) (opcode | (1 << 7))
/* Macro for getting R or opcode values of r_opcode in headers */
#define IS_RESPONSE(r_opcode) ((r_opcode & (1 << 7)) > 0)
#define OPCODE(r_opcode) (r_opcode & ~(1 << 7))

#include <stdint.h>
#include <arpa/inet.h>

/*
 * Variables used locally for distinguishing between packet types
 */
typedef enum
{
    MAP_REQUEST,        // 0
    MAP_RESPONSE,       // 1
    PEER_REQUEST,       // 2
    PEER_RESPONSE,      // 3
    ANNOUNCE_REQUEST,   // 4
    ANNOUNCE_RESPONSE,  // 5
    PACKET_TYPE_MAX     // 6 - Error case
} packet_type;

/*
 * Result codes of PCP response messages
 */
typedef enum
{
    SUCCESS,
    UNSUPP_VERSION,
    NOT_AUTHORIZED,
    MALFORMED_REQUEST,
    UNSUPP_OPCODE,
    UNSUPP_OPTION,
    MALFORMED_OPTION,
    NETWORK_FAILURE,
    NO_RESOURCES,
    UNSUPP_PROTOCOL,
    USER_EX_QUOTA,
    CANNOT_PROVIDE_EXTERNAL,
    ADDRESS_MISMATCH,
    EXCESSIVE_REMOTE_PEERS,
    RESULT_CODE_MAX,        // Used for error checking only. Do not use in responses.
} result_code;

/* Define a PCP request packet header
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |  Version = 2  |R|   Opcode    |         Reserved              |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                 Requested Lifetime (32 bits)                  |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                                                               |
     |            PCP Client's IP Address (128 bits)                 |
     |                                                               |
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     :                                                               :
     :             (optional) Opcode-specific information            :
     :                                                               :
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     :                                                               :
     :             (optional) PCP Options                            :
     :                                                               :
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
* R indicates request (0) or response (1)
*/
typedef struct _pcp_request_header
{
    u_int8_t version;
    u_int8_t r_opcode;
    u_int16_t reserved;
    u_int32_t requested_lifetime;
    struct in6_addr client_ip;
} PACKED pcp_request_header;


/* Define a PCP response packet header
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |  Version = 2  |R|   Opcode    |   Reserved    |  Result Code  |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                      Lifetime (32 bits)                       |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                     Epoch Time (32 bits)                      |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                                                               |
     |                      Reserved (96 bits)                       |
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     :                                                               :
     :             (optional) Opcode-specific response data          :
     :                                                               :
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     :             (optional) Options                                :
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
* R indicates request (0) or response (1)
*/
typedef struct _pcp_response_header
{
    u_int8_t version;
    u_int8_t r_opcode;
    u_int8_t reserved;
    u_int8_t result_code;
    u_int32_t lifetime;
    u_int32_t epoch_time;
    u_int32_t reserved_array[RESPONSE_RESERVED_SIZE];
} PACKED pcp_response_header;


/* Define a MAP request packet
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                                                               |
     |                 Mapping Nonce (96 bits)                       |
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |   Protocol    |          Reserved (24 bits)                   |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |        Internal Port          |    Suggested External Port    |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                                                               |
     |           Suggested External IP Address (128 bits)            |
     |                                                               |
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
typedef struct _map_request
{
    pcp_request_header header;
    u_int32_t mapping_nonce[MAPPING_NONCE_SIZE];
    u_int8_t protocol;
    u_int8_t reserved_1;
    u_int16_t reserved_2;
    u_int16_t internal_port;
    u_int16_t suggested_external_port;
    struct in6_addr suggested_external_ip;
} PACKED map_request;


/* Define a MAP response packet
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                                                               |
     |                 Mapping Nonce (96 bits)                       |
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |   Protocol    |          Reserved (24 bits)                   |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |        Internal Port          |    Assigned External Port     |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                                                               |
     |            Assigned External IP Address (128 bits)            |
     |                                                               |
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
typedef struct _map_response
{
    pcp_response_header header;
    u_int32_t mapping_nonce[MAPPING_NONCE_SIZE];
    u_int8_t protocol;
    u_int8_t reserved_1;
    u_int16_t reserved_2;
    u_int16_t internal_port;
    u_int16_t assigned_external_port;
    struct in6_addr assigned_external_ip;
} PACKED map_response;


/* Define a PEER request packet
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                                                               |
     |                 Mapping Nonce (96 bits)                       |
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |   Protocol    |          Reserved (24 bits)                   |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |        Internal Port          |    Suggested External Port    |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                                                               |
     |           Suggested External IP Address (128 bits)            |
     |                                                               |
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |       Remote Peer Port        |     Reserved (16 bits)        |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                                                               |
     |               Remote Peer IP Address (128 bits)               |
     |                                                               |
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
typedef struct _peer_request
{
    pcp_request_header header;
    u_int32_t mapping_nonce[MAPPING_NONCE_SIZE];
    u_int8_t protocol;
    u_int8_t reserved_1;
    u_int16_t reserved_2;
    u_int16_t internal_port;
    u_int16_t suggested_external_port;
    struct in6_addr suggested_external_ip;
    u_int16_t remote_peer_port;
    u_int16_t reserved_3;
    struct in6_addr remote_peer_ip;
} PACKED peer_request;


// Create a new PCP headers
bool new_pcp_request_header (pcp_request_header *hdr,
                             u_int8_t opcode, u_int32_t requested_lifetime,
                             const char *ip6str);

void new_pcp_response_header (pcp_response_header *resp_hdr, pcp_request_header *req_hdr);

// Create new PCP MAP packets
map_request *new_pcp_map_request (u_int32_t requested_lifetime, const char *ip6str);

map_response *new_pcp_map_response (map_request *map_req);

// Create new PCP PEER packets
peer_request *new_pcp_peer_request (u_int32_t requested_lifetime, const char *ip6str);

// Create a new PCP error response
pcp_response_header *new_pcp_error_response (u_int8_t r_opcode, result_code result, u_int32_t lifetime);

// Validate a PCP packet buffer
result_code validate_packet_buffer (unsigned char *pkt_buf, int n);

// Getting PCP variables by parsing a byte array.
u_int8_t get_version (unsigned char *pkt_buf);

u_int8_t get_r_opcode (unsigned char *pkt_buf);

bool r_bit_is_set (unsigned char *pkt_buf);

packet_type get_packet_type (unsigned char *pkt_buf);

unsigned char *add_zero_padding (unsigned char *pkt_buf, unsigned char *ptr);

#endif /* PACKETS_PCP_H */
