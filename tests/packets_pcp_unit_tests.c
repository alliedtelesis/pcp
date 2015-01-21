#include <np.h> /* NovaProva library */
#include "../pcpd/packets_pcp.h"
#include "../pcpd/packets_pcp_serialization.h"
#include "stdlib.h"
#include <stdint.h>
#include <stdio.h>

void
partial_hexdump (void *data, unsigned int len, char *buffer)
{
    char *result_ptr;
    unsigned int i;

    result_ptr = buffer;
    for (i = 0; i < len; i++)
    {
        sprintf (result_ptr, "%02X ", 0xFF & ((char *) data)[i]);
        result_ptr += 3;
    }
    if (i > 0)
        result_ptr[-1] = '\0';  // Terminate at one char before the ptr
}

void
test_serialize_u_int8_t (void)
{
    // 10101010
    u_int8_t test_value = 0xAA;
    char *answer_string = "AA";

    unsigned char buffer[MAX_STRING_LEN] = { '\0' };
    unsigned char *ptr;
    char hex_buffer[MAX_STRING_LEN];

    ptr = serialize_u_int8_t (buffer, test_value);
    partial_hexdump (buffer, ptr - buffer, hex_buffer);

    NP_ASSERT_EQUAL (ptr - buffer, sizeof (u_int8_t));
    NP_ASSERT_STR_EQUAL (hex_buffer, answer_string);
}

void
test_serialize_u_int16_t (void)
{
    // 1010101010101010
    u_int16_t test_value = 0xAAAA;
    char *answer_string = "AA AA";

    unsigned char buffer[MAX_STRING_LEN] = { '\0' };
    unsigned char *ptr;
    char hex_buffer[MAX_STRING_LEN];

    ptr = serialize_u_int16_t (buffer, test_value);
    partial_hexdump (buffer, ptr - buffer, hex_buffer);

    NP_ASSERT_EQUAL (ptr - buffer, sizeof (u_int16_t));
    NP_ASSERT_STR_EQUAL (hex_buffer, answer_string);
}

void
test_serialize_u_int32_t (void)
{
    // 10101010101010101010101010101010
    u_int32_t test_value = 0xAAAAAAAA;
    char *answer_string = "AA AA AA AA";

    unsigned char buffer[MAX_STRING_LEN] = { '\0' };
    unsigned char *ptr;
    char hex_buffer[MAX_STRING_LEN];

    ptr = serialize_u_int32_t (buffer, test_value);
    partial_hexdump (buffer, ptr - buffer, hex_buffer);

    NP_ASSERT_EQUAL (ptr - buffer, sizeof (u_int32_t));
    NP_ASSERT_STR_EQUAL (hex_buffer, answer_string);
}

void
test_serialize_ip_address (void)
{
    char *test_str = "2001:DB8:7654:3210:FEDC:BA98:7654:3210";
    char *answer_string = "20 01 0D B8 76 54 32 10 FE DC BA 98 76 54 32 10";

    struct in6_addr test_ip_address;
    inet_pton (AF_INET6, test_str, &(test_ip_address));

    unsigned char buffer[MAX_STRING_LEN] = { '\0' };
    unsigned char *ptr;
    char hex_buffer[MAX_STRING_LEN];

    ptr = serialize_ip_address (buffer, &test_ip_address);
    partial_hexdump (buffer, ptr - buffer, hex_buffer);

    NP_ASSERT_EQUAL (ptr - buffer, sizeof (struct in6_addr));
    NP_ASSERT_STR_EQUAL (hex_buffer, answer_string);
}

void
test_serialize_u_int32_t_array3 (void)
{
    // 10101010101010101010101010101010
    // 10101010101010101010101010101011
    // 10101010101010101010101010101100
    u_int32_t test_value[3] = { 0xAAAAAAAA, 0xAAAAAAAB, 0xAAAAAAAC };
    char *answer_string = "AA AA AA AA AA AA AA AB AA AA AA AC";

    unsigned char buffer[MAX_STRING_LEN] = { '\0' };
    unsigned char *ptr;
    char hex_buffer[MAX_STRING_LEN];

    ptr = serialize_u_int32_t_array3 (buffer, test_value);
    partial_hexdump (buffer, ptr - buffer, hex_buffer);

    NP_ASSERT_EQUAL (ptr - buffer, 3 * sizeof (u_int32_t));
    NP_ASSERT_STR_EQUAL (hex_buffer, answer_string);
}

void
test_deserialize_u_int8_t (void)
{
    // 10101010
    unsigned char test_value[] = { 0xAA };
    u_int8_t answer = 0xAA;

    u_int8_t result;
    unsigned char *ptr;
    ptr = deserialize_u_int8_t (&result, test_value);

    NP_ASSERT_EQUAL (ptr - test_value, sizeof (u_int8_t));
    NP_ASSERT_EQUAL (result, answer);
}

void
test_deserialize_u_int16_t (void)
{
    // 1010101010101010
    unsigned char test_value[] = { 0xAA, 0xAA };
    u_int16_t answer = 0xAAAA;

    u_int16_t result;
    unsigned char *ptr;
    ptr = deserialize_u_int16_t (&result, test_value);

    NP_ASSERT_EQUAL (ptr - test_value, sizeof (u_int16_t));
    NP_ASSERT_EQUAL (result, answer);
}

void
test_deserialize_u_int32_t (void)
{
    // 10101010101010101010101010101010
    unsigned char test_value[] = { 0xAA, 0xAA, 0xAA, 0xAA };
    u_int32_t answer = 0xAAAAAAAA;

    u_int32_t result;
    unsigned char *ptr;
    ptr = deserialize_u_int32_t (&result, test_value);

    NP_ASSERT_EQUAL (ptr - test_value, sizeof (u_int32_t));
    NP_ASSERT_EQUAL (result, answer);
}

void
test_deserialize_ip_address (void)
{
    unsigned char test_value[] = { 0x20, 0x01, 0x0D, 0xB8, 0x76, 0x54, 0x32, 0x10,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    char *answer = "2001:db8:7654:3210:fedc:ba98:7654:3210";

    char result[INET6_ADDRSTRLEN] = { '\0' };
    struct in6_addr result_struct;
    unsigned char *ptr;
    ptr = deserialize_ip_address (&result_struct, test_value);

    inet_ntop (AF_INET6, &(result_struct.s6_addr), result, INET6_ADDRSTRLEN);

    NP_ASSERT_EQUAL (ptr - test_value, sizeof (struct in6_addr));
    NP_ASSERT_STR_EQUAL (result, answer);
}

void
test_deserialize_u_int32_t_array3 (void)
{
    // 10101010101010101010101010101010
    // 10101010101010101010101010101011
    // 10101010101010101010101010101100
    unsigned char test_value[] = { 0xAA, 0xAA, 0xAA, 0xAA,
        0xAA, 0xAA, 0xAA, 0xAB,
        0xAA, 0xAA, 0xAA, 0xAC
    };
    u_int32_t answer1 = 0xAAAAAAAA;
    u_int32_t answer2 = 0xAAAAAAAB;
    u_int32_t answer3 = 0xAAAAAAAC;

    u_int32_t result[3];
    unsigned char *ptr;
    ptr = deserialize_u_int32_t_array3 (result, test_value);

    NP_ASSERT_EQUAL (ptr - test_value, 3 * sizeof (u_int32_t));
    NP_ASSERT_EQUAL (result[0], answer1);
    NP_ASSERT_EQUAL (result[1], answer2);
    NP_ASSERT_EQUAL (result[2], answer3);
}

void
test_get_packet_type_map_req (void)
{
    unsigned char test_value[24] = { '\0' };
    test_value[1] = R_REQUEST (MAP_OPCODE);
    packet_type answer = MAP_REQUEST;

    packet_type result = get_packet_type (test_value);
    NP_ASSERT_EQUAL (answer, result);
}

void
test_get_packet_type_map_resp (void)
{
    unsigned char test_value[24] = { '\0' };
    test_value[1] = R_RESPONSE (MAP_OPCODE);
    packet_type answer = MAP_RESPONSE;

    packet_type result = get_packet_type (test_value);
    NP_ASSERT_EQUAL (answer, result);
}

void
test_get_packet_type_peer_req (void)
{
    unsigned char test_value[24] = { '\0' };
    test_value[1] = R_REQUEST (PEER_OPCODE);
    packet_type answer = PEER_REQUEST;

    packet_type result = get_packet_type (test_value);
    NP_ASSERT_EQUAL (answer, result);
}

void
test_get_packet_type_peer_resp (void)
{
    unsigned char test_value[24] = { '\0' };
    test_value[1] = R_RESPONSE (PEER_OPCODE);
    packet_type answer = PEER_RESPONSE;

    packet_type result = get_packet_type (test_value);
    NP_ASSERT_EQUAL (answer, result);
}

void
test_serialize_request_header (void)
{
    pcp_request_header test_hdr;

    u_int8_t version = PCP_VERSION;
    u_int8_t r_opcode = R_REQUEST (MAP_OPCODE);
    u_int16_t reserved = 0;
    u_int32_t req_lifetime = 86400; // 24 hrs

    struct in6_addr client_ip;
    inet_pton (AF_INET6, "2001:db8:7654:3210:fedc:ba98:7654:3210", &(client_ip));

    unsigned char result[MAX_STRING_LEN];
    unsigned char *ptr;
    int i, j;

    test_hdr.version = version;                 // 1B
    test_hdr.r_opcode = r_opcode;               // 1B
    test_hdr.reserved = reserved;               // 2B
    test_hdr.requested_lifetime = req_lifetime; // 4B
    test_hdr.client_ip = client_ip;             // 16B

    ptr = serialize_request_header (result, &test_hdr);

    NP_ASSERT_EQUAL (ptr - result, sizeof (pcp_request_header));

    i = 0;
    NP_ASSERT_EQUAL (version, result[i++]);
    NP_ASSERT_EQUAL (r_opcode, result[i++]);
    NP_ASSERT_EQUAL (reserved, (result[i] << 8) + result[i + 1]);
    i += 2;
    NP_ASSERT_EQUAL (req_lifetime,
                     (result[i] << 24) + (result[i + 1] << 16) + (result[i + 2] << 8) +
                     result[i + 3]);
    i += 4;
    for (j = 0; j < sizeof (struct in6_addr); j++, i++)
    {
        NP_ASSERT_EQUAL (client_ip.s6_addr[j], result[i]);
    }
}

void
test_serialize_response_header (void)
{
    pcp_response_header test_hdr;

    u_int8_t version = PCP_VERSION;
    u_int8_t r_opcode = R_RESPONSE (PEER_OPCODE);
    u_int8_t reserved = 0;
    u_int8_t result_code = 4;
    u_int32_t lifetime = 86400; // 24 hrs
    u_int32_t epoch_time = 1419215249;
    u_int32_t reserved_array[RESPONSE_RESERVED_SIZE] = { 0, 0, 0 };

    unsigned char result[MAX_STRING_LEN];
    unsigned char *ptr;
    int i, j;

    test_hdr.version = version;                     // 1B
    test_hdr.r_opcode = r_opcode;                   // 1B
    test_hdr.reserved = reserved;                   // 1B
    test_hdr.result_code = result_code;             // 1B
    test_hdr.lifetime = lifetime;                   // 4B
    test_hdr.epoch_time = epoch_time;               // 4B
    test_hdr.reserved_array[0] = reserved_array[0]; // 12B
    test_hdr.reserved_array[1] = reserved_array[1];
    test_hdr.reserved_array[2] = reserved_array[2];

    ptr = serialize_response_header (result, &test_hdr);
    NP_ASSERT_EQUAL (ptr - result, sizeof (pcp_response_header));

    i = 0;
    NP_ASSERT_EQUAL (version, result[i++]);
    NP_ASSERT_EQUAL (r_opcode, result[i++]);
    NP_ASSERT_EQUAL (reserved, result[i++]);
    NP_ASSERT_EQUAL (result_code, result[i++]);
    NP_ASSERT_EQUAL (lifetime,
                     (result[i] << 24) + (result[i + 1] << 16) + (result[i + 2] << 8) +
                     result[i + 3]);
    i += 4;
    NP_ASSERT_EQUAL (epoch_time,
                     (result[i] << 24) + (result[i + 1] << 16) + (result[i + 2] << 8) +
                     result[i + 3]);
    i += 4;
    for (j = 0; j < RESPONSE_RESERVED_SIZE; j++, i += 4)
    {
        NP_ASSERT_EQUAL (reserved_array[j],
                         (result[i] << 24) + (result[i + 1] << 16) + (result[i + 2] << 8) +
                         result[i + 3]);
    }
}

void
test_serialize_map_request (void)
{
    map_request test_map_req;

    // Test the header separately
    pcp_request_header header;
    u_int32_t mapping_nonce[MAPPING_NONCE_SIZE] = { 2058005162, 2058005161, 2058005160 };
    u_int8_t protocol = 6;
    u_int8_t reserved_1 = 0;
    u_int16_t reserved_2 = 0;
    u_int16_t internal_port = 51717;
    u_int16_t suggested_external_port = 51717;

    struct in6_addr suggested_external_ip;
    inet_pton (AF_INET6, "2001:db8:7654:3210:fedc:ba98:7654:3210",
               &(suggested_external_ip));

    unsigned char result[MAX_STRING_LEN];
    unsigned char *ptr;
    int i, j;

    test_map_req.header = header;
    test_map_req.mapping_nonce[0] = mapping_nonce[0];
    test_map_req.mapping_nonce[1] = mapping_nonce[1];
    test_map_req.mapping_nonce[2] = mapping_nonce[2];
    test_map_req.protocol = protocol;
    test_map_req.reserved_1 = reserved_1;
    test_map_req.reserved_2 = reserved_2;
    test_map_req.internal_port = internal_port;
    test_map_req.suggested_external_port = suggested_external_port;
    test_map_req.suggested_external_ip = suggested_external_ip;

    ptr = serialize_map_request (result, &test_map_req);
    NP_ASSERT_EQUAL (ptr - result, sizeof (map_request));

    test_serialize_request_header ();

    i = 0;
    i += sizeof (pcp_request_header);
    for (j = 0; j < MAPPING_NONCE_SIZE; j++, i += 4)
    {
        NP_ASSERT_EQUAL (mapping_nonce[j],
                         (result[i] << 24) + (result[i + 1] << 16) + (result[i + 2] << 8) +
                         result[i + 3]);
    }
    NP_ASSERT_EQUAL (protocol, result[i++]);
    NP_ASSERT_EQUAL (reserved_1, result[i++]);
    NP_ASSERT_EQUAL (reserved_2, (result[i] << 8) + result[i + 1]);
    i += 2;
    NP_ASSERT_EQUAL (internal_port, (result[i] << 8) + result[i + 1]);
    i += 2;
    NP_ASSERT_EQUAL (suggested_external_port, (result[i] << 8) + result[i + 1]);
    i += 2;
    for (j = 0; j < sizeof (struct in6_addr); j++, i++)
    {
        NP_ASSERT_EQUAL (suggested_external_ip.s6_addr[j], result[i]);
    }
}

void
test_serialize_map_response (void)
{
    map_response test_map_resp;

    // Test the header separately
    pcp_response_header header;
    u_int32_t mapping_nonce[MAPPING_NONCE_SIZE] = { 2058005162, 2058005161, 2058005160 };
    u_int8_t protocol = 6;
    u_int8_t reserved_1 = 0;
    u_int16_t reserved_2 = 0;
    u_int16_t internal_port = 51717;
    u_int16_t assigned_external_port = 51717;

    struct in6_addr assigned_external_ip;
    inet_pton (AF_INET6, "2001:db8:7654:3210:fedc:ba98:7654:3210",
               &(assigned_external_ip));

    unsigned char result[MAX_STRING_LEN];
    unsigned char *ptr;
    int i, j;

    test_map_resp.header = header;
    test_map_resp.mapping_nonce[0] = mapping_nonce[0];
    test_map_resp.mapping_nonce[1] = mapping_nonce[1];
    test_map_resp.mapping_nonce[2] = mapping_nonce[2];
    test_map_resp.protocol = protocol;
    test_map_resp.reserved_1 = reserved_1;
    test_map_resp.reserved_2 = reserved_2;
    test_map_resp.internal_port = internal_port;
    test_map_resp.assigned_external_port = assigned_external_port;
    test_map_resp.assigned_external_ip = assigned_external_ip;

    ptr = serialize_map_response (result, &test_map_resp);
    NP_ASSERT_EQUAL (ptr - result, sizeof (map_response));

    i = 0;
    test_serialize_response_header ();
    i += sizeof (pcp_response_header);  // Skip past the header
    for (j = 0; j < MAPPING_NONCE_SIZE; j++, i += 4)
    {
        NP_ASSERT_EQUAL (mapping_nonce[j],
                         (result[i] << 24) + (result[i + 1] << 16) + (result[i + 2] << 8) +
                         result[i + 3]);
    }
    NP_ASSERT_EQUAL (protocol, result[i++]);
    NP_ASSERT_EQUAL (reserved_1, result[i++]);
    NP_ASSERT_EQUAL (reserved_2, (result[i] << 8) + result[i + 1]);
    i += 2;
    NP_ASSERT_EQUAL (internal_port, (result[i] << 8) + result[i + 1]);
    i += 2;
    NP_ASSERT_EQUAL (assigned_external_port, (result[i] << 8) + result[i + 1]);
    i += 2;
    for (j = 0; j < sizeof (struct in6_addr); j++, i++)
    {
        NP_ASSERT_EQUAL (assigned_external_ip.s6_addr[j], result[i]);
    }
}

void
test_deserialize_request_header (void)
{
    pcp_request_header result;

    u_int8_t version = PCP_VERSION;
    u_int8_t r_opcode = R_REQUEST (PEER_OPCODE);
    u_int16_t reserved = 0;
    u_int32_t req_lifetime = 86400; // 24 hrs

    struct in6_addr client_ip;
    inet_pton (AF_INET6, "2001:db8:7654:3210:fedc:ba98:7654:3210", &(client_ip));

    unsigned char test_data[sizeof (pcp_request_header)] = {
        version, r_opcode, reserved >> 8, reserved,
        req_lifetime >> 24, req_lifetime >> 16, req_lifetime >> 8, req_lifetime,
        0x20, 0x01, 0x0D, 0xB8,
        0x76, 0x54, 0x32, 0x10,
        0xFE, 0xDC, 0xBA, 0x98,
        0x76, 0x54, 0x32, 0x10
    };

    unsigned char *ptr;
    int i;

    ptr = deserialize_request_header (&result, test_data);

    NP_ASSERT_EQUAL (ptr - test_data, sizeof (pcp_request_header));

    NP_ASSERT_EQUAL (version, result.version);
    NP_ASSERT_EQUAL (r_opcode, result.r_opcode);
    NP_ASSERT_EQUAL (reserved, result.reserved);
    NP_ASSERT_EQUAL (req_lifetime, result.requested_lifetime);
    for (i = 0; i < sizeof (struct in6_addr); i++)
    {
        NP_ASSERT_EQUAL (client_ip.s6_addr[i], result.client_ip.s6_addr[i]);
    }
}

void
test_deserialize_response_header (void)
{
    pcp_response_header result;

    u_int8_t version = PCP_VERSION;
    u_int8_t r_opcode = R_RESPONSE (MAP_OPCODE);
    u_int8_t reserved = 0;
    u_int8_t result_code = 2;
    u_int32_t lifetime = 86400; // 24 hrs
    u_int32_t epoch_time = 1419215249;
    u_int32_t reserved_array[RESPONSE_RESERVED_SIZE] = { 0, 0, 0 };

    unsigned char test_data[sizeof (pcp_response_header)] = {
        version, r_opcode, reserved, result_code,
        lifetime >> 24, lifetime >> 16, lifetime >> 8, lifetime,
        epoch_time >> 24, epoch_time >> 16, epoch_time >> 8, epoch_time,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0
    };

    unsigned char *ptr;
    int i;

    ptr = deserialize_response_header (&result, test_data);

    NP_ASSERT_EQUAL (ptr - test_data, sizeof (pcp_response_header));

    NP_ASSERT_EQUAL (version, result.version);
    NP_ASSERT_EQUAL (r_opcode, result.r_opcode);
    NP_ASSERT_EQUAL (reserved, result.reserved);
    NP_ASSERT_EQUAL (result_code, result.result_code);
    NP_ASSERT_EQUAL (lifetime, result.lifetime);
    NP_ASSERT_EQUAL (epoch_time, result.epoch_time);
    for (i = 0; i < RESPONSE_RESERVED_SIZE; i++)
    {
        NP_ASSERT_EQUAL (reserved_array[i], result.reserved_array[i]);
    }
}

void
test_deserialize_map_request (void)
{
    map_request *result;

    u_int32_t mapping_nonce[MAPPING_NONCE_SIZE] = { 2058005162, 2058005161, 2058005160 };
    u_int8_t protocol = 6;
    u_int8_t reserved_1 = 0;
    u_int16_t reserved_2 = 0;
    u_int16_t internal_port = 51717;
    u_int16_t suggested_external_port = 51717;

    struct in6_addr suggested_external_ip;
    inet_pton (AF_INET6, "2001:db8:7654:3210:fedc:ba98:7654:3210",
               &(suggested_external_ip));

    unsigned char test_data[sizeof (map_request)] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Ignore the header
        mapping_nonce[0] >> 24, mapping_nonce[0] >> 16, mapping_nonce[0] >> 8,
        mapping_nonce[0],
        mapping_nonce[1] >> 24, mapping_nonce[1] >> 16, mapping_nonce[1] >> 8,
        mapping_nonce[1],
        mapping_nonce[2] >> 24, mapping_nonce[2] >> 16, mapping_nonce[2] >> 8,
        mapping_nonce[2],
        protocol, reserved_1, reserved_2 >> 8, reserved_2,
        internal_port >> 8, internal_port, suggested_external_port >> 8,
        suggested_external_port,
        0x20, 0x01, 0x0D, 0xB8,
        0x76, 0x54, 0x32, 0x10,
        0xFE, 0xDC, 0xBA, 0x98,
        0x76, 0x54, 0x32, 0x10
    };

    int i;

    result = deserialize_map_request (test_data);

    test_deserialize_request_header ();
    NP_ASSERT_EQUAL (mapping_nonce[0], result->mapping_nonce[0]);
    NP_ASSERT_EQUAL (mapping_nonce[1], result->mapping_nonce[1]);
    NP_ASSERT_EQUAL (mapping_nonce[2], result->mapping_nonce[2]);
    NP_ASSERT_EQUAL (protocol, result->protocol);
    NP_ASSERT_EQUAL (reserved_1, result->reserved_1);
    NP_ASSERT_EQUAL (reserved_2, result->reserved_2);
    NP_ASSERT_EQUAL (internal_port, result->internal_port);
    NP_ASSERT_EQUAL (suggested_external_port, result->suggested_external_port);
    for (i = 0; i < sizeof (struct in6_addr); i++)
    {
        NP_ASSERT_EQUAL (suggested_external_ip.s6_addr[i],
                         result->suggested_external_ip.s6_addr[i]);
    }

    free (result);
}

void
test_deserialize_map_response (void)
{
    map_response *result;

    u_int32_t mapping_nonce[MAPPING_NONCE_SIZE] = { 2058005162, 2058005161, 2058005160 };
    u_int8_t protocol = 6;
    u_int8_t reserved_1 = 0;
    u_int16_t reserved_2 = 0;
    u_int16_t internal_port = 51717;
    u_int16_t assigned_external_port = 51717;

    struct in6_addr assigned_external_ip;
    inet_pton (AF_INET6, "2001:db8:7654:3210:fedc:ba98:7654:3210",
               &(assigned_external_ip));

    unsigned char test_data[sizeof (map_response)] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Ignore the header
        mapping_nonce[0] >> 24, mapping_nonce[0] >> 16, mapping_nonce[0] >> 8,
        mapping_nonce[0],
        mapping_nonce[1] >> 24, mapping_nonce[1] >> 16, mapping_nonce[1] >> 8,
        mapping_nonce[1],
        mapping_nonce[2] >> 24, mapping_nonce[2] >> 16, mapping_nonce[2] >> 8,
        mapping_nonce[2],
        protocol, reserved_1, reserved_2 >> 8, reserved_2,
        internal_port >> 8, internal_port, assigned_external_port >> 8,
        assigned_external_port,
        0x20, 0x01, 0x0D, 0xB8,
        0x76, 0x54, 0x32, 0x10,
        0xFE, 0xDC, 0xBA, 0x98,
        0x76, 0x54, 0x32, 0x10
    };

    int i;

    result = deserialize_map_response (test_data);

    test_deserialize_request_header ();
    NP_ASSERT_EQUAL (mapping_nonce[0], result->mapping_nonce[0]);
    NP_ASSERT_EQUAL (mapping_nonce[1], result->mapping_nonce[1]);
    NP_ASSERT_EQUAL (mapping_nonce[2], result->mapping_nonce[2]);
    NP_ASSERT_EQUAL (protocol, result->protocol);
    NP_ASSERT_EQUAL (reserved_1, result->reserved_1);
    NP_ASSERT_EQUAL (reserved_2, result->reserved_2);
    NP_ASSERT_EQUAL (internal_port, result->internal_port);
    NP_ASSERT_EQUAL (assigned_external_port, result->assigned_external_port);
    for (i = 0; i < sizeof (struct in6_addr); i++)
    {
        NP_ASSERT_EQUAL (assigned_external_ip.s6_addr[i],
                         result->assigned_external_ip.s6_addr[i]);
    }

    free (result);
}
