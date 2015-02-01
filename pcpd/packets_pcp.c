/**
 * PCP packet functions.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <arpa/inet.h>

#include "packets_pcp.h"

/**
 * @brief new_pcp_request_header - Create a new pcp request header, used by clients.
 *          Function incomplete and initially used for testing only. Use for PCP proxy
 *          in future.
 * @param hdr - Where to place result
 * @param opcode - The opcode of the packet
 * @param requested_lifetime - The requested lifetime
 * @param ip6str - The ipv6 address of the source
 * @return - True if function was successful
 */
bool
new_pcp_request_header (pcp_request_header *hdr,
                        u_int8_t opcode, u_int32_t requested_lifetime, const char *ip6str)
{
    hdr->version = PCP_VERSION;
    hdr->r_opcode = R_REQUEST (opcode);
    hdr->reserved = 0;
    hdr->requested_lifetime = requested_lifetime;
    return (inet_pton (AF_INET6, ip6str, &(hdr->client_ip)) == 1);  // success for ipv6
}

/**
 * @brief new_pcp_response_header - Create a new pcp response header, used by servers
 * @param resp_hdr - Where to place the created response
 * @param req_hdr - The corresponding request header
 * @param lifetime - Lifetime of mapping or expected lifetime of error
 */
void
new_pcp_response_header (pcp_response_header *resp_hdr, pcp_request_header *req_hdr)
{
    resp_hdr->version = PCP_VERSION;    // Set version to pcpd's current version
    resp_hdr->r_opcode = R_RESPONSE (req_hdr->r_opcode);    // Set R bit of opcode
    resp_hdr->reserved = 0;
    resp_hdr->result_code = SUCCESS;    // Set result to SUCCESS (0)
    resp_hdr->lifetime = req_hdr->requested_lifetime;
    resp_hdr->epoch_time = 0;           // Set this to time (NULL) before sending
    resp_hdr->reserved_array[0] = 0;
    resp_hdr->reserved_array[1] = 0;
    resp_hdr->reserved_array[2] = 0;
}

/**
 * Incomplete and unused by pcpd. Used only for client implementation, so complete and
 * remove magic numbers if this function is needed. Currently used only for testing
 * server functionality.
 */
map_request *
new_pcp_map_request (u_int32_t requested_lifetime, const char *ip6str)
{
    const char *ip2 = "2001:df5:b000:21:4492:4cb5:5eca:58fa";
    map_request *map_req = malloc (sizeof (map_request));
    new_pcp_request_header (&map_req->header, MAP_OPCODE, requested_lifetime, ip6str);
    map_req->mapping_nonce[0] = 2058005162;
    map_req->mapping_nonce[1] = 2058005161;
    map_req->mapping_nonce[2] = 2058005160;
    map_req->protocol = 6;
    map_req->reserved_1 = 0;
    map_req->reserved_2 = 0;
    map_req->internal_port = 51717;
    map_req->suggested_external_port = 51717;
    inet_pton (AF_INET6, ip2, &(map_req->suggested_external_ip));
    return map_req;
}

/**
 * @brief new_pcp_map_response - Create a new initial PCP MAP response
 * @param map_req - MAP request to copy values from
 * @return - The MAP response packet
 */
map_response *
new_pcp_map_response (map_request *map_req)
{
    map_response *map_resp = malloc (sizeof (map_response));
    new_pcp_response_header (&map_resp->header, &map_req->header);
    map_resp->mapping_nonce[0] = map_req->mapping_nonce[0];
    map_resp->mapping_nonce[1] = map_req->mapping_nonce[1];
    map_resp->mapping_nonce[2] = map_req->mapping_nonce[2];
    map_resp->protocol = map_req->protocol;
    map_resp->reserved_1 = 0;
    map_resp->reserved_2 = 0;
    map_resp->internal_port = map_req->internal_port;
    map_resp->assigned_external_port = map_req->suggested_external_port;
    map_resp->assigned_external_ip = map_req->suggested_external_ip;
    return map_resp;
}

/**
 * Incomplete function for PEER request creation. Currently used for testing only.
 */
peer_request *
new_pcp_peer_request (u_int32_t requested_lifetime, const char *ip6str)
{
    peer_request *peer_req = malloc (sizeof (peer_request));
    new_pcp_request_header (&peer_req->header, PEER_OPCODE, requested_lifetime, ip6str);
    return peer_req;
}

/**
 * @brief new_pcp_error_response - Create a new error PCP response
 * @param r_opcode - The r_opcode value in the original packet
 * @param result - The error result
 * @param lifetime - The lifetime of the error
 * @return - The error response
 */
pcp_response_header *
new_pcp_error_response (u_int8_t r_opcode, result_code result, u_int32_t lifetime)
{
    pcp_response_header *error_resp = malloc (sizeof (pcp_response_header));
    error_resp->version = PCP_VERSION;
    error_resp->r_opcode = R_RESPONSE (r_opcode);
    error_resp->reserved = 0;
    error_resp->result_code = result;
    error_resp->lifetime = lifetime;
    error_resp->epoch_time = time (NULL);
    error_resp->reserved_array[0] = 0;
    error_resp->reserved_array[1] = 0;
    error_resp->reserved_array[2] = 0;
    return error_resp;
}

u_int8_t
get_version (unsigned char *pkt_buf)
{
    return pkt_buf[0];
}

u_int8_t
get_r_opcode (unsigned char *pkt_buf)
{
    return pkt_buf[1];
}

bool
r_bit_is_set (unsigned char *pkt_buf)
{
    return IS_RESPONSE (get_r_opcode (pkt_buf));
}

/*
 * Get the packet type of the byte string to deserialize.
 */
packet_type
get_packet_type (unsigned char *pkt_buf)
{
    u_int8_t r_opcode = pkt_buf[1];
    bool response = IS_RESPONSE (r_opcode);
    u_int8_t opcode = OPCODE (r_opcode);

    packet_type result = PACKET_TYPE_MAX;

    if (opcode == MAP_OPCODE)
    {
        result = response ? MAP_RESPONSE : MAP_REQUEST;
    }
    else if (opcode == PEER_OPCODE)
    {
        result = response ? PEER_RESPONSE : PEER_REQUEST;
    }
    else if (opcode == ANNOUNCE_OPCODE)
    {
        result = response ? ANNOUNCE_RESPONSE : ANNOUNCE_REQUEST;
    }
    return result;
}

/**
 * @brief validate_packet_buffer - Validate a packet buffer
 * @param pkt_buf - Packet buffer
 * @param n - Length of the packet buffer
 * @return - Result code of the packet validation
 */
result_code
validate_packet_buffer (unsigned char *pkt_buf, int n)
{
    result_code ret = SUCCESS;
    packet_type type = PACKET_TYPE_MAX;

    if (n < 2 || r_bit_is_set (pkt_buf))
    {
        /* Less than 2 octets long or received a response packet.
         * Silently drop the packet. */
        ret = RESULT_CODE_MAX;
    }
    else if (get_version (pkt_buf) != PCP_VERSION)
    {
        /* Unsupported version */
        ret = UNSUPP_VERSION;
    }
    else if (n < 24)
    {
        /* Version supported but packet is too short. Silently drop the packet */
        ret = RESULT_CODE_MAX;
    }
    else if (n > MAX_PAYLOAD_LEN || n % 4 != 0)
    {
        /* Packet is too long or not a mulitiple of 4 */
        ret = MALFORMED_REQUEST;
    }
    else
    {
        /* Verify the opcode and ensure it's not too short for the opcode in question.
         * Response packets have been discarded earlier. */
        type = get_packet_type (pkt_buf);
        if (type == PACKET_TYPE_MAX)
        {
            ret = UNSUPP_OPCODE;
        }
        else if ((type == MAP_REQUEST && n < MIN_MAP_PKT_LEN) ||
                 (type == PEER_REQUEST && n < MIN_PEER_PKT_LEN) ||
                 (type == ANNOUNCE_REQUEST && n < MIN_ANNOUNCE_PKT_LEN))
        {
            ret = MALFORMED_REQUEST;
        }
    }
    return ret;
}

/**
 * @brief add_zero_padding - Add zero-padding if pkt_buf length is not a multiple of 4
 * @param pkt_buf - Buffer to modify
 * @param ptr - Pointer to the next byte of the buffer
 * @return - Pointer to the next byte of the buffer after zero-padding it
 */
unsigned char *
add_zero_padding (unsigned char *pkt_buf, unsigned char *ptr)
{
    while ((ptr - pkt_buf) % 4 != 0)
    {
        *ptr++ = 0;
    }
    return ptr;
}
