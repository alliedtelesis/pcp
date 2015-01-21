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
 * @param hdr - Where to place result
 * @param opcode - The opcode of the packet
 * @param result - The result code
 * @param lifetime - Lifetime of mapping or expected lifetime of error
 */
void
new_pcp_response_header (pcp_response_header *hdr,
                         u_int8_t opcode, result_code result, u_int32_t lifetime)
{
    hdr->version = PCP_VERSION;
    hdr->r_opcode = R_RESPONSE (opcode);
    hdr->reserved = 0;
    hdr->result_code = result;
    hdr->lifetime = lifetime;
    hdr->epoch_time = time (NULL);
    hdr->reserved_array[0] = 0;
    hdr->reserved_array[1] = 0;
    hdr->reserved_array[2] = 0;
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
 * @brief new_pcp_map_response - Create a new PCP MAP response based on results from
 *  a PCP MAP request and the creation of the mapping.
 * @param lifetime - Lifetime of mapping or expected lifetime of error
 * @param port - The assigned external port
 * @param ipv6_addr - The ipv6 address of assigned external address
 * @return - The MAP response packet
 */
map_response *
new_pcp_map_response (map_request *map_req,
                      u_int32_t lifetime, result_code result, u_int16_t port,
                      struct in6_addr *ipv6_addr)
{
    // TODO: Make function work as described in RFC page 24/25
    map_response *map_resp = malloc (sizeof (map_response));
    new_pcp_response_header (&map_resp->header, MAP_OPCODE, result, lifetime);
    map_resp->mapping_nonce[0] = map_req->mapping_nonce[0];
    map_resp->mapping_nonce[1] = map_req->mapping_nonce[1];
    map_resp->mapping_nonce[2] = map_req->mapping_nonce[2];
    map_resp->protocol = map_req->protocol;
    map_resp->reserved_1 = 0;
    map_resp->reserved_2 = 0;
    map_resp->internal_port = map_req->internal_port;

    if (map_resp->header.result_code == SUCCESS)
    {
        // If SUCCESS, put actual values of assigned ip/port in, NOT copy over from request
        map_resp->assigned_external_port = port;
        map_resp->assigned_external_ip = *ipv6_addr;
    }
    else
    {
        map_resp->assigned_external_port = map_req->suggested_external_port;
        map_resp->assigned_external_ip = map_req->suggested_external_ip;
    }
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
