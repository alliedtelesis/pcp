/**
 * @file packets_pcp_serialization.c
 *
 * Functions for serializing PCP packet data.
 *
 * Copyright 2015 Allied Telesis Labs, New Zealand
 *
 * This file is part of pcpd.
 *
 * pcpd is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * pcpd is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with pcpd.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <arpa/inet.h>

#include "packets_pcp.h"

/* The following "unsigned char *serialize_xx (unsigned char *buffer, u_intx_t value)"
 * functions all take the integer value given by value and place it into the buffer.
 * Then it returns a pointer which points to the buffer at the end location of the
 * serialized value to prepare for the next serialization call.
 */

unsigned char *
serialize_u_int8_t (unsigned char *buffer, u_int8_t value)
{
    buffer[0] = (value) & 0xFF;
    return buffer + 1;
}

unsigned char *
serialize_u_int16_t (unsigned char *buffer, u_int16_t value)
{
    buffer[0] = (value >> 8) & 0xFF;
    buffer[1] = (value) & 0xFF;
    return buffer + 2;
}

unsigned char *
serialize_u_int32_t (unsigned char *buffer, u_int32_t value)
{
    buffer[0] = (value >> 24) & 0xFF;
    buffer[1] = (value >> 16) & 0xFF;
    buffer[2] = (value >> 8) & 0xFF;
    buffer[3] = (value) & 0xFF;
    return buffer + 4;
}

unsigned char *
serialize_ip_address (unsigned char *buffer, struct in6_addr *ip_address)
{
    memcpy (buffer, ip_address->s6_addr, sizeof (struct in6_addr));
    return buffer + sizeof (struct in6_addr);
}

unsigned char *
serialize_u_int32_t_array3 (unsigned char *buffer, u_int32_t value[3])
{
    int i;
    for (i = 0; i < 3; i++)
    {
        buffer = serialize_u_int32_t (buffer, value[i]);
    }
    return buffer;
}

/*
 * The following serialization functions serialize entire packets by calling the
 * above functions multiple times for each of the different packet variables.
 * Returns a pointer to the end of the buffer.
 */

unsigned char *
serialize_request_header (unsigned char *buffer, pcp_request_header *header)
{
    buffer = serialize_u_int8_t (buffer, header->version);
    buffer = serialize_u_int8_t (buffer, header->r_opcode);
    buffer = serialize_u_int16_t (buffer, header->reserved);
    buffer = serialize_u_int32_t (buffer, header->requested_lifetime);
    buffer = serialize_ip_address (buffer, &(header->client_ip));
    return buffer;
}

unsigned char *
serialize_response_header (unsigned char *buffer, pcp_response_header *header)
{
    buffer = serialize_u_int8_t (buffer, header->version);
    buffer = serialize_u_int8_t (buffer, header->r_opcode);
    buffer = serialize_u_int8_t (buffer, header->reserved);
    buffer = serialize_u_int8_t (buffer, header->result_code);
    buffer = serialize_u_int32_t (buffer, header->lifetime);
    buffer = serialize_u_int32_t (buffer, header->epoch_time);
    buffer = serialize_u_int32_t_array3 (buffer, header->reserved_array);
    return buffer;
}

unsigned char *
serialize_map_request (unsigned char *buffer, map_request *data)
{
    buffer = serialize_request_header (buffer, &(data->header));
    buffer = serialize_u_int32_t_array3 (buffer, data->mapping_nonce);
    buffer = serialize_u_int8_t (buffer, data->protocol);
    buffer = serialize_u_int8_t (buffer, data->reserved_1);
    buffer = serialize_u_int16_t (buffer, data->reserved_2);
    buffer = serialize_u_int16_t (buffer, data->internal_port);
    buffer = serialize_u_int16_t (buffer, data->suggested_external_port);
    buffer = serialize_ip_address (buffer, &(data->suggested_external_ip));
    return buffer;
}

unsigned char *
serialize_map_response (unsigned char *buffer, map_response *data)
{
    buffer = serialize_response_header (buffer, &(data->header));
    buffer = serialize_u_int32_t_array3 (buffer, data->mapping_nonce);
    buffer = serialize_u_int8_t (buffer, data->protocol);
    buffer = serialize_u_int8_t (buffer, data->reserved_1);
    buffer = serialize_u_int16_t (buffer, data->reserved_2);
    buffer = serialize_u_int16_t (buffer, data->internal_port);
    buffer = serialize_u_int16_t (buffer, data->assigned_external_port);
    buffer = serialize_ip_address (buffer, &(data->assigned_external_ip));
    return buffer;
}

/*
 * The following deserialize value functions deserialize a byte string and place
 * the result value to dest. Returns a pointer to the end of the decoded data
 * in the data buffer.
 */

unsigned char *
deserialize_u_int8_t (u_int8_t *dest, unsigned char *data)
{
    *dest = data[0];
    return data + 1;
}

unsigned char *
deserialize_u_int16_t (u_int16_t *dest, unsigned char *data)
{
    *dest = (data[0] << 8) + data[1];
    return data + 2;
}

unsigned char *
deserialize_u_int32_t (u_int32_t *dest, unsigned char *data)
{
    *dest = (data[0] << 24) + (data[1] << 16) + (data[2] << 8) + data[3];
    return data + 4;
}

unsigned char *
deserialize_ip_address (struct in6_addr *ip_address, unsigned char *data)
{
    memcpy (ip_address->s6_addr, data, sizeof (struct in6_addr));
    return data + sizeof (struct in6_addr);
}

unsigned char *
deserialize_u_int32_t_array3 (u_int32_t dest[3], unsigned char *data)
{
    int i;
    for (i = 0; i < 3; i++)
    {
        data = deserialize_u_int32_t (dest + i, data);
    }
    return data;
}

/*
 * The following deserialize packet functions deserialize a longer byte string and place
 * the resulting packet to the destination. Returns a pointer to the end of the decoded data
 * in the data buffer.
 * TODO: Handle malloc returning NULL.
 */

unsigned char *
deserialize_request_header (pcp_request_header *hdr, unsigned char *data)
{
    data = deserialize_u_int8_t (&hdr->version, data);
    data = deserialize_u_int8_t (&hdr->r_opcode, data);
    data = deserialize_u_int16_t (&hdr->reserved, data);
    data = deserialize_u_int32_t (&hdr->requested_lifetime, data);
    data = deserialize_ip_address (&hdr->client_ip, data);
    return data;
}

unsigned char *
deserialize_response_header (pcp_response_header *hdr, unsigned char *data)
{
    data = deserialize_u_int8_t (&hdr->version, data);
    data = deserialize_u_int8_t (&hdr->r_opcode, data);
    data = deserialize_u_int8_t (&hdr->reserved, data);
    data = deserialize_u_int8_t (&hdr->result_code, data);
    data = deserialize_u_int32_t (&hdr->lifetime, data);
    data = deserialize_u_int32_t (&hdr->epoch_time, data);
    data = deserialize_u_int32_t_array3 (hdr->reserved_array, data);
    return data;
}

map_request *
deserialize_map_request (unsigned char *data)
{
    map_request *map_req = malloc (sizeof (map_request));
    data = deserialize_request_header (&map_req->header, data);
    data = deserialize_u_int32_t_array3 (map_req->mapping_nonce, data);
    data = deserialize_u_int8_t (&map_req->protocol, data);
    data = deserialize_u_int8_t (&map_req->reserved_1, data);
    data = deserialize_u_int16_t (&map_req->reserved_2, data);
    data = deserialize_u_int16_t (&map_req->internal_port, data);
    data = deserialize_u_int16_t (&map_req->suggested_external_port, data);
    data = deserialize_ip_address (&map_req->suggested_external_ip, data);
    return map_req;
}

map_response *
deserialize_map_response (unsigned char *data)
{
    map_response *map_resp = malloc (sizeof (map_response));
    data = deserialize_response_header (&map_resp->header, data);
    data = deserialize_u_int32_t_array3 (map_resp->mapping_nonce, data);
    data = deserialize_u_int8_t (&map_resp->protocol, data);
    data = deserialize_u_int8_t (&map_resp->reserved_1, data);
    data = deserialize_u_int16_t (&map_resp->reserved_2, data);
    data = deserialize_u_int16_t (&map_resp->internal_port, data);
    data = deserialize_u_int16_t (&map_resp->assigned_external_port, data);
    data = deserialize_ip_address (&map_resp->assigned_external_ip, data);
    return map_resp;
}
