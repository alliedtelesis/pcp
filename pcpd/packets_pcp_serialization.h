/**
 * Function declarations for serializing PCP packet data
 */

// Serialize various types of variables and place into a buffer.
unsigned char *serialize_u_int8_t (unsigned char *buffer, u_int8_t value);

unsigned char *serialize_u_int16_t (unsigned char *buffer, u_int16_t value);

unsigned char *serialize_u_int32_t (unsigned char *buffer, u_int32_t value);

unsigned char *serialize_ip_address (unsigned char *buffer, struct in6_addr ip_address);

unsigned char *serialize_u_int32_t_array3 (unsigned char *buffer, u_int32_t value[3]);

// Deserialize various types of variables and place value at pointer.
unsigned char *deserialize_u_int8_t (u_int8_t *dest, unsigned char *data);

unsigned char *deserialize_u_int16_t (u_int16_t *dest, unsigned char *data);

unsigned char *deserialize_u_int32_t (u_int32_t *dest, unsigned char *data);

unsigned char *deserialize_ip_address (struct in6_addr *ip_address, unsigned char *data);

unsigned char *deserialize_u_int32_t_array3 (u_int32_t dest[3], unsigned char *data);

// Get the packet type by parsing a byte array.
packet_type get_packet_type (unsigned char *pkt_buf);

// Serialize a packet and place the result in a buffer.
unsigned char *serialize_request_header (unsigned char *buffer, pcp_request_header *header);

unsigned char *serialize_response_header (unsigned char *buffer,
                                          pcp_response_header *header);

unsigned char *serialize_map_request (unsigned char *buffer, map_request *data);

unsigned char *serialize_map_response (unsigned char *buffer, map_response *data);

// Deserialize a packet and return the result.
unsigned char *deserialize_request_header (pcp_request_header *hdr, unsigned char *data);

unsigned char *deserialize_response_header (pcp_response_header *hdr, unsigned char *data);

map_request *deserialize_map_request (unsigned char *data);

map_response *deserialize_map_response (unsigned char *data);
