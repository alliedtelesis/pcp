#include <np.h> /* NovaProva library */
#include "../api/libpcp.h"
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>

/* Give apteryx time to start or close */
#define WAIT_TIME 150 * 1000

int
set_up (void)
{
    system ("apteryxd -b");
    usleep (WAIT_TIME);
    pcp_init ();
    return 0;
}

/* Test libpcp config setters and getters */
void
test_pcp_initialized_set_get (void)
{
    NP_ASSERT_TRUE (pcp_initialized_set (true));
    NP_ASSERT_EQUAL (pcp_initialized_get (), true);

    NP_ASSERT_TRUE (pcp_initialized_set (false));
    NP_ASSERT_EQUAL (pcp_initialized_get (), false);
}

void
test_pcp_enabled_set_get (void)
{
    NP_ASSERT_TRUE (pcp_enabled_set (true));
    NP_ASSERT_EQUAL (pcp_enabled_get (), true);

    NP_ASSERT_TRUE (pcp_enabled_set (false));
    NP_ASSERT_EQUAL (pcp_enabled_get (), false);
}

void
test_map_support_set_get (void)
{
    NP_ASSERT_TRUE (map_support_set (true));
    NP_ASSERT_EQUAL (map_support_get (), true);

    NP_ASSERT_TRUE (map_support_set (false));
    NP_ASSERT_EQUAL (map_support_get (), false);
}

void
test_peer_support_set_get (void)
{
    NP_ASSERT_TRUE (peer_support_set (true));
    NP_ASSERT_EQUAL (peer_support_get (), true);

    NP_ASSERT_TRUE (peer_support_set (false));
    NP_ASSERT_EQUAL (peer_support_get (), false);
}

void
test_third_party_support_set_get (void)
{
    NP_ASSERT_TRUE (third_party_support_set (true));
    NP_ASSERT_EQUAL (third_party_support_get (), true);

    NP_ASSERT_TRUE (third_party_support_set (false));
    NP_ASSERT_EQUAL (third_party_support_get (), false);
}

void
test_proxy_support_set_get (void)
{
    NP_ASSERT_TRUE (proxy_support_set (true));
    NP_ASSERT_EQUAL (proxy_support_get (), true);

    NP_ASSERT_TRUE (proxy_support_set (false));
    NP_ASSERT_EQUAL (proxy_support_get (), false);
}

void
test_upnp_igd_pcp_iwf_support_set_get (void)
{
    NP_ASSERT_TRUE (upnp_igd_pcp_iwf_support_set (true));
    NP_ASSERT_EQUAL (upnp_igd_pcp_iwf_support_get (), true);

    NP_ASSERT_TRUE (upnp_igd_pcp_iwf_support_set (false));
    NP_ASSERT_EQUAL (upnp_igd_pcp_iwf_support_get (), false);
}

void
test_min_mapping_lifetime_set_get (void)
{
    NP_ASSERT_TRUE (min_mapping_lifetime_set (1234567890));
    NP_ASSERT_EQUAL (min_mapping_lifetime_get (), 1234567890);

    NP_ASSERT_TRUE (min_mapping_lifetime_set (DEFAULT_MIN_MAPPING_LIFETIME));
    NP_ASSERT_EQUAL (min_mapping_lifetime_get (), DEFAULT_MIN_MAPPING_LIFETIME);
}

void
test_max_mapping_lifetime_set_get (void)
{
    NP_ASSERT_TRUE (max_mapping_lifetime_set (1234567892));
    NP_ASSERT_EQUAL (max_mapping_lifetime_get (), 1234567892);

    NP_ASSERT_TRUE (max_mapping_lifetime_set (DEFAULT_MAX_MAPPING_LIFETIME));
    NP_ASSERT_EQUAL (max_mapping_lifetime_get (), DEFAULT_MAX_MAPPING_LIFETIME);
}

void
test_prefer_failure_req_rate_limit_set_get (void)
{
    NP_ASSERT_TRUE (prefer_failure_req_rate_limit_set (1234567894));
    NP_ASSERT_EQUAL (prefer_failure_req_rate_limit_get (), 1234567894);

    NP_ASSERT_TRUE (prefer_failure_req_rate_limit_set (DEFAULT_PREFER_FAILURE_REQ_RATE_LIMIT));
    NP_ASSERT_EQUAL (prefer_failure_req_rate_limit_get (), DEFAULT_PREFER_FAILURE_REQ_RATE_LIMIT);
}

/* Test the load config function when PCP has not yet been initialized. This will load the
 * default config and simultaneously tests the config_set_default function. */
void
test_pcp_load_config (void)
{
    NP_ASSERT_TRUE (pcp_load_config ());

    NP_ASSERT_EQUAL (pcp_initialized_get (), true);
    NP_ASSERT_EQUAL (pcp_enabled_get (), true);

    NP_ASSERT_EQUAL (map_support_get (), DEFAULT_MAP_SUPPORT);
    NP_ASSERT_EQUAL (peer_support_get (), DEFAULT_PEER_SUPPORT);
    NP_ASSERT_EQUAL (third_party_support_get (), DEFAULT_THIRD_PARTY_SUPPORT);
    NP_ASSERT_EQUAL (proxy_support_get (), DEFAULT_PROXY_SUPPORT);
    NP_ASSERT_EQUAL (upnp_igd_pcp_iwf_support_get (), DEFAULT_UPNP_IGD_PCP_IWF_SUPPORT);
    NP_ASSERT_EQUAL (min_mapping_lifetime_get (), DEFAULT_MIN_MAPPING_LIFETIME);
    NP_ASSERT_EQUAL (max_mapping_lifetime_get (), DEFAULT_MAX_MAPPING_LIFETIME);
    NP_ASSERT_EQUAL (prefer_failure_req_rate_limit_get (), DEFAULT_PREFER_FAILURE_REQ_RATE_LIMIT);
}

/* Test the apteryx set and get functions for IPv6 addresses introduced in libpcp */
void
test_apteryx_set_get_ipv6_addr (void)
{
    struct in6_addr test_ip;
    struct in6_addr result_ip;
    inet_pton (AF_INET6, "2001:db8:7654:3210:fedc:ba98:7654:3210", &(test_ip));

    NP_ASSERT_TRUE (apteryx_set_ipv6_addr ("/pcp/testing", "test_ip_key", test_ip));

    result_ip = apteryx_get_ipv6_addr ("/pcp/testing", "test_ip_key");

    int i;
    for (i = 0; i < sizeof (struct in6_addr); i++)
    {
        NP_ASSERT_EQUAL (result_ip.s6_addr[i], test_ip.s6_addr[i]);
    }
}

/* Test the function for freeing memory for PCP mappings */
void
test_pcp_mapping_destroy (void)
{
    pcp_mapping mapping;

    // Allocate some memory
    mapping = malloc (sizeof (*mapping));
    asprintf (&mapping->path, "/pcp/testpath/123");

    // Free it. Valgrind will fail the test if not freed properly.
    pcp_mapping_destroy (mapping);
}

/* Helper functions that add mappings to apteryx */
static void
add_test_mapping (int index)
{
    u_int32_t mapping_nonce[MAPPING_NONCE_SIZE] = {1732282673, 1882683910, 2109096625};
    struct in6_addr internal_ip;
    u_int16_t internal_port = 1234;
    struct in6_addr external_ip;
    u_int16_t external_port = 9876;
    u_int32_t lifetime = 8002;
    u_int8_t opcode = MAP_OPCODE;
    u_int8_t protocol = 6;

    inet_pton (AF_INET6, "2001:db8:7654:3210:fedc:ba98:7654:3210", &(internal_ip));
    inet_pton (AF_INET6, "2001:db8:7654:1234:fedc:abab:4554:9875", &(external_ip));

    NP_ASSERT_TRUE (pcp_mapping_add (index, mapping_nonce, &internal_ip,
                                     internal_port, &external_ip, external_port,
                                     lifetime, opcode, protocol));
}

static void
add_three_test_mappings (int index1, int index2, int index3)
{
    add_test_mapping (index1);
    add_test_mapping (index2);
    add_test_mapping (index3);
}

static void
add_three_mappings (int index1,
                    int index2,
                    int index3,
                    u_int32_t mapping_nonce[MAPPING_NONCE_SIZE],
                    struct in6_addr *internal_ip,
                    u_int16_t internal_port,
                    struct in6_addr *external_ip,
                    u_int16_t external_port,
                    u_int32_t lifetime,
                    u_int8_t opcode,
                    u_int8_t protocol)
{
    NP_ASSERT_TRUE (pcp_mapping_add (index1, mapping_nonce, internal_ip,
                                     internal_port, external_ip, external_port,
                                     lifetime, opcode, protocol));

    NP_ASSERT_TRUE (pcp_mapping_add (index2, mapping_nonce, internal_ip,
                                     internal_port, external_ip, external_port,
                                     lifetime, opcode, protocol));

    NP_ASSERT_TRUE (pcp_mapping_add (index3, mapping_nonce, internal_ip,
                                     internal_port, external_ip, external_port,
                                     lifetime, opcode, protocol));
}

/* Test the add and find functions */
void
test_pcp_mapping_add_find (void)
{
    int index1 = 54;
    int index2 = 154;
    int index3 = 254;
    u_int32_t mapping_nonce[MAPPING_NONCE_SIZE] = {1732282673, 1882683910, 2109096625};
    struct in6_addr internal_ip;
    u_int16_t internal_port = 1234;
    struct in6_addr external_ip;
    u_int16_t external_port = 9876;
    u_int32_t lifetime = 8002;
    u_int8_t opcode = MAP_OPCODE;
    u_int8_t protocol = 6;
    pcp_mapping mapping;
    int i;

    inet_pton (AF_INET6, "2001:db8:7654:3210:fedc:ba98:7654:3210", &(internal_ip));
    inet_pton (AF_INET6, "2001:db8:7654:1234:fedc:abab:4554:9875", &(external_ip));

    add_three_mappings (index1, index2, index3,
                        mapping_nonce, &internal_ip,
                        internal_port, &external_ip,
                        external_port, lifetime,
                        opcode, protocol);

    /* Get the second one to check that find function doesn't just grab
     * the first or last entry */
    mapping = pcp_mapping_find (index2);

    NP_ASSERT_NOT_NULL (mapping);

    NP_ASSERT_EQUAL (mapping->index, index2);
    NP_ASSERT_EQUAL (mapping->internal_port, internal_port);
    NP_ASSERT_EQUAL (mapping->external_port, external_port);
    NP_ASSERT_EQUAL (mapping->lifetime, lifetime);
    NP_ASSERT_EQUAL (mapping->opcode, opcode);
    NP_ASSERT_EQUAL (mapping->protocol, protocol);

    for (i = 0; i < MAPPING_NONCE_SIZE; i++)
    {
        NP_ASSERT_EQUAL (mapping->mapping_nonce[i], mapping_nonce[i]);
    }
    for (i = 0; i < sizeof (struct in6_addr); i++)
    {
        NP_ASSERT_EQUAL (mapping->internal_ip.s6_addr[i], internal_ip.s6_addr[i]);
        NP_ASSERT_EQUAL (mapping->external_ip.s6_addr[i], external_ip.s6_addr[i]);
    }

    pcp_mapping_destroy (mapping);
}

/* Test the delete function. Test depends on the add and find functions */
void
test_pcp_mapping_delete (void)
{
    int index = 300;
    pcp_mapping mapping;

    add_test_mapping (index);

    mapping = pcp_mapping_find (index);
    NP_ASSERT_NOT_NULL (mapping);
    pcp_mapping_destroy (mapping);

    NP_ASSERT_TRUE (pcp_mapping_delete (index));
    NP_ASSERT_NULL (pcp_mapping_find (index));
}

/* Test the deleteall function. Test depends on the add and find functions */
void
test_pcp_mapping_deleteall (void)
{
    int index1 = 400;
    int index2 = 450;
    int index3 = 500;
    pcp_mapping mapping1;
    pcp_mapping mapping2;
    pcp_mapping mapping3;

    add_three_test_mappings (index1, index2, index3);

    mapping1 = pcp_mapping_find (index1);
    mapping2 = pcp_mapping_find (index2);
    mapping3 = pcp_mapping_find (index3);

    NP_ASSERT_NOT_NULL (mapping1);
    pcp_mapping_destroy (mapping1);

    NP_ASSERT_NOT_NULL (mapping2);
    pcp_mapping_destroy (mapping2);

    NP_ASSERT_NOT_NULL (mapping3);
    pcp_mapping_destroy (mapping3);

    NP_ASSERT_TRUE (pcp_mapping_deleteall ());
    NP_ASSERT_NULL (pcp_mapping_find (index1));
    NP_ASSERT_NULL (pcp_mapping_find (index2));
    NP_ASSERT_NULL (pcp_mapping_find (index3));
}

/* Test the getall function. Test depends on the add function */
void
test_pcp_mapping_getall (void)
{
    int index[3] = {400, 450, 500};
    u_int32_t mapping_nonce[MAPPING_NONCE_SIZE] = {1732282673, 1882683910, 2109096625};
    struct in6_addr internal_ip;
    u_int16_t internal_port = 1234;
    struct in6_addr external_ip;
    u_int16_t external_port = 9876;
    u_int32_t lifetime = 8002;
    u_int8_t opcode = MAP_OPCODE;
    u_int8_t protocol = 6;
    int i, j;

    GList *mappings;
    GList *elem;
    pcp_mapping mapping = NULL;
    int count = 0;

    inet_pton (AF_INET6, "2001:db8:7654:3210:fedc:ba98:7654:3210", &(internal_ip));
    inet_pton (AF_INET6, "2001:db8:7654:1234:fedc:abab:4554:9875", &(external_ip));

    // Add mappings with indices out of sequence
    add_three_mappings (index[2], index[0], index[1],
                        mapping_nonce, &internal_ip,
                        internal_port, &external_ip,
                        external_port, lifetime,
                        opcode, protocol);

    mappings = pcp_mapping_getall ();

    for (elem = mappings, i = 0; elem; elem = elem->next, i++)
    {
        mapping = (pcp_mapping) elem->data;
        NP_ASSERT_NOT_NULL (mapping);

        // Indices in GList mappings should be sorted
        NP_ASSERT_EQUAL (mapping->index, index[i]);
        NP_ASSERT_EQUAL (mapping->internal_port, internal_port);
        NP_ASSERT_EQUAL (mapping->external_port, external_port);
        NP_ASSERT_EQUAL (mapping->lifetime, lifetime);
        NP_ASSERT_EQUAL (mapping->opcode, opcode);
        NP_ASSERT_EQUAL (mapping->protocol, protocol);

        for (j = 0; j < MAPPING_NONCE_SIZE; j++)
        {
            NP_ASSERT_EQUAL (mapping->mapping_nonce[j], mapping_nonce[j]);
        }
        for (j = 0; j < sizeof (struct in6_addr); j++)
        {
            NP_ASSERT_EQUAL (mapping->internal_ip.s6_addr[j], internal_ip.s6_addr[j]);
            NP_ASSERT_EQUAL (mapping->external_ip.s6_addr[j], external_ip.s6_addr[j]);
        }

        count ++;

        pcp_mapping_destroy (mapping);
    }

    g_list_free (mappings);

    NP_ASSERT_EQUAL (count, 3);
}

/* Test the remaining lifetime get function. Test may fail if time goes to the next
 * second in between the start_of_life assignment and remaining lifetime calculation. */
void
test_pcp_mapping_remaining_lifetime_get (void)
{
    pcp_mapping mapping;
    u_int32_t lifetime;
    u_int32_t time_alive;
    u_int32_t start_of_life;
    u_int32_t remaining_life;

    // Allocate some memory
    mapping = malloc (sizeof (*mapping));
    asprintf (&mapping->path, "/pcp/testpath/123");

    // Set lifetime variables
    lifetime = 4000;
    time_alive = 1000;
    start_of_life = time (NULL) - time_alive;
    mapping->lifetime = lifetime;
    mapping->start_of_life = start_of_life;

    // Calculate remaining lifetime and compare
    remaining_life = pcp_mapping_remaining_lifetime_get (mapping);
    NP_ASSERT_EQUAL (remaining_life, lifetime - time_alive);

    pcp_mapping_destroy (mapping);
}

int
tear_down (void)
{
    pcp_deinit_hard ();
    system ("pkill apteryxd");
    usleep (WAIT_TIME);
    return 0;
}
