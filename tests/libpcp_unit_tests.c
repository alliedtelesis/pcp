#include <np.h> /* NovaProva library */
#include "../api/libpcp.h"
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>

/* Give apteryx 1/10th of a second to start or close */
#define WAIT_TIME 100 * 1000

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

void
test_pcp_load_config (void)
{
    /* PCP config will have not been initialized so this will load the default config.
     * This simultaneously tests the config_set_default function. */
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

void
test_pcp_mapping_add (void)
{
    int index = 254;
    u_int32_t mapping_nonce[MAPPING_NONCE_SIZE] = {1732282673, 1882683910, 2109096625};
    struct in6_addr internal_ip;
    u_int16_t internal_port = 1234;
    struct in6_addr external_ip;
    u_int16_t external_port = 9876;
    u_int32_t lifetime = 8002;
    u_int8_t opcode = MAP_OPCODE;
    u_int8_t protocol = 6;
    int i;

    inet_pton (AF_INET6, "2001:db8:7654:3210:fedc:ba98:7654:3210", &(internal_ip));
    inet_pton (AF_INET6, "2001:db8:7654:1234:fedc:abab:4554:9875", &(external_ip));

    NP_ASSERT_TRUE (pcp_mapping_add (index, mapping_nonce, &internal_ip,
                                     internal_port, &external_ip, external_port,
                                     lifetime, opcode, protocol));

    pcp_mapping mapping = pcp_mapping_find (index);

    NP_ASSERT_TRUE (mapping != NULL);

    NP_ASSERT_EQUAL (mapping->index, index);
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

int
tear_down (void)
{
    pcp_deinit_hard ();
    system ("pkill apteryxd");
    usleep (WAIT_TIME);
    return 0;
}
