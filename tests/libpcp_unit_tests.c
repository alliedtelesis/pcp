#include <np.h> /* NovaProva library */
#include "../api/libpcp.h"
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

int
set_up (void)
{
    system ("apteryxd -b");
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
    NP_ASSERT_TRUE (max_mapping_lifetime_set (1234567890));
    NP_ASSERT_EQUAL (max_mapping_lifetime_get (), 1234567890);

    NP_ASSERT_TRUE (max_mapping_lifetime_set (DEFAULT_MAX_MAPPING_LIFETIME));
    NP_ASSERT_EQUAL (max_mapping_lifetime_get (), DEFAULT_MAX_MAPPING_LIFETIME);
}

void
test_prefer_failure_req_rate_limit_set_get (void)
{
    NP_ASSERT_TRUE (prefer_failure_req_rate_limit_set (1234567890));
    NP_ASSERT_EQUAL (prefer_failure_req_rate_limit_get (), 1234567890);

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

int
tear_down (void)
{
    pcp_deinit_hard ();
    system ("pkill apteryxd");
    return 0;
}
