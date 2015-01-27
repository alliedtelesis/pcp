#include <np.h> /* NovaProva library */
#include "../api/libpcp.h"
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>

/* Give apteryx time to start or close */
#define APTERYXD_WAIT_TIME 150 * 1000
/* Give apteryx time to set value and call callback function */
#define APTERYX_SET_WAIT_TIME 10 * 1000

/* Declare apteryx watch callback functions for testing */
bool pcp_config_changed (const char *path, void *priv, const unsigned char *value, size_t len);
bool pcp_mapping_changed (const char *path, void *priv, const unsigned char *value, size_t len);

/* Global struct to contain flags whether callbacks were successfully called or not */
struct pcp_callback_flags
{
    bool pcp_enabled;
    bool map_support;
    bool peer_support;
    bool third_party_support;
    bool proxy_support;
    bool upnp_igd_pcp_iwf_support;
    u_int32_t min_mapping_lifetime;
    u_int32_t max_mapping_lifetime;
    u_int32_t prefer_failure_req_rate_limit;
    int new_pcp_mapping;        // Number of times new mapping is called
    int delete_pcp_mapping;     // Number of times delete mapping is called
    int mapping_count;          // Count of current mappings
};

struct pcp_callback_flags cb_flags = { 0 };

int
set_up (void)
{
    system ("apteryxd -b");
    usleep (APTERYXD_WAIT_TIME);
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
 * second in between the end_of_life assignment and remaining lifetime calculation. */
void
test_pcp_mapping_remaining_lifetime_get (void)
{
    pcp_mapping mapping;
    u_int32_t lifetime;
    u_int32_t time_alive;
    u_int32_t end_of_life;
    u_int32_t remaining_life;

    // Allocate some memory
    mapping = malloc (sizeof (*mapping));
    asprintf (&mapping->path, "/pcp/testpath/123");

    // Set lifetime variables
    lifetime = 4000;
    time_alive = 1000;
    end_of_life = time (NULL) + lifetime - time_alive;

    mapping->lifetime = lifetime;
    mapping->end_of_life = end_of_life;

    // Calculate remaining lifetime and compare
    remaining_life = pcp_mapping_remaining_lifetime_get (mapping);
    NP_ASSERT_EQUAL (remaining_life, lifetime - time_alive);

    pcp_mapping_destroy (mapping);
}

/* Test the path processing in the pcp_config_changed function works correctly */
void
test_pcp_config_changed_valid_path (void)
{
    // Test valid keys
    NP_ASSERT_TRUE (pcp_config_changed ("/pcp/config/pcp_initialized", NULL, NULL, 0));
    NP_ASSERT_TRUE (pcp_config_changed ("/pcp/config/pcp_enabled", NULL, NULL, 0));
    NP_ASSERT_TRUE (pcp_config_changed ("/pcp/config/map_support", NULL, NULL, 0));
    NP_ASSERT_TRUE (pcp_config_changed ("/pcp/config/peer_support", NULL, NULL, 0));
    NP_ASSERT_TRUE (pcp_config_changed ("/pcp/config/third_party_support", NULL, NULL, 0));
    NP_ASSERT_TRUE (pcp_config_changed ("/pcp/config/proxy_support", NULL, NULL, 0));
    NP_ASSERT_TRUE (pcp_config_changed ("/pcp/config/upnp_igd_pcp_iwf_support", NULL, NULL, 0));
    NP_ASSERT_TRUE (pcp_config_changed ("/pcp/config/min_mapping_lifetime", NULL, NULL, 0));
    NP_ASSERT_TRUE (pcp_config_changed ("/pcp/config/max_mapping_lifetime", NULL, NULL, 0));
    NP_ASSERT_TRUE (pcp_config_changed ("/pcp/config/prefer_failure_req_rate_limit", NULL, NULL, 0));
}

void
test_pcp_config_changed_invalid_path (void)
{
    // Test invalid keys
    NP_ASSERT_FALSE (pcp_config_changed ("/pcp/config/notakey", NULL, NULL, 0));
    NP_ASSERT_FALSE (pcp_config_changed ("/pcp/config/p", NULL, NULL, 0));

    // Test no keys
    NP_ASSERT_FALSE (pcp_config_changed ("/pcp/config/", NULL, NULL, 0));
    NP_ASSERT_FALSE (pcp_config_changed ("/pcp/config", NULL, NULL, 0));

    // Test invalid paths
    NP_ASSERT_FALSE (pcp_config_changed ("/pcp/confi", NULL, NULL, 0));
    NP_ASSERT_FALSE (pcp_config_changed ("/pcp/", NULL, NULL, 0));
    NP_ASSERT_FALSE (pcp_config_changed ("/pcp", NULL, NULL, 0));
    NP_ASSERT_FALSE (pcp_config_changed ("/cpc", NULL, NULL, 0));
    NP_ASSERT_FALSE (pcp_config_changed ("/", NULL, NULL, 0));
    NP_ASSERT_FALSE (pcp_config_changed ("", NULL, NULL, 0));
    NP_ASSERT_FALSE (pcp_config_changed ("abcdefg", NULL, NULL, 0));
    NP_ASSERT_FALSE (pcp_config_changed (NULL, NULL, NULL, 0));
}

/* Test the path processing in the pcp_mapping_changed function works correctly */
void
test_pcp_mapping_changed_valid_path (void)
{
    // Test valid paths with integer keys
    NP_ASSERT_TRUE (pcp_mapping_changed ("/pcp/mappings/1", NULL, NULL, 0));
    NP_ASSERT_TRUE (pcp_mapping_changed ("/pcp/mappings/1/", NULL, NULL, 0));
    NP_ASSERT_TRUE (pcp_mapping_changed ("/pcp/mappings/32767", NULL, NULL, 0));
    NP_ASSERT_TRUE (pcp_mapping_changed ("/pcp/mappings/32767/", NULL, NULL, 0));
}

void
test_pcp_mapping_changed_invalid_path (void)
{
    // Test non-integer keys
    NP_ASSERT_FALSE (pcp_mapping_changed ("/pcp/mappings/test", NULL, NULL, 0));
    NP_ASSERT_FALSE (pcp_mapping_changed ("/pcp/mappings/a", NULL, NULL, 0));

    // Test no keys
    NP_ASSERT_FALSE (pcp_mapping_changed ("/pcp/mappings/", NULL, NULL, 0));
    NP_ASSERT_FALSE (pcp_mapping_changed ("/pcp/mappings", NULL, NULL, 0));

    // Test invalid paths
    NP_ASSERT_FALSE (pcp_mapping_changed ("/pcp/mapping", NULL, NULL, 0));
    NP_ASSERT_FALSE (pcp_mapping_changed ("/pcp/", NULL, NULL, 0));
    NP_ASSERT_FALSE (pcp_mapping_changed ("/pcp", NULL, NULL, 0));
    NP_ASSERT_FALSE (pcp_mapping_changed ("/cpc", NULL, NULL, 0));
    NP_ASSERT_FALSE (pcp_mapping_changed ("/", NULL, NULL, 0));
    NP_ASSERT_FALSE (pcp_mapping_changed ("", NULL, NULL, 0));
    NP_ASSERT_FALSE (pcp_mapping_changed ("abcdefg", NULL, NULL, 0));
    NP_ASSERT_FALSE (pcp_mapping_changed (NULL, NULL, NULL, 0));
}

/* Test callback functions */
void
pcp_enabled (bool enabled)
{
    cb_flags.pcp_enabled = enabled;
}

void
map_support (bool enabled)
{
    cb_flags.map_support = enabled;
}

void
peer_support (bool enabled)
{
    cb_flags.peer_support = enabled;
}

void
third_party_support (bool enabled)
{
    cb_flags.third_party_support = enabled;
}

void
proxy_support (bool enabled)
{
    cb_flags.proxy_support = enabled;
}

void
upnp_igd_pcp_iwf_support (bool enabled)
{
    cb_flags.upnp_igd_pcp_iwf_support = enabled;
}

void
min_mapping_lifetime (u_int32_t lifetime)
{
    cb_flags.min_mapping_lifetime = lifetime;
}

void
max_mapping_lifetime (u_int32_t lifetime)
{
    cb_flags.max_mapping_lifetime = lifetime;
}

void
prefer_failure_req_rate_limit (u_int32_t rate)
{
    cb_flags.prefer_failure_req_rate_limit = rate;
}

void
new_pcp_mapping (int index,
                 u_int32_t mapping_nonce[MAPPING_NONCE_SIZE],
                 struct in6_addr internal_ip,
                 u_int16_t internal_port,
                 struct in6_addr external_ip,
                 u_int16_t external_port,
                 u_int32_t lifetime,
                 u_int32_t start_of_life,
                 u_int32_t end_of_life,
                 u_int8_t opcode,
                 u_int8_t protocol)
{
    cb_flags.new_pcp_mapping++;
    cb_flags.mapping_count++;
}

void
delete_pcp_mapping (int index)
{
    cb_flags.delete_pcp_mapping++;
    cb_flags.mapping_count--;
}

/* A struct that contains function pointers for handling each of the possible callbacks */
pcp_callbacks callbacks = {
    .pcp_enabled = pcp_enabled,
    .map_support = map_support,
    .peer_support = peer_support,
    .third_party_support = third_party_support,
    .proxy_support = proxy_support,
    .upnp_igd_pcp_iwf_support = upnp_igd_pcp_iwf_support,
    .min_mapping_lifetime = min_mapping_lifetime,
    .max_mapping_lifetime = max_mapping_lifetime,
    .prefer_failure_req_rate_limit = prefer_failure_req_rate_limit,
    .new_pcp_mapping = new_pcp_mapping,
    .delete_pcp_mapping = delete_pcp_mapping,
};

/* Test the pcp config callbacks. Note that the memory leaks caused by apteryx_watch
 * when creating pthreads are false alarms and are not an issue. */
void
test_pcp_config_changed_callback (void)
{
    NP_ASSERT_TRUE (pcp_register_cb (&callbacks));

    NP_ASSERT_TRUE (pcp_enabled_set (true));
    usleep (APTERYX_SET_WAIT_TIME);
    NP_ASSERT_TRUE (cb_flags.pcp_enabled);

    NP_ASSERT_TRUE (map_support_set (true));
    usleep (APTERYX_SET_WAIT_TIME);
    NP_ASSERT_TRUE (cb_flags.map_support);

    NP_ASSERT_TRUE (peer_support_set (true));
    usleep (APTERYX_SET_WAIT_TIME);
    NP_ASSERT_TRUE (cb_flags.peer_support);

    NP_ASSERT_TRUE (third_party_support_set (true));
    usleep (APTERYX_SET_WAIT_TIME);
    NP_ASSERT_TRUE (cb_flags.third_party_support);

    NP_ASSERT_TRUE (proxy_support_set (true));
    usleep (APTERYX_SET_WAIT_TIME);
    NP_ASSERT_TRUE (cb_flags.proxy_support);

    NP_ASSERT_TRUE (upnp_igd_pcp_iwf_support_set (true));
    usleep (APTERYX_SET_WAIT_TIME);
    NP_ASSERT_TRUE (cb_flags.upnp_igd_pcp_iwf_support);

    NP_ASSERT_TRUE (min_mapping_lifetime_set (500));
    usleep (APTERYX_SET_WAIT_TIME);
    NP_ASSERT_EQUAL (cb_flags.min_mapping_lifetime, 500);

    NP_ASSERT_TRUE (max_mapping_lifetime_set (600));
    usleep (APTERYX_SET_WAIT_TIME);
    NP_ASSERT_EQUAL (cb_flags.max_mapping_lifetime, 600);

    NP_ASSERT_TRUE (prefer_failure_req_rate_limit_set (400));
    usleep (APTERYX_SET_WAIT_TIME);
    NP_ASSERT_EQUAL (cb_flags.prefer_failure_req_rate_limit, 400);
}

static void
compare_mapping_counts (void)
{
    GList *apteryx_mappings = pcp_mapping_getall ();
    int apteryx_mapping_count = (int) g_list_length (apteryx_mappings);

    NP_ASSERT_EQUAL (cb_flags.mapping_count, apteryx_mapping_count);

    g_list_free_full (apteryx_mappings, (GDestroyNotify) pcp_mapping_destroy);
}

/* Test the pcp mapping callbacks. Note that the memory leaks caused by apteryx_watch
 * when creating pthreads are false alarms and are not an issue. */
void
test_pcp_mapping_changed_callback (void)
{
    NP_ASSERT_TRUE (pcp_register_cb (&callbacks));

    NP_ASSERT_EQUAL (cb_flags.new_pcp_mapping, 0);
    NP_ASSERT_EQUAL (cb_flags.delete_pcp_mapping, 0);
    NP_ASSERT_EQUAL (cb_flags.mapping_count, 0);
    compare_mapping_counts ();

    u_int32_t mapping_nonce[MAPPING_NONCE_SIZE] = { 0 };
    struct in6_addr internal_ip = {{{ 0 }}};
    struct in6_addr external_ip = {{{ 0 }}};

    NP_ASSERT_TRUE (pcp_mapping_add (50, mapping_nonce, &internal_ip, 0,
                                     &external_ip, 0, 0, 0, 0));
    usleep (APTERYX_SET_WAIT_TIME);
    NP_ASSERT_EQUAL (cb_flags.new_pcp_mapping, 1);
    NP_ASSERT_EQUAL (cb_flags.mapping_count, 1);
    compare_mapping_counts ();

    NP_ASSERT_TRUE (pcp_mapping_add (100, mapping_nonce, &internal_ip, 0,
                                     &external_ip, 0, 0, 0, 0));
    usleep (APTERYX_SET_WAIT_TIME);
    NP_ASSERT_EQUAL (cb_flags.new_pcp_mapping, 2);
    NP_ASSERT_EQUAL (cb_flags.mapping_count, 2);
    compare_mapping_counts ();

    NP_ASSERT_TRUE (pcp_mapping_add (150, mapping_nonce, &internal_ip, 0,
                                     &external_ip, 0, 0, 0, 0));
    usleep (APTERYX_SET_WAIT_TIME);
    NP_ASSERT_EQUAL (cb_flags.new_pcp_mapping, 3);
    NP_ASSERT_EQUAL (cb_flags.mapping_count, 3);
    compare_mapping_counts ();

    NP_ASSERT_TRUE (pcp_mapping_delete (100));
    usleep (APTERYX_SET_WAIT_TIME);
    NP_ASSERT_EQUAL (cb_flags.delete_pcp_mapping, 1);
    NP_ASSERT_EQUAL (cb_flags.mapping_count, 2);
    compare_mapping_counts ();

    NP_ASSERT_TRUE (pcp_mapping_add (200, mapping_nonce, &internal_ip, 0,
                                     &external_ip, 0, 0, 0, 0));
    usleep (APTERYX_SET_WAIT_TIME);
    NP_ASSERT_EQUAL (cb_flags.new_pcp_mapping, 4);
    NP_ASSERT_EQUAL (cb_flags.mapping_count, 3);
    compare_mapping_counts ();

    NP_ASSERT_TRUE (pcp_mapping_delete (50));
    usleep (APTERYX_SET_WAIT_TIME);
    NP_ASSERT_EQUAL (cb_flags.delete_pcp_mapping, 2);
    NP_ASSERT_EQUAL (cb_flags.mapping_count, 2);
    compare_mapping_counts ();
}

/* Test the pcp mapping callbacks when adding multiple mappings of the same index. */
void
test_pcp_mapping_changed_callback_add_duplicate (void)
{
    NP_ASSERT_TRUE (pcp_register_cb (&callbacks));

    NP_ASSERT_EQUAL (cb_flags.new_pcp_mapping, 0);
    NP_ASSERT_EQUAL (cb_flags.delete_pcp_mapping, 0);
    NP_ASSERT_EQUAL (cb_flags.mapping_count, 0);
    compare_mapping_counts ();

    u_int32_t mapping_nonce[MAPPING_NONCE_SIZE] = { 0 };
    struct in6_addr internal_ip = {{{ 0 }}};
    struct in6_addr external_ip = {{{ 0 }}};

    NP_ASSERT_TRUE (pcp_mapping_add (50, mapping_nonce, &internal_ip, 0,
                                     &external_ip, 0, 0, 0, 0));
    usleep (APTERYX_SET_WAIT_TIME);
    NP_ASSERT_EQUAL (cb_flags.new_pcp_mapping, 1);
    NP_ASSERT_EQUAL (cb_flags.mapping_count, 1);
    compare_mapping_counts ();

    NP_ASSERT_FALSE (pcp_mapping_add (50, mapping_nonce, &internal_ip, 0,
                                     &external_ip, 0, 0, 0, 0));
    usleep (APTERYX_SET_WAIT_TIME);
    NP_ASSERT_EQUAL (cb_flags.new_pcp_mapping, 1);
    NP_ASSERT_EQUAL (cb_flags.mapping_count, 1);
    compare_mapping_counts ();

    NP_ASSERT_FALSE (pcp_mapping_add (50, mapping_nonce, &internal_ip, 0,
                                     &external_ip, 0, 0, 0, 0));
    usleep (APTERYX_SET_WAIT_TIME);
    NP_ASSERT_EQUAL (cb_flags.new_pcp_mapping, 1);
    NP_ASSERT_EQUAL (cb_flags.mapping_count, 1);
    compare_mapping_counts ();

    NP_ASSERT_TRUE (pcp_mapping_delete (50));
    usleep (APTERYX_SET_WAIT_TIME);
    NP_ASSERT_EQUAL (cb_flags.delete_pcp_mapping, 1);
    NP_ASSERT_EQUAL (cb_flags.mapping_count, 0);
    compare_mapping_counts ();
}

/* Test the pcp mapping callbacks when deleting a mapping of the same index
 * multiple times. */
void
test_pcp_mapping_changed_callback_delete_duplicate (void)
{
    NP_ASSERT_TRUE (pcp_register_cb (&callbacks));

    NP_ASSERT_EQUAL (cb_flags.new_pcp_mapping, 0);
    NP_ASSERT_EQUAL (cb_flags.delete_pcp_mapping, 0);
    NP_ASSERT_EQUAL (cb_flags.mapping_count, 0);
    compare_mapping_counts ();

    u_int32_t mapping_nonce[MAPPING_NONCE_SIZE] = { 0 };
    struct in6_addr internal_ip = {{{ 0 }}};
    struct in6_addr external_ip = {{{ 0 }}};

    NP_ASSERT_TRUE (pcp_mapping_add (100, mapping_nonce, &internal_ip, 0,
                                     &external_ip, 0, 0, 0, 0));
    usleep (APTERYX_SET_WAIT_TIME);
    NP_ASSERT_EQUAL (cb_flags.new_pcp_mapping, 1);
    NP_ASSERT_EQUAL (cb_flags.mapping_count, 1);
    compare_mapping_counts ();

    NP_ASSERT_TRUE (pcp_mapping_delete (100));
    usleep (APTERYX_SET_WAIT_TIME);
    NP_ASSERT_EQUAL (cb_flags.delete_pcp_mapping, 1);
    NP_ASSERT_EQUAL (cb_flags.mapping_count, 0);
    compare_mapping_counts ();

    NP_ASSERT_FALSE (pcp_mapping_delete (100));
    usleep (APTERYX_SET_WAIT_TIME);
    NP_ASSERT_EQUAL (cb_flags.delete_pcp_mapping, 1);
    NP_ASSERT_EQUAL (cb_flags.mapping_count, 0);
    compare_mapping_counts ();

    NP_ASSERT_FALSE (pcp_mapping_delete (100));
    usleep (APTERYX_SET_WAIT_TIME);
    NP_ASSERT_EQUAL (cb_flags.delete_pcp_mapping, 1);
    NP_ASSERT_EQUAL (cb_flags.mapping_count, 0);
    compare_mapping_counts ();
}

int
tear_down (void)
{
    pcp_register_cb (NULL);
    pcp_deinit_hard ();
    system ("pkill apteryxd");
    usleep (APTERYXD_WAIT_TIME);
    return 0;
}
