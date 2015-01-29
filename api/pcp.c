/**
 * @file pcp.c
 *
 * Implementation of pcpd API
 *
 * Copyright 2015 Allied Telesis Labs, New Zealand
 *
 */


#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <apteryx.h>

#include "libpcp.h"


#ifndef MAXIMUM_MAPPING_ID
#define MAXIMUM_MAPPING_ID INT_MAX
#endif

/* ctime strings are exactly 26 characters with the format
 * "%.3s %.3s%3d %.2d:%.2d:%.2d %d\n" */
#define CTIME_BUF_SIZE 32

#define ROOT_PATH "/pcp"

/* mapping keys */
#define MAPPING_PATH ROOT_PATH "/mappings"
#define INDEX_KEY "index"
#define MAPPING_NONCE_1_KEY "mapping_nonce_1"
#define MAPPING_NONCE_2_KEY "mapping_nonce_2"
#define MAPPING_NONCE_3_KEY "mapping_nonce_3"
#define INTERNAL_IP_KEY "internal_ip"
#define INTERNAL_PORT_KEY "internal_port"
#define EXTERNAL_IP_KEY "external_ip"
#define EXTERNAL_PORT_KEY "external_port"
#define LIFETIME_KEY "lifetime"
#define START_OF_LIFE_KEY "start_of_life"
#define END_OF_LIFE_KEY "end_of_life"
#define OPCODE_KEY "opcode"
#define PROTOCOL_KEY "protocol"

/* config keys */
#define CONFIG_PATH ROOT_PATH "/config"
#define PCP_INITIALIZED_KEY "pcp_initialized"
#define PCP_ENABLED_KEY "pcp_enabled"
#define MAP_SUPPORT_KEY "map_support"
#define PEER_SUPPORT_KEY "peer_support"
#define THIRD_PARTY_SUPPORT_KEY "third_party_support"
#define PROXY_SUPPORT_KEY "proxy_support"
#define UPNP_IGD_PCP_IWF_SUPPORT_KEY "upnp_igd_pcp_iwf_support"
#define MIN_MAPPING_LIFETIME_KEY "min_mapping_lifetime"
#define MAX_MAPPING_LIFETIME_KEY "max_mapping_lifetime"
#define PREFER_FAILURE_REQ_RATE_LIMIT_KEY "prefer_failure_req_rate_limit"

static pcp_callbacks *saved_cbs = NULL;
static pthread_mutex_t callback_lock = PTHREAD_MUTEX_INITIALIZER;

void
pcp_init (void)
{
    apteryx_init (false);
    apteryx_set_string (ROOT_PATH, NULL, "-");
    apteryx_set_string (CONFIG_PATH, NULL, "-");
    apteryx_set_string (MAPPING_PATH, NULL, "-");
}

void
pcp_deinit (void)
{
    pcp_mapping_deleteall ();
    apteryx_shutdown ();
}

void
pcp_deinit_hard (void)
{
    apteryx_prune (ROOT_PATH);
    apteryx_shutdown ();
}

bool
apteryx_set_ipv6_addr (const char *path, const char *key, struct in6_addr value)
{
    char *full_path;
    size_t len;
    bool res = false;

    /* Create full path */
    if (key)
        len = asprintf (&full_path, "%s/%s", path, key);
    else
        len = asprintf (&full_path, "%s", path);
    if (len)
    {
        res = apteryx_set (full_path, value.s6_addr, sizeof (struct in6_addr));
        free (full_path);
    }
    return res;
}

struct in6_addr
apteryx_get_ipv6_addr (const char *path, const char *key)
{
    char *full_path;
    size_t len;
    unsigned char *v = NULL;
    struct in6_addr value;

    /* Create full path */
    if (key)
        len = asprintf (&full_path, "%s/%s", path, key);
    else
        len = asprintf (&full_path, "%s", path);
    if (len)
    {
        if (apteryx_get (full_path, &v, &len) && v)
        {
            memcpy (value.s6_addr, v, sizeof (struct in6_addr));
            free (v);
        }
        free (full_path);
    }
    return value;
}

static int
current_highest_index (const char *path)
{
    GList *query_head = apteryx_search (path);
    GList *query;
    int max = 0;
    int index_id;

    for (query = query_head; query; query = g_list_next (query))
    {
        if (query->data)
        {
            index_id = apteryx_get_int (query->data, INDEX_KEY);
            if (index_id > max)
            {
                max = index_id;
            }
        }
    }
    g_list_free_full (query_head, free);

    return max;
}

static int
next_highest_id (const char *path)
{
    int index = -1;
    int max_index = current_highest_index (path);
    max_index += 11;
    index = (max_index) - (max_index % 10);
    if (index > MAXIMUM_MAPPING_ID)
    {
        return -1;
    }
    return index;
}

bool // TODO: Decide if bool or enum of error types
pcp_mapping_add (int index,
                 u_int32_t mapping_nonce[MAPPING_NONCE_SIZE],
                 struct in6_addr *internal_ip,
                 u_int16_t internal_port,
                 struct in6_addr *external_ip,
                 u_int16_t external_port,
                 u_int32_t lifetime,
                 u_int8_t opcode,
                 u_int8_t protocol)
{
    char *path = NULL;

    /* TODO: Verify valid, maybe check if mapping already exists */

    if (index == -1)
    {
        index = next_highest_id (MAPPING_PATH "/");
        if (index < 0)
        {
            return false;   // Invalid index
        }
    }


    /* Make sure the specified mapping index is not in use */
    pcp_mapping mapping = pcp_mapping_find (index);
    if (mapping)
    {
        /* already exists */
        pcp_mapping_destroy (mapping);
        return false;
    }


    if (asprintf (&path, MAPPING_PATH "/%d", index) == 0)
    {
        return false;       // Out of memory
    }

    apteryx_set_int (path, INDEX_KEY, index);
    apteryx_set_int (path, MAPPING_NONCE_1_KEY, mapping_nonce[0]);
    apteryx_set_int (path, MAPPING_NONCE_2_KEY, mapping_nonce[1]);
    apteryx_set_int (path, MAPPING_NONCE_3_KEY, mapping_nonce[2]);
    apteryx_set_ipv6_addr (path, INTERNAL_IP_KEY, *internal_ip);
    apteryx_set_int (path, INTERNAL_PORT_KEY, internal_port);
    apteryx_set_ipv6_addr (path, EXTERNAL_IP_KEY, *external_ip);
    apteryx_set_int (path, EXTERNAL_PORT_KEY, external_port);
    apteryx_set_int (path, LIFETIME_KEY, lifetime);
    apteryx_set_int (path, START_OF_LIFE_KEY, time (NULL));
    apteryx_set_int (path, END_OF_LIFE_KEY, time (NULL) + lifetime);
    apteryx_set_int (path, OPCODE_KEY, opcode);
    apteryx_set_int (path, PROTOCOL_KEY, protocol);
    apteryx_set_string (path, NULL, "-");

    free (path);

    return true;            // Success
}

bool
pcp_mapping_refresh_lifetime (int index, u_int32_t new_lifetime, u_int32_t new_end_of_life)
{
    char *path = NULL;
    bool ret;

    /* Make sure the mapping exists */
    pcp_mapping mapping = pcp_mapping_find (index);
    if (!mapping)
    {
        return false;
    }
    pcp_mapping_destroy (mapping);

    if (asprintf (&path, MAPPING_PATH "/%d", index) == 0)
    {
        return false;       // Out of memory
    }

    ret = apteryx_set_int (path, LIFETIME_KEY, new_lifetime);
    ret = apteryx_set_int (path, END_OF_LIFE_KEY, new_end_of_life);
    free (path);
    return ret;
}

bool
pcp_mapping_delete (int index)
{
    char *tmp;
    pcp_mapping mapping;

    /* Make sure the specified mapping index exists */
    mapping = pcp_mapping_find (index);
    if (!mapping)
        return false;

    pcp_mapping_destroy (mapping);

    if (asprintf (&tmp, MAPPING_PATH "/%d", index) > 0)
    {
        apteryx_prune (tmp);
        free (tmp);
        return true;
    }
    return false;
}

bool
pcp_mapping_deleteall (void)
{
    bool status = apteryx_prune (MAPPING_PATH);
    apteryx_set_string (MAPPING_PATH, NULL, "-");
    return status;
}

pcp_mapping
pcp_mapping_find (int mapping_id)
{
    char *tmp;
    pcp_mapping mapping;
    mapping = malloc (sizeof (*mapping));

    if (asprintf (&mapping->path, MAPPING_PATH "/%d", mapping_id) == 0 ||
        (tmp = apteryx_get_string (mapping->path, NULL)) == NULL)
    {
        pcp_mapping_destroy (mapping);
        return NULL;
    }
    free (tmp);

    mapping->index = mapping_id;
    mapping->mapping_nonce[0] = apteryx_get_int (mapping->path, MAPPING_NONCE_1_KEY);
    mapping->mapping_nonce[1] = apteryx_get_int (mapping->path, MAPPING_NONCE_2_KEY);
    mapping->mapping_nonce[2] = apteryx_get_int (mapping->path, MAPPING_NONCE_3_KEY);
    mapping->internal_ip = apteryx_get_ipv6_addr (mapping->path, INTERNAL_IP_KEY);
    mapping->internal_port = apteryx_get_int (mapping->path, INTERNAL_PORT_KEY);
    mapping->external_ip = apteryx_get_ipv6_addr (mapping->path, EXTERNAL_IP_KEY);
    mapping->external_port = apteryx_get_int (mapping->path, EXTERNAL_PORT_KEY);
    mapping->lifetime = apteryx_get_int (mapping->path, LIFETIME_KEY);
    mapping->start_of_life = apteryx_get_int (mapping->path, START_OF_LIFE_KEY);
    mapping->end_of_life = apteryx_get_int (mapping->path, END_OF_LIFE_KEY);
    mapping->opcode = apteryx_get_int (mapping->path, OPCODE_KEY);
    mapping->protocol = apteryx_get_int (mapping->path, PROTOCOL_KEY);

    return mapping;
}

static int
mapping_index_cmp (gconstpointer _a, gconstpointer _b)
{
    return ((pcp_mapping) _a)->index - ((pcp_mapping) _b)->index;
}

GList *
pcp_mapping_getall (void)
{
    GList *mappings = NULL;
    GList *paths = apteryx_search (MAPPING_PATH "/");
    GList *iter;
    for (iter = paths; iter; iter = g_list_next (iter))
    {
        pcp_mapping mapping;
        int id;
        char *tmp = strrchr ((char *) iter->data, '/');
        if (!tmp)
            continue;
        /* read the ID */
        id = atoi (++tmp);
        mapping = pcp_mapping_find (id);
        if (mapping)
            mappings = g_list_insert_sorted (mappings, mapping, mapping_index_cmp);
    }
    g_list_free_full (paths, free);
    return mappings;
}

u_int32_t
pcp_mapping_remaining_lifetime_get (pcp_mapping mapping)
{
    u_int32_t now = time (NULL);
    if (!mapping || mapping->end_of_life <= now)
    {
        return 0;
    }
    return mapping->end_of_life - now;
}

void
pcp_mapping_destroy (pcp_mapping mapping)
{
    if (mapping != NULL)
    {
        if (mapping->path != NULL)
        {
            free (mapping->path);
        }
        free (mapping);
    }
}

bool
pcp_load_config (void)
{
    if (pcp_initialized_get ())
    {
        pthread_mutex_lock (&callback_lock);

        if (saved_cbs->pcp_enabled)
        {
            saved_cbs->pcp_enabled (pcp_enabled_get ());
        }
        if (saved_cbs->map_support)
        {
            saved_cbs->map_support (map_support_get ());
        }
        if (saved_cbs->peer_support)
        {
            saved_cbs->peer_support (peer_support_get ());
        }
        if (saved_cbs->third_party_support)
        {
            saved_cbs->third_party_support (third_party_support_get ());
        }
        if (saved_cbs->proxy_support)
        {
            saved_cbs->proxy_support (proxy_support_get ());
        }
        if (saved_cbs->upnp_igd_pcp_iwf_support)
        {
            saved_cbs->upnp_igd_pcp_iwf_support (upnp_igd_pcp_iwf_support_get ());
        }
        if (saved_cbs->min_mapping_lifetime)
        {
            saved_cbs->min_mapping_lifetime (min_mapping_lifetime_get ());
        }
        if (saved_cbs->max_mapping_lifetime)
        {
            saved_cbs->max_mapping_lifetime (max_mapping_lifetime_get ());
        }
        if (saved_cbs->prefer_failure_req_rate_limit)
        {
            saved_cbs->prefer_failure_req_rate_limit (prefer_failure_req_rate_limit_get ());
        }

        pthread_mutex_unlock (&callback_lock);

        return true;
    }
    else
    {
        return (pcp_initialized_set (true) &&
                pcp_enabled_set (true) &&
                config_set_default ());
    }
}

bool
pcp_initialized_set (bool enable)
{
    return apteryx_set_int (CONFIG_PATH, PCP_INITIALIZED_KEY, enable);
}

bool
pcp_initialized_get (void)
{
    return (apteryx_get_int (CONFIG_PATH, PCP_INITIALIZED_KEY) == 1);
}

bool
pcp_enabled_set (bool enable)
{
    return apteryx_set_int (CONFIG_PATH, PCP_ENABLED_KEY, enable);
}

bool
pcp_enabled_get (void)
{
    return (apteryx_get_int (CONFIG_PATH, PCP_ENABLED_KEY) == 1);
}

bool
map_support_set (bool enable)
{
    return apteryx_set_int (CONFIG_PATH, MAP_SUPPORT_KEY, enable);
}

bool
map_support_get (void)
{
    return (apteryx_get_int (CONFIG_PATH, MAP_SUPPORT_KEY) == 1);
}

bool
peer_support_set (bool enable)
{
    return apteryx_set_int (CONFIG_PATH, PEER_SUPPORT_KEY, enable);
}

bool
peer_support_get (void)
{
    return (apteryx_get_int (CONFIG_PATH, PEER_SUPPORT_KEY) == 1);
}

bool
third_party_support_set (bool enable)
{
    return apteryx_set_int (CONFIG_PATH, THIRD_PARTY_SUPPORT_KEY, enable);
}

bool
third_party_support_get (void)
{
    return (apteryx_get_int (CONFIG_PATH, THIRD_PARTY_SUPPORT_KEY) == 1);
}

bool
proxy_support_set (bool enable)
{
    return apteryx_set_int (CONFIG_PATH, PROXY_SUPPORT_KEY, enable);
}

bool
proxy_support_get (void)
{
    return (apteryx_get_int (CONFIG_PATH, PROXY_SUPPORT_KEY) == 1);
}

bool
upnp_igd_pcp_iwf_support_set (bool enable)
{
    return apteryx_set_int (CONFIG_PATH, UPNP_IGD_PCP_IWF_SUPPORT_KEY, enable);
}

bool
upnp_igd_pcp_iwf_support_get (void)
{
    return (apteryx_get_int (CONFIG_PATH, UPNP_IGD_PCP_IWF_SUPPORT_KEY) == 1);
}

bool
min_mapping_lifetime_set (u_int32_t lifetime)
{
    return apteryx_set_int (CONFIG_PATH, MIN_MAPPING_LIFETIME_KEY, lifetime);
}

u_int32_t
min_mapping_lifetime_get (void)
{
    return (u_int32_t) apteryx_get_int (CONFIG_PATH, MIN_MAPPING_LIFETIME_KEY);
}

bool
max_mapping_lifetime_set (u_int32_t lifetime)
{
    return apteryx_set_int (CONFIG_PATH, MAX_MAPPING_LIFETIME_KEY, lifetime);
}

u_int32_t
max_mapping_lifetime_get (void)
{
    return (u_int32_t) apteryx_get_int (CONFIG_PATH, MAX_MAPPING_LIFETIME_KEY);
}

bool
prefer_failure_req_rate_limit_set (u_int32_t rate)
{
    return apteryx_set_int (CONFIG_PATH, PREFER_FAILURE_REQ_RATE_LIMIT_KEY, rate);
}

u_int32_t
prefer_failure_req_rate_limit_get (void)
{
    return (u_int32_t) apteryx_get_int (CONFIG_PATH, PREFER_FAILURE_REQ_RATE_LIMIT_KEY);
}

/**
 * @brief config_set_default - Reset all settings to their default settings,
 *          except the enabled setting to avoid shutting down the server.
 */
bool
config_set_default (void)
{
    if (map_support_set (DEFAULT_MAP_SUPPORT) &&
        peer_support_set (DEFAULT_PEER_SUPPORT) &&
        third_party_support_set (DEFAULT_THIRD_PARTY_SUPPORT) &&
        proxy_support_set (DEFAULT_PROXY_SUPPORT) &&
        upnp_igd_pcp_iwf_support_set (DEFAULT_UPNP_IGD_PCP_IWF_SUPPORT) &&
        min_mapping_lifetime_set (DEFAULT_MIN_MAPPING_LIFETIME) &&
        max_mapping_lifetime_set (DEFAULT_MAX_MAPPING_LIFETIME) &&
        prefer_failure_req_rate_limit_set (DEFAULT_PREFER_FAILURE_REQ_RATE_LIMIT))
    {
        return true;
    }
    else
    {
        return false;
    }
}

/************************
 * Watches
 *************************/

bool
pcp_config_changed (const char *path, void *priv, const unsigned char *value,
                         size_t len)
{
    const char *key = NULL;

    /* check we are in the right place */
    if (!path || strncmp (path, CONFIG_PATH "/", strlen (CONFIG_PATH "/")) != 0)
        return false;

    key = path + strlen (CONFIG_PATH "/");

    pthread_mutex_lock (&callback_lock);

    if (strcmp (key, PCP_ENABLED_KEY) == 0)
    {
        if (saved_cbs && saved_cbs->pcp_enabled)
        {
            saved_cbs->pcp_enabled (pcp_enabled_get ());
        }
    }
    else if (strcmp (key, MAP_SUPPORT_KEY) == 0)
    {
        if (saved_cbs && saved_cbs->map_support)
        {
            saved_cbs->map_support (map_support_get ());
        }
    }
    else if (strcmp (key, PEER_SUPPORT_KEY) == 0)
    {
        if (saved_cbs && saved_cbs->peer_support)
        {
            saved_cbs->peer_support (peer_support_get ());
        }
    }
    else if (strcmp (key, THIRD_PARTY_SUPPORT_KEY) == 0)
    {
        if (saved_cbs && saved_cbs->third_party_support)
        {
            saved_cbs->third_party_support (third_party_support_get ());
        }
    }
    else if (strcmp (key, PROXY_SUPPORT_KEY) == 0)
    {
        if (saved_cbs && saved_cbs->proxy_support)
        {
            saved_cbs->proxy_support (proxy_support_get ());
        }
    }
    else if (strcmp (key, UPNP_IGD_PCP_IWF_SUPPORT_KEY) == 0)
    {
        if (saved_cbs && saved_cbs->upnp_igd_pcp_iwf_support)
        {
            saved_cbs->upnp_igd_pcp_iwf_support (upnp_igd_pcp_iwf_support_get ());
        }
    }
    else if (strcmp (key, MIN_MAPPING_LIFETIME_KEY) == 0)
    {
        if (saved_cbs && saved_cbs->min_mapping_lifetime)
        {
            saved_cbs->min_mapping_lifetime (min_mapping_lifetime_get ());
        }
    }
    else if (strcmp (key, MAX_MAPPING_LIFETIME_KEY) == 0)
    {
        if (saved_cbs && saved_cbs->max_mapping_lifetime)
        {
            saved_cbs->max_mapping_lifetime (max_mapping_lifetime_get ());
        }
    }
    else if (strcmp (key, PREFER_FAILURE_REQ_RATE_LIMIT_KEY) == 0)
    {
        if (saved_cbs && saved_cbs->prefer_failure_req_rate_limit)
        {
            saved_cbs->prefer_failure_req_rate_limit (prefer_failure_req_rate_limit_get ());
        }
    }
    else if (strcmp (key, PCP_INITIALIZED_KEY) != 0)
    {
        // key does not match any known keys
        pthread_mutex_unlock (&callback_lock);
        return false;
    }

    pthread_mutex_unlock (&callback_lock);

    puts ("config_changed");  // TODO: remove

    return true;
}

bool
pcp_mapping_changed (const char *path, void *priv, const unsigned char *value,
                   size_t len)
{
    char *tmp = NULL;
    int mapping_id = -1;
    pcp_mapping mapping;

    /* check we are in the right place */
    if (!path || strncmp (path, MAPPING_PATH "/", strlen (MAPPING_PATH "/")) != 0)
        return false;

    /* Parse the rule ID and key */
    tmp = strdup (path + strlen (MAPPING_PATH "/"));
    if (!tmp)
        return false;

    if (strchr (tmp, '/'))
    {
        *strrchr (tmp, '/') = '\0';
    }
    if (sscanf (tmp, "%d", &mapping_id) != 1)
    {
        free (tmp);
        return false;
    }
    mapping = pcp_mapping_find (mapping_id);
    pthread_mutex_lock (&callback_lock);
    if (!mapping)
    {
        if (saved_cbs && saved_cbs->delete_pcp_mapping)
        {
            saved_cbs->delete_pcp_mapping (mapping_id);
        }
    }
    else
    {
        if (saved_cbs && saved_cbs->new_pcp_mapping)
        {
            saved_cbs->new_pcp_mapping (mapping->index, mapping->mapping_nonce,
                                        mapping->internal_ip, mapping->internal_port,
                                        mapping->external_ip, mapping->external_port,
                                        mapping->lifetime, mapping->start_of_life,
                                        mapping->end_of_life, mapping->opcode,
                                        mapping->protocol);
        }
    }
    // TODO: extend lifetime

    if (mapping)
    {
        pcp_mapping_destroy (mapping);
    }

    pthread_mutex_unlock (&callback_lock);

    puts ("mapping_changed");  // TODO: remove

    free (tmp);
    return true;
}

bool
pcp_register_cb (pcp_callbacks *cb)
{
    pthread_mutex_lock (&callback_lock);
    saved_cbs = cb;
    pthread_mutex_unlock (&callback_lock);

    apteryx_watch (CONFIG_PATH "/*", cb ? pcp_config_changed : NULL, NULL);
    apteryx_watch (MAPPING_PATH "/", cb ? pcp_mapping_changed : NULL, NULL);

    return true;
}

// TODO: remove
void
print_pcp_apteryx_config (void)
{
    printf ("\npcp:\n");
    GList* paths = apteryx_search ("/pcp/");
    GList* _iter;
    for (_iter= paths; _iter; _iter = _iter->next)
    {
        char *path;

        path = (char *)_iter->data;
        printf ("  %s\n", strrchr (path, '/') + 1);

        if (strcmp (strrchr (path, '/') + 1, "config") == 0)
        {
            printf ("    %s     %d\n", PCP_ENABLED_KEY, pcp_enabled_get());
            printf ("    %s     %d\n", MAP_SUPPORT_KEY, map_support_get());
            printf ("    %s     %d\n", PEER_SUPPORT_KEY, peer_support_get());
            printf ("    %s     %d\n", THIRD_PARTY_SUPPORT_KEY, third_party_support_get());
            printf ("    %s     %d\n", PROXY_SUPPORT_KEY, proxy_support_get());
            printf ("    %s     %d\n", UPNP_IGD_PCP_IWF_SUPPORT_KEY, upnp_igd_pcp_iwf_support_get());
            printf ("    %s     %u\n", MIN_MAPPING_LIFETIME_KEY, min_mapping_lifetime_get());
            printf ("    %s     %u\n", MAX_MAPPING_LIFETIME_KEY, max_mapping_lifetime_get());
            printf ("    %s     %u\n", PREFER_FAILURE_REQ_RATE_LIMIT_KEY, prefer_failure_req_rate_limit_get());
        }
    }
    g_list_free_full (paths, free);
}

// TODO: Move out of watches section
void
pcp_mapping_print (pcp_mapping mapping)
{
    if (mapping)
    {
        char internal_ip_str[INET6_ADDRSTRLEN];
        char external_ip_str[INET6_ADDRSTRLEN];
        char start_of_life_str[CTIME_BUF_SIZE];
        char end_of_life_str[CTIME_BUF_SIZE];

        time_t start_of_life = (time_t) mapping->start_of_life;
        time_t end_of_life = (time_t) mapping->end_of_life;

        ctime_r (&start_of_life, start_of_life_str);
        ctime_r (&end_of_life, end_of_life_str);

        inet_ntop (AF_INET6, &(mapping->internal_ip.s6_addr), internal_ip_str, INET6_ADDRSTRLEN);
        inet_ntop (AF_INET6, &(mapping->external_ip.s6_addr), external_ip_str, INET6_ADDRSTRLEN);

        printf ("     %-21.20s: %d\n"
                "       %-19.18s: %10u %10u %10u\n"
                "       %-19.18s: [%s]:%u\n"
                "       %-19.18s: [%s]:%u\n"
                "       %-19.18s: %u\n"
                "       %-19.18s: %u\n"
                "       %-19.18s: %s"
                "       %-19.18s: %s"
                "       %-19.18s: %u\n"
                "         To remove later\n" // TODO: Remove later
                "         %-17.16s: %s\n"
                "         %-17.16s: %u\n"
                "         %-17.16s: %u\n\n",
                (mapping->opcode == MAP_OPCODE) ? "MAP mapping ID" : "PEER mapping ID",
                mapping->index,
                "Mapping nonce",
                mapping->mapping_nonce[0],
                mapping->mapping_nonce[1],
                mapping->mapping_nonce[2],
                "Internal IP & port",
                internal_ip_str,
                mapping->internal_port,
                "External IP & port",
                external_ip_str,
                mapping->external_port,
                "Lifetime",
                mapping->lifetime,
                "Lifetime remaining",
                pcp_mapping_remaining_lifetime_get (mapping),
                "First requested",
                start_of_life_str,
                "Expiry date/time",
                end_of_life_str,
                "Protocol",
                mapping->protocol,
                "Path",  // TODO: Remove later
                mapping->path,
                "Start of life",
                mapping->start_of_life,
                "End of life",
                mapping->end_of_life);
    }
    else
    {
        puts ("null");
    }
}

void
pcp_mapping_printall (GList *mappings)
{
    GList *elem;
    pcp_mapping mapping = NULL;

    for (elem = mappings; elem; elem = elem->next)
    {
        mapping = (pcp_mapping) elem->data;

        pcp_mapping_print (mapping);
    }
}
