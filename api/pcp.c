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
#include <apteryx.h>
#include "libpcp.h"

#define ROOT_PATH "/pcp"

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
}

void
pcp_deinit (void)
{
    apteryx_shutdown ();
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

static bool
pcp_config_change (const char *path, void *priv, const unsigned char *value,
                         size_t len)
{
    const char *key = NULL;

    /* check we are in the right place */
    if (strncmp (path, CONFIG_PATH, strlen (CONFIG_PATH)) != 0)
        return false;

    key = path + strlen (CONFIG_PATH);

    pthread_mutex_lock (&callback_lock);

    /* skip the '/' character */
    key++;

    if (strcmp (key, PCP_ENABLED_KEY) == 0)
    {
        if (saved_cbs->pcp_enabled)
        {
            saved_cbs->pcp_enabled (pcp_enabled_get ());
        }
    }
    else if (strcmp (key, MAP_SUPPORT_KEY) == 0)
    {
        if (saved_cbs->map_support)
        {
            saved_cbs->map_support (map_support_get ());
        }
    }
    else if (strcmp (key, PEER_SUPPORT_KEY) == 0)
    {
        if (saved_cbs->peer_support)
        {
            saved_cbs->peer_support (peer_support_get ());
        }
    }
    else if (strcmp (key, THIRD_PARTY_SUPPORT_KEY) == 0)
    {
        if (saved_cbs->third_party_support)
        {
            saved_cbs->third_party_support (third_party_support_get ());
        }
    }
    else if (strcmp (key, PROXY_SUPPORT_KEY) == 0)
    {
        if (saved_cbs->proxy_support)
        {
            saved_cbs->proxy_support (proxy_support_get ());
        }
    }
    else if (strcmp (key, UPNP_IGD_PCP_IWF_SUPPORT_KEY) == 0)
    {
        if (saved_cbs->upnp_igd_pcp_iwf_support)
        {
            saved_cbs->upnp_igd_pcp_iwf_support (upnp_igd_pcp_iwf_support_get ());
        }
    }
    else if (strcmp (key, MIN_MAPPING_LIFETIME_KEY) == 0)
    {
        if (saved_cbs->min_mapping_lifetime)
        {
            saved_cbs->min_mapping_lifetime (min_mapping_lifetime_get ());
        }
    }
    else if (strcmp (key, MAX_MAPPING_LIFETIME_KEY) == 0)
    {
        if (saved_cbs->max_mapping_lifetime)
        {
            saved_cbs->max_mapping_lifetime (max_mapping_lifetime_get ());
        }
    }
    else if (strcmp (key, PREFER_FAILURE_REQ_RATE_LIMIT_KEY) == 0)
    {
        if (saved_cbs->prefer_failure_req_rate_limit)
        {
            saved_cbs->prefer_failure_req_rate_limit (prefer_failure_req_rate_limit_get ());
        }
    }

    pthread_mutex_unlock (&callback_lock);

    puts ("config_changed");  // TODO: remove

    return true;
}

bool
pcp_register_cb (pcp_callbacks *cb)
{
    pthread_mutex_lock (&callback_lock);
    saved_cbs = cb;
    pthread_mutex_unlock (&callback_lock);

    apteryx_watch (CONFIG_PATH "/*", cb ? pcp_config_change : NULL, NULL);

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
    g_list_free_full (paths, free);
}
