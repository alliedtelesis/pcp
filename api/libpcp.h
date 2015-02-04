/**
 * @file libpcp.h
 *
 * Header file for pcpd API
 *
 * Copyright 2015 Allied Telesis Labs, New Zealand
 *
 */

#ifndef LIBPCP_H
#define LIBPCP_H

#include <stdint.h>
#include <stdbool.h>
#include <glib.h>
#include <netinet/in.h>

#define TIME_BUF_SIZE 32
// Format of Www Mmm dd hh:mm:ss yyyy
#define DATE_TIME_FORMAT "%a %b %e %T %Y"

#define PCP_VERSION 2
#define RESPONSE_RESERVED_SIZE 3
#define MAPPING_NONCE_SIZE 3
#define MAP_OPCODE 1
#define PEER_OPCODE 2
#define ANNOUNCE_OPCODE 3
#define PCP_SERVER_LISTENING_PORT 5351

#define DEFAULT_MAP_SUPPORT false
#define DEFAULT_PEER_SUPPORT false
#define DEFAULT_THIRD_PARTY_SUPPORT false
#define DEFAULT_PROXY_SUPPORT false
#define DEFAULT_UPNP_IGD_PCP_IWF_SUPPORT false
#define DEFAULT_MIN_MAPPING_LIFETIME 120
#define DEFAULT_MAX_MAPPING_LIFETIME 86400
#define DEFAULT_PREFER_FAILURE_REQ_RATE_LIMIT 256


/** Mapping handle */
struct pcp_mapping_s
{
    char *path;                 // Path stored in apteryx in libpcp.
    int index;
    u_int32_t mapping_nonce[MAPPING_NONCE_SIZE];
    struct in6_addr internal_ip;
    u_int16_t internal_port;
    struct in6_addr external_ip;
    u_int16_t external_port;
    u_int32_t lifetime;         // assigned_lifetime
    u_int32_t start_of_life;    // call time (NULL) at start and kept constant
    u_int32_t end_of_life;      // call time (NULL) + lifetime at start and update
    u_int8_t opcode;            // MAP or PEER opcode
    u_int8_t protocol;
};

typedef struct pcp_mapping_s *pcp_mapping;


void pcp_init (void);

void pcp_deinit (void);

void pcp_deinit_hard (void);

bool apteryx_set_ipv6_addr (const char *path, const char *key, struct in6_addr value);

struct in6_addr apteryx_get_ipv6_addr (const char *path, const char *key);


/* Mappings */

int next_mapping_id (void);

bool // TODO: Decide if bool or enum of error types
pcp_mapping_add (int index,
                 u_int32_t mapping_nonce[MAPPING_NONCE_SIZE],
                 struct in6_addr *internal_ip,
                 u_int16_t internal_port,
                 struct in6_addr *external_ip,
                 u_int16_t external_port,
                 u_int32_t lifetime,
                 u_int8_t opcode,
                 u_int8_t protocol);

bool pcp_mapping_refresh_lifetime (int index, u_int32_t new_lifetime, u_int32_t new_end_of_life);

bool pcp_mapping_delete (int index);

bool pcp_mapping_deleteall (void);

pcp_mapping pcp_mapping_find (int mapping_id);

GList *pcp_mapping_getall (void);

u_int32_t pcp_mapping_remaining_lifetime_get (pcp_mapping mapping);

void pcp_mapping_destroy (pcp_mapping mapping);


/* Config */

bool pcp_load_config (void);

bool pcp_initialized_set (bool enable);

bool pcp_initialized_get (void);

bool pcp_enabled_set (bool enable);

bool pcp_enabled_get (void);

bool map_support_set (bool enable);

bool map_support_get (void);

bool peer_support_set (bool enable);

bool peer_support_get (void);

bool third_party_support_set (bool enable);

bool third_party_support_get (void);

bool proxy_support_set (bool enable);

bool proxy_support_get (void);

bool upnp_igd_pcp_iwf_support_set (bool enable);

bool upnp_igd_pcp_iwf_support_get (void);

bool min_mapping_lifetime_set (u_int32_t lifetime);

u_int32_t min_mapping_lifetime_get (void);

bool max_mapping_lifetime_set (u_int32_t lifetime);

u_int32_t max_mapping_lifetime_get (void);

bool prefer_failure_req_rate_limit_set (u_int32_t rate);

u_int32_t prefer_failure_req_rate_limit_get (void);

bool startup_epoch_time_set (u_int32_t startup_time);

u_int32_t startup_epoch_time_get (void);

bool config_set_default (void);

char *get_uptime_string (void);


/************************
 * Watches
 *************************/

/* A struct that contains function pointers for handling each of the possible callbacks */
typedef struct _pcp_callbacks
{
    /** PCP service has been enabled/disabled */
    void (*pcp_enabled) (bool enable);

    /** MAP opcode support has been enabled/disabled */
    void (*map_support) (bool enable);

    /** PEER opcode support has been enabled/disabled */
    void (*peer_support) (bool enable);

    /** THIRD_PARTY option support has been enabled/disabled */
    void (*third_party_support) (bool enable);

    /** Proxy feature has been enabled/disabled */
    void (*proxy_support) (bool enable);

    /** UPnP IGD-PCP interworking funciton has been enabled/disabled */
    void (*upnp_igd_pcp_iwf_support) (bool enable);

    /** Minimum mapping lifetime has been changed */
    void (*min_mapping_lifetime) (u_int32_t lifetime);

    /** Maximum mapping lifetime has been changed */
    void (*max_mapping_lifetime) (u_int32_t lifetime);

    /** PREFER_FAILURE request rate limit has been changed */
    void (*prefer_failure_req_rate_limit) (u_int32_t rate);

    /** Server has been restarted so refresh startup time */
    void (*startup_epoch_time) (u_int32_t startup_time);

    /** New mapping has been added */
    void (*new_pcp_mapping) (int index,
                             u_int32_t mapping_nonce[MAPPING_NONCE_SIZE],
                             struct in6_addr internal_ip,
                             u_int16_t internal_port,
                             struct in6_addr external_ip,
                             u_int16_t external_port,
                             u_int32_t lifetime,
                             u_int32_t start_of_life,
                             u_int32_t end_of_life,
                             u_int8_t opcode,
                             u_int8_t protocol);

    /** A mapping has been deleted */
    void (*delete_pcp_mapping) (int index);
} pcp_callbacks;

bool pcp_register_cb (pcp_callbacks *cb);

// TODO: remove
void print_pcp_apteryx_config (void);
// TODO: somehow get output into show pcp and write pcp state
void pcp_mapping_print (pcp_mapping mapping);
void pcp_mapping_printall (GList *mappings);

#endif /* LIBPCP_H */
