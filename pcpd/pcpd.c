/**
 * @file pcpd.c
 *
 * The main Port Control Protocol Daemon.
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

#include <getopt.h>
#include <glib.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <netinet/in.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "libpcp.h"
#include "packets_pcp.h"
#include "packets_pcp_serialization.h"
#include "pcp_iptables.h"


#define PCPD_PID_PATH "/var/run/pcpd.pid"
#define OUTPUT_BUF_SIZE 2048
#define SMALL_BUF_SIZE 32

/* Short lifetime errors use a 30-second lifetime and
 * long lifetime errors use a 30-minute lifetime. */
#define SHORT_LIFETIME_ERROR 30
#define LONG_LIFETIME_ERROR 1800

/* Possible results from attempting to create a mapping */
typedef enum
{
    CREATE_MAPPING_SUCCESS,
    DELETE_MAPPING_SUCCESS,
    DELETE_MAPPING_FAILED,
    EXTEND_MAPPING_SUCCESS,
    EXTEND_MAPPING_FAILED,
    INVALID_MAPPING_REQUEST,
    IPV6_UNSUPPORTED,       // TODO: Remove once implemented
    // TODO: Other cases e.g. no resources, excessive peers, network failure, etc.
} create_mapping_result;

/* Long version of argument options */
static struct option long_options[] = {
    { "output", required_argument, NULL, 'o' },
    { "help", no_argument, NULL, 'h' },
    { NULL, 0, NULL, 0 }
};

/* PCP config struct */
typedef struct _pcp_config
{
    char *output_path;
    bool pcp_enabled;
    bool map_support;
    bool peer_support;
    bool third_party_support;
    bool proxy_support;
    bool upnp_igd_pcp_iwf_support;
    u_int32_t min_mapping_lifetime;
    u_int32_t max_mapping_lifetime;
    u_int32_t prefer_failure_req_rate_limit;
    u_int32_t startup_epoch_time;
} pcp_config;


/* Global config struct */
pcp_config config;

/* Global list of all current mappings */
GList *mappings = NULL;

/* Thread variables */
pthread_t mapping_thread;
static pthread_mutex_t mapping_lock = PTHREAD_MUTEX_INITIALIZER;


/** TODO: Remove */
void
print_mappings_debug (void)
{
    puts("\n printing all mappings from apteryx");
    GList *apteryx_mappings = pcp_mapping_getall ();
    pcp_mapping_printall (apteryx_mappings);
    g_list_free_full (apteryx_mappings, (GDestroyNotify) pcp_mapping_destroy);
    puts(" end printing all mappings from apteryx\n");

    pthread_mutex_lock (&mapping_lock);
    puts("\n printing all mappings from local list");
    pcp_mapping_printall (mappings);
    puts(" end printing all mappings from local list\n");
    pthread_mutex_unlock (&mapping_lock);
}

/**
 * @brief usage - Print help text to stdout
 */
void
usage (void)
{
    fprintf (stdout, "pcpd, a port control protocol daemon\n\n"
             "usage:\tpcpd [-o OUTPUT_FILE]\n\n"
             "(Below text not updated)\n\n"
             "Without a specified config file, configuration\n"
             "will be locked to default.\n"
             "Output file is where to dump current pcpd information.\n\n");
}

/**
 * @brief error - Check return value. If error, then print it and exit.
 * @param msg - Error message to print
 */
void
check_error (int n, const char *msg)
{
    if (n < 0)
    {
        syslog (LOG_ERR, "%s", msg);
        exit (EXIT_FAILURE);
    }
}

static int
write_mapping (pcp_mapping mapping, FILE *target)
{
    int n = -1;

    if (mapping != NULL && target != NULL)
    {
        char internal_ip_str[INET6_ADDRSTRLEN];
        char external_ip_str[INET6_ADDRSTRLEN];
        char start_of_life_str[TIME_BUF_SIZE];
        char end_of_life_str[TIME_BUF_SIZE];

        time_t start_of_life_time_t = (time_t) mapping->start_of_life;
        time_t end_of_life_time_t = (time_t) mapping->end_of_life;

        struct tm *start_of_life_tm = localtime (&start_of_life_time_t);
        strftime (start_of_life_str, TIME_BUF_SIZE, DATE_TIME_FORMAT, start_of_life_tm);

        struct tm *end_of_life_tm = localtime (&end_of_life_time_t);
        strftime (end_of_life_str, TIME_BUF_SIZE, DATE_TIME_FORMAT, end_of_life_tm);

        inet_ntop (AF_INET6, &(mapping->internal_ip.s6_addr), internal_ip_str, INET6_ADDRSTRLEN);
        inet_ntop (AF_INET6, &(mapping->external_ip.s6_addr), external_ip_str, INET6_ADDRSTRLEN);

        n = fprintf (target,
                     "     %-21.20s: %d\n"
                     "       %-19.18s: %10u %10u %10u\n"
                     "       %-19.18s: [%s]:%u\n"
                     "       %-19.18s: [%s]:%u\n"
                     "       %-19.18s: %u\n"
                     "       %-19.18s: %u\n"
                     "       %-19.18s: %s\n"
                     "       %-19.18s: %s\n"
                     "       %-19.18s: %u\n\n",
                     (mapping->opcode == MAP_OPCODE) ? "MAP mapping ID" : "PEER mapping ID",
                     mapping->index,
                     "Mapping nonce",
                      mapping->mapping_nonce[0],
                      mapping->mapping_nonce[1],
                      mapping->mapping_nonce[2],
                      "Internal IP:port",
                      internal_ip_str,
                      mapping->internal_port,
                     "External IP:port",
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
                      mapping->protocol);
    }
    return n;
}

/**
 * @brief write_pcp_state_to_file - Write PCP state to target file.
 * @param config - PCP config struct.
 * @param target - File to write to.
 * @return - Negative number on error.
 */
int
write_pcp_state_to_file (pcp_config *config, FILE *target)
{
    int n;

    char startup_time_str[TIME_BUF_SIZE];
    time_t startup_epoch_time_t = (time_t) config->startup_epoch_time;
    struct tm *startup_time_tm = localtime (&startup_epoch_time_t);

    char *uptime_string;

    GList *elem;
    pcp_mapping mapping = NULL;

    strftime (startup_time_str, TIME_BUF_SIZE, DATE_TIME_FORMAT, startup_time_tm);

    uptime_string = get_uptime_string ();

    n = fprintf (target,
                 "PCP Config:\n"
                 "     %-36.35s: %s\n"
                 "     %-36.35s: %s\n"
                 "     %-36.35s: %s\n"
                 "     %-36.35s: %s\n"
                 "     %-36.35s: %s\n"
                 "     %-36.35s: %s\n"
                 "     %-36.35s: %u\n"
                 "     %-36.35s: %u\n"
                 "     %-36.35s: %u\n",
                 "PCP service",
                 config->pcp_enabled ? "Enabled" : "Disabled",
                 "MAP opcode support",
                 config->map_support ? "Enabled" : "Disabled",
                 "PEER opcode support",
                 config->peer_support ? "Enabled" : "Disabled",
                 "THIRD_PARTY option support",
                 config->third_party_support ? "Enabled" : "Disabled",
                 "Proxy support",
                 config->proxy_support ? "Enabled" : "Disabled",
                 "UPnP IGD-PCP IWF support",
                 config->upnp_igd_pcp_iwf_support ? "Enabled" :
                 "Disabled", "Minimum mapping lifetime",
                 config->min_mapping_lifetime,
                 "Maximum mapping lifetime",
                 config->max_mapping_lifetime,
                 "PREFER_FAILURE request rate limit",
                 config->prefer_failure_req_rate_limit);

    if (n < 0)
        return n;

    n = fprintf (target,
                 "PCP Server:\n"
                 "     %-36.35s: %s\n"
                 "     %-36.35s: %s\n"
                 "     %-36.35s: %s\n",
                 "Server IP address", "something",
                 "Server startup time",
                 startup_time_str,
                 "Server uptime",
                 uptime_string ? uptime_string : "Unknown - Out of memory");

    if (uptime_string)
        free (uptime_string);

    if (n < 0)
        return n;

    n = fprintf (target, "PCP Clients:\n");
    if (n < 0)
        return n;

    if (mappings)
    {
        for (elem = mappings; elem; elem = elem->next)
        {
            mapping = (pcp_mapping) elem->data;

            n = write_mapping (mapping, target);

            if (n < 0)
                return n;
        }
    }
    else
    {
        n = fprintf (target, "     There are no current mappings\n");
        if (n < 0)
            return n;
    }

    // TODO: Probably very similar to standard mappings
    n = fprintf (target,
                 "PCP Static Mappings:\n"
                 "     There are no current static mappings\n");

    return n;
}

/**
 * @brief write_pcp_state - Write current pcpd information to output file or
 *          stdout if not specified
 * @param config - Current config
 */
void
write_pcp_state (pcp_config *config)
{
    FILE *target;
    int n;

    if (config->output_path != NULL)
    {
        target = fopen (config->output_path, "w");
        if (target == NULL)
        {
            syslog (LOG_ERR, "Failed to create file for PCP output");
            target = stdout;
        }
    }
    else
    {
        target = stdout;
    }

    n = write_pcp_state_to_file (config, target);

    if (n < 0)
        syslog (LOG_ERR, "Failed writing to PCP output file");

    if (target != stdout && target != NULL)
        fclose (target);
}

/**
 * @brief create_pcpd_pid_file - Create pcpd.pid file for other processes to get process id
 */
static void
create_pcpd_pid_file (void)
{
    pid_t pid = getpid ();
    FILE *pid_fp = fopen (PCPD_PID_PATH, "w");

    if (pid_fp != NULL)
    {
        chmod (PCPD_PID_PATH, S_IROTH | S_IRGRP | S_IRUSR | S_IWUSR);
        fprintf (pid_fp, "%d\n", (int) pid);
        fclose (pid_fp);
    }
    else
    {
        syslog (LOG_ERR, "Failed to create file for the process ID, may have unexpected behaviour later");
        syslog (LOG_DEBUG, "Failed to create pcpd.pid, Signal processing may not work as expected.");
    }
}

static void
exit_pcpd (void)
{
    GList *elem;
    pcp_mapping mapping = NULL;

    pthread_cancel (mapping_thread);

    /* Deregister callback (perform callback delete functions manually to avoid possibly
     * exiting pcpd before callbacks successfully execute) */
    pcp_register_cb (NULL);

    for (elem = mappings; elem; elem = elem->next)
    {
        mapping = (pcp_mapping) elem->data;
        remove_pcp_port_forwarding_chain (mapping->index);
    }

    pcp_iptables_deinit ();
    g_list_free_full (mappings, (GDestroyNotify) pcp_mapping_destroy);
    pcp_deinit ();

    exit (EXIT_SUCCESS);
}

/**
 * @brief signal_handler - Signal handler that reloads the configuration or writes show output.
 * @param signal - The received signal
 */
static void
signal_handler (int signal)
{
    if (signal == SIGUSR1)
    {
        write_pcp_state (&config);
    }
    if (signal == SIGINT || signal == SIGTERM)
    {
        exit_pcpd ();
    }
}

/**
 * @brief setup_signal_handlers - Set up the signal handlers
 */
static void
setup_signal_handlers (void)
{
    struct sigaction sigact;

    sigact.sa_handler = signal_handler;
    sigact.sa_flags = SA_RESTART;
    sigfillset (&sigact.sa_mask);

    if (sigaction (SIGUSR1, &sigact, NULL) < 0)
    {
        syslog (LOG_ERR, "sigaction");
        exit (-1);
    }
    if (sigaction (SIGINT, &sigact, NULL) < 0)
    {
        syslog (LOG_ERR, "sigaction");
        exit (-1);
    }
    if (sigaction (SIGTERM, &sigact, NULL) < 0)
    {
        syslog (LOG_ERR, "sigaction");
        exit (-1);
    }
}

/**
 * @brief process_arguments - Process command line arguments
 * @param argc - argc from main()
 * @param argv - argv from main()
 */
void
process_arguments (int argc, char *argv[])
{
    char *p, *cmdname;
    int opt;

    cmdname = *argv;
    if ((p = strrchr (cmdname, '/')) != NULL)
        cmdname = p + 1;

    config.output_path = NULL;
    while ((opt = getopt_long (argc, argv, "o:h", long_options, NULL)) != EOF)
    {
        switch (opt)
        {
        case 'o':
            config.output_path = optarg;
            break;
        case 'h':
            usage ();
            exit (EXIT_SUCCESS);
        default:   /* '?' */
            fprintf (stderr, "Try `%s --help' for more information." "\n", cmdname);
            exit (EXIT_FAILURE);
        }
    }
}

/**
 * @brief setup_pcpd - Set up the PCP daemon.
 * @return - Socket value for the server
 */
int
setup_pcpd (void)
{
    int length, n, sock;
    struct sockaddr_in server;

    create_pcpd_pid_file ();

    setup_signal_handlers ();

    sock = socket (AF_INET, SOCK_DGRAM, 0);

    check_error (sock, "Opening socket");

    length = sizeof (server);
    memset (&server, 0, length);
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons (PCP_SERVER_LISTENING_PORT);

    n = bind (sock, (struct sockaddr *) &server, length);
    check_error (n, "binding");

    pcp_iptables_init ();

    return sock;
}

static bool
compare_mapping_nonces (u_int32_t nonce1[MAPPING_NONCE_SIZE],
                        u_int32_t nonce2[MAPPING_NONCE_SIZE])
{
    int i;
    for (i = 0; i < MAPPING_NONCE_SIZE; i++)
    {
        if (nonce1[i] != nonce2[i])
        {
            return false;
        }
    }
    return true;
}

static bool
compare_ipv6_addresses (struct in6_addr *ip1, struct in6_addr *ip2)
{
    return memcmp (ip1, ip2, sizeof (struct in6_addr)) == 0;
}

static bool
compare_map_request_to_mapping (map_request *map_req, pcp_mapping mapping)
{
    return compare_mapping_nonces (map_req->mapping_nonce, mapping->mapping_nonce) &&
            compare_ipv6_addresses (&(map_req->header.client_ip), &(mapping->internal_ip)) &&
            map_req->internal_port == mapping->internal_port &&
            map_req->protocol == mapping->protocol;
}

pcp_mapping
find_mapping_by_request (map_request *map_req)
{
    GList *elem;
    pcp_mapping mapping = NULL;

    for (elem = mappings; elem; elem = elem->next)
    {
        mapping = (pcp_mapping) elem->data;
        if (compare_map_request_to_mapping (map_req, mapping))
        {
            return mapping;
        }
    }
    return NULL;
}

create_mapping_result
process_existing_mapping (pcp_mapping mapping, map_response *map_resp)
{
    u_int32_t new_lifetime;
    u_int32_t new_end_of_life;
    create_mapping_result ret = EXTEND_MAPPING_SUCCESS;

    // Extend the existing mapping's lifetime by the validated lifetime currently stored in the response
    new_lifetime = map_resp->header.lifetime;
    new_end_of_life = time (NULL) + new_lifetime;

    if (new_lifetime == 0)
    {
        if (pcp_mapping_delete (mapping->index))
        {
            ret = DELETE_MAPPING_SUCCESS;
        }
        else
        {
            syslog (LOG_ERR, "Could not delete mapping with ID %d", mapping->index);
            ret = DELETE_MAPPING_FAILED;
        }
    }
    else if (pcp_mapping_refresh_lifetime (mapping->index, new_lifetime, new_end_of_life))
    {
        mapping->lifetime = new_lifetime;
        mapping->end_of_life = new_end_of_life;

        // Put the existing mapping's external IP:port into the response
        map_resp->assigned_external_ip = mapping->external_ip;
        map_resp->assigned_external_port = mapping->external_port;
    }
    else
    {
        syslog (LOG_ERR, "Could not extend mapping lifetime with ID %d", mapping->index);
        ret = EXTEND_MAPPING_FAILED;
    }

    usleep (25 * 1000);         // Give apteryx and callbacks time to run
    puts("MAPPING EXISTS");     // TODO: remove
    print_mappings_debug ();    // TODO: remove

    return ret;
}

create_mapping_result
create_mapping (map_response *map_resp, map_request *map_req)
{
    pcp_mapping mapping;
    create_mapping_result ret = CREATE_MAPPING_SUCCESS;
    int index;

    mapping = find_mapping_by_request (map_req);
    if (mapping)
    {
        ret = process_existing_mapping (mapping, map_resp);
    }
    else
    {
        /* TODO:
         * - Make mapping using values from the struct
         * - Get info of mapping if successful, like assigned lifetime, ext port and ext ip address
         *    (may be different to requested values)
         * - Set result_code based on result
         * Below are temporary values for these variables
         */
//        map_resp->header.lifetime = 9001;       // Lifetime of mapping or expected lifetime of resulting error
//        map_resp->header.lifetime = 10;         // Short lifetime to test the lifetime check thread
//        map_resp->assigned_external_port = 4321;
//        struct in6_addr temp_ip = { { { 0x80, 0xfe, 0, 0, 0, 0, 0, 0,
//                                        0x20, 0x20, 0xff, 0x3b, 0x2e, 0xef, 0x38, 0x29 } } };
//        map_resp->assigned_external_ip = temp_ip;

        struct in_addr temp_int_ip = { 0 };
        struct in_addr temp_ext_ip = { 0 };

        if (is_ipv4_mapped_ipv6_addr (&(map_req->header.client_ip)) &&
                is_ipv4_mapped_ipv6_addr (&(map_resp->assigned_external_ip)))
        {
                temp_int_ip = convert_ipv6_to_ipv4 (&(map_req->header.client_ip));
                temp_ext_ip = convert_ipv6_to_ipv4 (&(map_resp->assigned_external_ip));

                index = next_mapping_id ();

                /* TODO: Move writing chain to callback function. Probably easier to do
                 * once ip6tables is implemented (Only call add function then do
                 * IPv6 to IPv4 conversion only if required in the write chain function) */
                if (write_pcp_port_forwarding_chain (index,
                                                     &temp_int_ip,
                                                     &temp_ext_ip,
                                                     map_req->internal_port,
                                                     map_resp->assigned_external_port,
                                                     map_resp->protocol))
                {
                    // Store the new mapping
                    pcp_mapping_add (index,
                                     map_resp->mapping_nonce,
                                     &(map_req->header.client_ip),
                                     map_resp->internal_port,
                                     &(map_resp->assigned_external_ip),
                                     map_resp->assigned_external_port,
                                     map_resp->header.lifetime,
                                     OPCODE (map_resp->header.r_opcode),
                                     map_resp->protocol);

                    print_mappings_debug (); // TODO: remove
                }
                else
                {
                    syslog (LOG_ERR,
                            "Could not add new mapping with nonce [%u %u %u]",
                            map_resp->mapping_nonce[0],
                            map_resp->mapping_nonce[1],
                            map_resp->mapping_nonce[2]);
                }
        }
        else
        {
            ret = IPV6_UNSUPPORTED;
        }
    }
    return ret;
}

/**
 * @brief get_error_lifetime - Get the lifetime of a result code error. Does not
 *          process SUCCESS or CANNOT_PROVIDE_EXTERNAL result codes.
 * @param result - Constant value for either a short or long lifetime error, or
 *          0 if not supported
 * @return - The error lifetime
 */
static u_int32_t
get_error_lifetime (result_code result)
{
    u_int32_t ret = 0;

    switch (result)
    {
    case NETWORK_FAILURE:
    case NO_RESOURCES:
    case USER_EX_QUOTA:
        ret = SHORT_LIFETIME_ERROR;
        break;

    case UNSUPP_VERSION:
    case NOT_AUTHORIZED:
    case MALFORMED_REQUEST:
    case UNSUPP_OPCODE:
    case MALFORMED_OPTION:
    case UNSUPP_OPTION:
    case UNSUPP_PROTOCOL:
    case ADDRESS_MISMATCH:
    case EXCESSIVE_REMOTE_PEERS:
        ret = LONG_LIFETIME_ERROR;
        break;

    default:
        ret = 0;
        break;
    }

    return ret;
}

u_int32_t
get_valid_lifetime (u_int32_t lifetime)
{
    u_int32_t new_lifetime;

    // Ignore 0 since that means delete the mapping
    if (lifetime > 0 && lifetime < config.min_mapping_lifetime)
    {
        new_lifetime = config.min_mapping_lifetime;
    }
    else if (lifetime > config.max_mapping_lifetime)
    {
        new_lifetime = config.max_mapping_lifetime;
    }
    else
    {
        new_lifetime = lifetime;
    }
    return new_lifetime;
}

/**
 * @brief process_map_request - Process a MAP request and create MAP response
 * @param pkt_buf - Serialized MAP request buffer
 * @return - Serialized MAP response
 */
unsigned char *
process_map_request (unsigned char *pkt_buf)
{
    // TODO: New parameter to get the sender's IP address to compare with client IP in packet
    unsigned char *ptr;
    map_request *map_req;
    map_response *map_resp;
    create_mapping_result mapping_result;

    map_req = deserialize_map_request (pkt_buf);

    map_resp = new_pcp_map_response (map_req);

    map_resp->header.lifetime = get_valid_lifetime (map_resp->header.lifetime);
    mapping_result = create_mapping (map_resp, map_req);

    if (mapping_result == EXTEND_MAPPING_FAILED ||
        mapping_result == DELETE_MAPPING_FAILED)
    {
        map_resp->header.result_code = NO_RESOURCES;
        map_resp->header.lifetime = get_error_lifetime (map_resp->header.result_code);
    }
    else if (mapping_result == INVALID_MAPPING_REQUEST)
    {
        map_resp->header.lifetime = get_error_lifetime (map_resp->header.result_code);
    }
    else if (mapping_result == IPV6_UNSUPPORTED)
    {
        /* Temporary result code. Actually unsupp IP type since ipv6 unsupported
         * at this time but this doesn't exist in RFC. */
        map_resp->header.result_code = UNSUPP_PROTOCOL;
        map_resp->header.lifetime = get_error_lifetime (map_resp->header.result_code);
    }

    // Done. Send the response
    map_resp->header.epoch_time = time (NULL);
    ptr = serialize_map_response (pkt_buf, map_resp);

    free (map_req);
    free (map_resp);

    return ptr;
}

void
pcp_enabled (bool enabled)
{
    if (config.pcp_enabled == enabled)
        return;
    config.pcp_enabled = enabled;
}

void
map_support (bool enabled)
{
    if (config.map_support == enabled)
        return;
    config.map_support = enabled;
}

void
peer_support (bool enabled)
{
    if (config.peer_support == enabled)
        return;
    config.peer_support = enabled;
}

void
third_party_support (bool enabled)
{
    if (config.third_party_support == enabled)
        return;
    config.third_party_support = enabled;
}

void
proxy_support (bool enabled)
{
    if (config.proxy_support == enabled)
        return;
    config.proxy_support = enabled;
}

void
upnp_igd_pcp_iwf_support (bool enabled)
{
    if (config.upnp_igd_pcp_iwf_support == enabled)
        return;
    config.upnp_igd_pcp_iwf_support = enabled;
}

void
min_mapping_lifetime (u_int32_t lifetime)
{
    if (config.min_mapping_lifetime == lifetime)
        return;
    config.min_mapping_lifetime = lifetime;
}

void
max_mapping_lifetime (u_int32_t lifetime)
{
    if (config.max_mapping_lifetime == lifetime)
        return;
    config.max_mapping_lifetime = lifetime;
}

void
prefer_failure_req_rate_limit (u_int32_t rate)
{
    if (config.prefer_failure_req_rate_limit == rate)
        return;
    config.prefer_failure_req_rate_limit = rate;
}

void
startup_epoch_time (u_int32_t startup_time)
{
    if (config.startup_epoch_time == startup_time)
        return;
    config.startup_epoch_time = startup_time;
}

static int
mapping_index_cmp (gconstpointer _a, gconstpointer _b)
{
    return ((pcp_mapping) _a)->index - ((pcp_mapping) _b)->index;
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
    pcp_mapping mapping;
    mapping = malloc (sizeof (*mapping));

    mapping->path = NULL;
    mapping->index = index;
    mapping->mapping_nonce[0] = mapping_nonce[0];
    mapping->mapping_nonce[1] = mapping_nonce[1];
    mapping->mapping_nonce[2] = mapping_nonce[2];
    mapping->internal_ip = internal_ip;
    mapping->internal_port = internal_port;
    mapping->external_ip = external_ip;
    mapping->external_port = external_port;
    mapping->lifetime = lifetime;
    mapping->start_of_life = start_of_life;
    mapping->end_of_life = end_of_life;
    mapping->opcode = opcode;
    mapping->protocol = protocol;

    pthread_mutex_lock (&mapping_lock);

    mappings = g_list_insert_sorted (mappings, mapping, mapping_index_cmp);

    pthread_mutex_unlock (&mapping_lock);
}

static pcp_mapping
pcp_mapping_get (int index)
{
    pcp_mapping temp_mapping = NULL;
    pcp_mapping mapping = NULL;
    GList *elem = NULL;

    temp_mapping = malloc (sizeof (*temp_mapping));
    temp_mapping->path = NULL;

    temp_mapping->index = index;

    elem = g_list_find_custom (mappings, temp_mapping, mapping_index_cmp);

    if (elem && elem->data)
    {
        mapping = (pcp_mapping) elem->data;
    }

    pcp_mapping_destroy (temp_mapping);

    return mapping;
}

void
delete_pcp_mapping (int index)
{
    if (!remove_pcp_port_forwarding_chain (index))
    {
        syslog (LOG_ERR, "Removing mapping of index %d failed", index);
    }

    pthread_mutex_lock (&mapping_lock);

    pcp_mapping mapping = pcp_mapping_get (index);

    if (mapping)
    {
        mappings = g_list_remove (mappings, mapping);

        pcp_mapping_destroy (mapping);
    }

    pthread_mutex_unlock (&mapping_lock);
}

/**
 * @brief process_request - Process a valid PCP request
 * @param pkt_buf - Packet buffer
 * @return - Pointer to the end of the next byte after the serialized response
 *           if successful or NULL if opcode is not supported is or disabled
 */
unsigned char *
process_request (unsigned char *pkt_buf)
{
    packet_type type = get_packet_type (pkt_buf);
    unsigned char *ptr = NULL;

    if (type == MAP_REQUEST && config.map_support == true)
    {
        /* TODO: Pass a parameter so actual IP received from can be compared to
         * internal IP stored in packet header for the ADDRESS_MISMATCH result code */
        ptr = process_map_request (pkt_buf);
    }
    // TODO: PEER_REQUEST and ANNOUNCE_REQUEST (ANNOUNCE opcode is non-configurable)
    return ptr;
}

/**
 * @brief process_error - Process an PCP request which resulted in an error
 * @param pkt_buf - Packet buffer
 * @param result - The error's result code
 * @return - Pointer to the next byte after the serialized error response
 */
unsigned char *
process_error (unsigned char *pkt_buf, result_code result)
{
    unsigned char *ptr = NULL;
    pcp_response_header *error_resp = new_pcp_error_response (
                get_r_opcode (pkt_buf), result, get_error_lifetime (result));

    ptr = serialize_response_header (pkt_buf, error_resp);

    free (error_resp);

    /* If it is desired to append the extra garbage in the error packet, set ptr to be
     * at the end of the packet. Maybe new parameter of pkt_buf size n and
     * return pkt_buf + n since the rest of pkt_buf is untouched */

    return ptr;
}

/**
 * @brief run_loop - The main loop
 * @param sock - Server socket number
 */
void
run_loop (int sock)
{
    int n;
    struct sockaddr_in from;
    socklen_t fromlen = sizeof (struct sockaddr_in);
    unsigned char pkt_buf[MAX_PAYLOAD_LEN + 1];
    unsigned char *ptr = NULL;
    result_code result = SUCCESS;

    // TODO: Handle IPv6
    /* Receive one more byte than the max size so that the error case of a packet being
     * too large can be detected */
    n = recvfrom (sock, pkt_buf, MAX_PAYLOAD_LEN + 1, 0, (struct sockaddr *) &from,
                  &fromlen);
    check_error (n, "recvfrom");

    result = validate_packet_buffer (pkt_buf, n);

    switch (result)
    {
    case RESULT_CODE_MAX:
        // Silently drop the packet
        return;

    case UNSUPP_VERSION:
        // TODO: Follow Version Negotiation steps in RFC pg29
        // Generate error response packet
        ptr = process_error (pkt_buf, result);
        break;

    case MALFORMED_REQUEST:
    case UNSUPP_OPCODE:
        // Generate error response packet
        ptr = process_error (pkt_buf, result);
        break;

    default:
        // Validation successful
        ptr = process_request (pkt_buf);
        break;
    }

    // Send the response
    if (ptr)
    {
        // Packet processing was successful and a response was generated in pkt_buf
        if (ptr - pkt_buf > MAX_PAYLOAD_LEN)
        {
            // Packet is longer than the maximum. Move the pointer.
            ptr = pkt_buf + MAX_PAYLOAD_LEN;
        }
        else
        {
            ptr = add_zero_padding (pkt_buf, ptr);
        }
        n = sendto (sock, pkt_buf, ptr - pkt_buf, 0, (struct sockaddr *) &from,
                    fromlen);
        check_error (n, "sendto");
    }
}

/**
 * Background thread which periodically iterates through the list of current mappings
 * and removes any expired ones.
 */
void *
check_mapping_lifetimes (void *arg)
{
    GList *elem;
    pcp_mapping mapping = NULL;
    bool deleted = false;   // TODO: remove
    int count = 0;          // TODO: remove

    while (1)
    {
        /* When an expired mapping is found, the delete function from libpcp is called
         * which changes the value stored in apteryx. This prompts the local function
         * delete_pcp_mapping to be called but it will block since the mapping lock
         * is in place. This causes all of the delete_pcp_mapping calls to queue
         * up in a separate thread and execute after this loop is complete. */
        pthread_mutex_lock (&mapping_lock);

        for (elem = mappings; elem; elem = elem->next)
        {
            mapping = (pcp_mapping) elem->data;

            if (pcp_mapping_remaining_lifetime_get (mapping) == 0)
            {
                if (pcp_mapping_delete (mapping->index))
                {
                    deleted = true; // TODO: remove
                    count++;        // TODO: remove
                }
                else
                {
                    syslog (LOG_ERR, "Could not delete mapping with ID %d", mapping->index);
                }
            }
        }

        pthread_mutex_unlock (&mapping_lock);

        // TODO: Remove if statement, the deleted flag and count
        if (deleted)
        {
            usleep (25 * 1000); // Give apteryx and callbacks time to run
            printf ("%d mappings deleted at %u - printing now\n", count, (u_int32_t) time (NULL));

            print_mappings_debug (); // TODO: remove

            deleted = false;
            count = 0;
        }
        sleep (1);
    }

    return NULL;
}

/** A struct that contains function pointers for handling each of the possible callbacks */
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
    .startup_epoch_time = startup_epoch_time,
};

/**
 * The main function
 */
int
main (int argc, char *argv[])
{
    int sock;

    process_arguments (argc, argv);

    pcp_init ();

    if (!pcp_register_cb (&callbacks))
    {
        syslog (LOG_ERR, "Could not initialize PCP config");
        return EXIT_FAILURE;
    }

    // Apply default config if first time running, otherwise load current config
    pcp_load_config ();

    // Set the startup time
    startup_epoch_time_set (time (NULL));

    print_pcp_apteryx_config (); // TODO: remove

    sock = setup_pcpd ();

    write_pcp_state (&config);

    if (pthread_create (&mapping_thread, NULL, &check_mapping_lifetimes, NULL) != 0)
    {
        syslog (LOG_ERR, "Failed to create mapping lifetime check thread\n");
    }
    if (pthread_detach (mapping_thread) != 0)
    {
        syslog (LOG_ERR, "Failed to detach thread\n");
    }

    while (1)
    {
        run_loop (sock);
    }
    return EXIT_SUCCESS;
}
