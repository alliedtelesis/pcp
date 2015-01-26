/**
 * The main Port Control Protocol Daemon
 */

#include <getopt.h>
#include <glib.h>
#include <netdb.h>
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


#define PCPD_PID_PATH "/var/run/pcpd.pid"
#define OUTPUT_BUF_SIZE 2048
#define SMALL_BUF_SIZE 32

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
} pcp_config;


/* Global config struct */
pcp_config config;

/* Global list of all current mappings */
GList *mappings = NULL;


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
                 "     %-36.35s: %d\n",
                 "Server IP address", "something",
                 "Server uptime", 9001);

    if (n < 0)
        return n;

    // Dynamic number of clients. Need some looping when implemented later (dynamic mem?). Maybe table format.
    n = fprintf (target,
                 "PCP Clients:\n"
                 "     %-36.35s: %s\n"
                 "     %-36.35s: %d\n",
                 "Server IP address", "something",
                 "Server uptime", 10001);

    if (n < 0)
        return n;

    // Same as above
    n = fprintf (target,
                 "PCP Static Mappings:\n"
                 "     %-36.35s: %s\n"
                 "     %-36.35s: %d\n",
                 "Server IP address", "something",
                 "Server uptime", 12001);

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
        pcp_register_cb (NULL);
        g_list_free_full (mappings, (GDestroyNotify) pcp_mapping_destroy);
        pcp_deinit ();
        exit (EXIT_SUCCESS);
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

    signal (SIGCHLD, SIG_IGN);  // Take care of zombie processes

    sock = socket (AF_INET, SOCK_DGRAM, 0);

    check_error (sock, "Opening socket");

    length = sizeof (server);
    memset (&server, 0, length);
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons (PCP_SERVER_LISTENING_PORT);

    n = bind (sock, (struct sockaddr *) &server, length);
    check_error (n, "binding");

    return sock;
}

/**
 * @brief process_map_request - Process a MAP request and create MAP response
 * @param pkt_buf - Serialized MAP request buffer
 * @return - Serialized MAP response
 */
unsigned char *
process_map_request (unsigned char *pkt_buf)
{
    unsigned char *ptr;
    map_request *map_req;
    map_response *map_resp;

    u_int32_t lifetime;
    u_int16_t assigned_ext_port;
    char *assigned_ext_ip_str;
    struct in6_addr assigned_ext_ip;
    result_code result;

    map_req = deserialize_map_request (pkt_buf);

    result = SUCCESS;
    /* TODO:
     * - Validate values on struct. E.g. if version != 2 then "result = UNSUPP_VERSION;"
     * If (result == SUCCESS) so far:
     * - Make mapping using values from the struct
     * - Get info of mapping if successful, like assigned lifetime, ext port and ext ip address
     * - Set result_code based on result
     * Below are temporary values for these variables
     */
    lifetime = 9001;    // Lifetime of mapping or expected lifetime of resulting error
    assigned_ext_port = 4321;
    assigned_ext_ip_str = "80fe::2020:ff3b:2eef:3829";
    if (!inet_pton (AF_INET6, assigned_ext_ip_str, &assigned_ext_ip))
    {
        perror ("failed parsing");
        result = NETWORK_FAILURE;
    }
    //result = NOT_AUTHORIZED;

    if (result == SUCCESS)
    {
        int index = -1;     // Next highest index
        pcp_mapping_add (index,
                         map_req->mapping_nonce,
                         &(map_req->header.client_ip),
                         map_req->internal_port,
                         &assigned_ext_ip,
                         assigned_ext_port,
                         lifetime,
                         MAP_OPCODE,
                         map_req->protocol);

        puts("\n printing all mappings from apteryx");
        GList *apteryx_mappings = pcp_mapping_getall ();
        pcp_mapping_printall (apteryx_mappings);
        g_list_free_full (apteryx_mappings, (GDestroyNotify) pcp_mapping_destroy);
        puts(" end printing all mappings from apteryx\n");

        puts("\n printing all mappings from local list");
        pcp_mapping_printall (mappings);
        puts(" end printing all mappings from local list\n");
    }

    map_resp =
        new_pcp_map_response (map_req, lifetime, result, assigned_ext_port,
                              &assigned_ext_ip);

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
    mapping->opcode = opcode;
    mapping->protocol = protocol;

    mappings = g_list_insert_sorted (mappings, mapping, mapping_index_cmp);
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
    pcp_mapping mapping = pcp_mapping_get (index);

    if (mapping)
    {
        mappings = g_list_remove (mappings, mapping);

        pcp_mapping_destroy (mapping);
    }
}

void
run_loop (int sock, socklen_t fromlen)
{
    int n;
    struct sockaddr_in from;
    unsigned char pkt_buf[MAX_STRING_LEN];
    bool pkt_buf_changed;
    unsigned char *ptr = NULL;
    packet_type type;

    n = recvfrom (sock, pkt_buf, MAX_STRING_LEN - 1, 0, (struct sockaddr *) &from,
                  &fromlen);
    check_error (n, "recvfrom");

    type = get_packet_type (pkt_buf);

    pkt_buf_changed = false;

    if (type == MAP_REQUEST && config.map_support == true)
    {
        ptr = process_map_request (pkt_buf);

        pkt_buf_changed = true;
    }

    // Send the response
    if (pkt_buf_changed)
    {
        n = sendto (sock, pkt_buf, ptr - pkt_buf, 0, (struct sockaddr *) &from,
                    fromlen);
        check_error (n, "sendto");
    }
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
};

/**
 * The main function
 */
int
main (int argc, char *argv[])
{
    int sock;
    socklen_t fromlen;

    process_arguments (argc, argv);

    pcp_init ();

    if (!pcp_register_cb (&callbacks))
    {
        syslog (LOG_ERR, "Could not initialize PCP config");
        return EXIT_FAILURE;
    }

    // apply default config if first time running, otherwise load current config
    pcp_load_config ();

    print_pcp_apteryx_config (); // TODO: remove

    sock = setup_pcpd ();

    write_pcp_state (&config);

    fromlen = sizeof (struct sockaddr_in);

    while (1)
    {
        run_loop (sock, fromlen);

    }
    return EXIT_SUCCESS;
}
