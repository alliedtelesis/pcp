/**
 * Functions to create PCP mappings on iptables.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <syslog.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include "pcp_iptables.h"

/* Note: ip6tables is not supported yet */
#define IP4TABLES_CMD "iptables"
#define IP6TABLES_CMD "ip6tables"

#define PCP_PREROUTING_CHAIN "PCP_NAT_PREROUTE_RULES"
#define PCP_POSTROUTING_CHAIN "PCP_NAT_POSTROUTE_RULES"
#define PCP_MANGLE_CHAIN "PCP_MANGLE_RULES"

#define PCP_PREROUTING_RULE_FORMAT "PCP_NAT_PREROUTE_RULE_%d"
#define PCP_POSTROUTING_RULE_FORMAT "PCP_NAT_POSTROUTE_RULE_%d"
#define PCP_MANGLE_RULE_FORMAT "PCP_MANGLE_RULE_%d"

#define IPT_BUF_SIZE 256

typedef enum
{
    IPV4_ONLY,
    IPV6_ONLY,
    IPV4_AND_IPV6,
} PCP_CMD_TYPE;

/**
 * @brief send_iptables_cmd - Send an iptables command for IPv4 and/or IPv6
 * @param cmd - The command excluding the iptables/ip6tables at the start
 * @param family - Whether command is for IPv4, IPv6, or both
 * @return - True on success, false if a command failed or out of memory
 */
bool
send_iptables_cmd (const char *cmd, PCP_CMD_TYPE family)
{
    char tmp[IPT_BUF_SIZE] = { '\0' };
    bool ret = true;

    if (family != IPV4_ONLY)
    {
        if (snprintf (tmp, IPT_BUF_SIZE, "%s %s", IP6TABLES_CMD, cmd) <= 0)
        {
            return false;
        }
        if (system (tmp))
        {
            syslog (LOG_ERR, "Command [%s %s] failed", IP6TABLES_CMD, cmd);
            ret = false;
        }
        syslog (LOG_DEBUG, "Sent cmd: %s\n", tmp);
    }
    if (family != IPV6_ONLY)
    {
        if (snprintf (tmp, IPT_BUF_SIZE, "%s %s", IP4TABLES_CMD, cmd) <= 0)
        {
            return false;
        }
        if (system (tmp))
        {
            syslog (LOG_ERR, "Command [%s %s] failed", IP4TABLES_CMD, cmd);
            ret = false;
        }
        syslog (LOG_DEBUG, "Sent cmd: %s\n", tmp);
    }
    return ret;
}

/**
 * @brief pcp_iptables_init - Create new iptables chains for PCP and append
 *          them to the correct places
 */
void
pcp_iptables_init (void)
{
    char *cmd_preroute;
    char *cmd_postroute;
    char *cmd_mangle;

    /* Create new chains for PCP mappings. Return if any one of them already exists */
    cmd_preroute = "-t nat -N " PCP_PREROUTING_CHAIN;
    cmd_postroute = "-t nat -N " PCP_POSTROUTING_CHAIN;
    cmd_mangle = "-t mangle -N " PCP_MANGLE_CHAIN;

    if (!send_iptables_cmd (cmd_preroute, IPV4_ONLY) ||
        !send_iptables_cmd (cmd_postroute, IPV4_ONLY) ||
        !send_iptables_cmd (cmd_mangle, IPV4_ONLY))
    {
        return;
    }

    /* Flush the chains */
    cmd_preroute = "-t nat -F " PCP_PREROUTING_CHAIN;
    cmd_postroute = "-t nat -F " PCP_POSTROUTING_CHAIN;
    cmd_mangle = "-t mangle -F " PCP_MANGLE_CHAIN;

    send_iptables_cmd (cmd_preroute, IPV4_ONLY);
    send_iptables_cmd (cmd_postroute, IPV4_ONLY);
    send_iptables_cmd (cmd_mangle, IPV4_ONLY);

    /* Append the chains to the correct places */
    cmd_preroute = "-t nat -A PREROUTING -j " PCP_PREROUTING_CHAIN;
    cmd_postroute = "-t nat -A POSTROUTING -j " PCP_POSTROUTING_CHAIN;
    cmd_mangle = "-t mangle -A PREROUTING -j " PCP_MANGLE_CHAIN;

    send_iptables_cmd (cmd_preroute, IPV4_ONLY);
    send_iptables_cmd (cmd_postroute, IPV4_ONLY);
    send_iptables_cmd (cmd_mangle, IPV4_ONLY);
}

/**
 * @brief pcp_iptables_deinit - Remove the references the the PCP iptables chains
 *          then remove them
 */
void
pcp_iptables_deinit (void)
{
    char *cmd_preroute;
    char *cmd_postroute;
    char *cmd_mangle;

    /* Remove the references to the chains */
    cmd_preroute = "-t nat -D PREROUTING -j " PCP_PREROUTING_CHAIN;
    cmd_postroute = "-t nat -D POSTROUTING -j " PCP_POSTROUTING_CHAIN;
    cmd_mangle = "-t mangle -D PREROUTING -j " PCP_MANGLE_CHAIN;

    send_iptables_cmd (cmd_preroute, IPV4_ONLY);
    send_iptables_cmd (cmd_postroute, IPV4_ONLY);
    send_iptables_cmd (cmd_mangle, IPV4_ONLY);

    /* Flush the chains */
    cmd_preroute = "-t nat -F " PCP_PREROUTING_CHAIN;
    cmd_postroute = "-t nat -F " PCP_POSTROUTING_CHAIN;
    cmd_mangle = "-t mangle -F " PCP_MANGLE_CHAIN;

    send_iptables_cmd (cmd_preroute, IPV4_ONLY);
    send_iptables_cmd (cmd_postroute, IPV4_ONLY);
    send_iptables_cmd (cmd_mangle, IPV4_ONLY);

    /* Delete the chains */
    cmd_preroute = "-t nat -X " PCP_PREROUTING_CHAIN;
    cmd_postroute = "-t nat -X " PCP_POSTROUTING_CHAIN;
    cmd_mangle = "-t mangle -X " PCP_MANGLE_CHAIN;

    send_iptables_cmd (cmd_preroute, IPV4_ONLY);
    send_iptables_cmd (cmd_postroute, IPV4_ONLY);
    send_iptables_cmd (cmd_mangle, IPV4_ONLY);
}

/**
 * @brief is_ipv4_mapped_ipv6_addr - Check if the IPv6 address was created from
 *          mapping a IPv4 address
 * @param ip6 - The IPv6 address
 * @return  - True if the IPv6 address is IPv4 mapped
 */
bool
is_ipv4_mapped_ipv6_addr (struct in6_addr *ip6)
{
    int i;
    for (i = 0; i < 10; i++)
    {
        if (ip6->s6_addr[i] != 0)
        {
            return false;
        }
    }
    if (ip6->s6_addr[10] != 0xff || ip6->s6_addr[11] != 0xff)
    {
        return false;
    }
    return true;
}

/**
 * @brief convert_ipv6_to_ipv4 - Convert the IPv6 address to IPv4. Before calling this
 *          function, check if compatible with is_ipv4_mapped_ipv6_addr or strange things
 *          may happen elsewhere.
 * @param ip6 - The IPv6 address
 * @return - The converted IPv4 address
 */
struct in_addr
convert_ipv6_to_ipv4 (struct in6_addr *ip6)
{
    struct in_addr result = { 0 };
    result.s_addr = (ip6->s6_addr[12] << 24) +
                    (ip6->s6_addr[13] << 16) +
                    (ip6->s6_addr[14] << 8) +
                    (ip6->s6_addr[15]);
    return result;
}

/* Create the chains in the correct tables */
static bool
create_pcp_rule_chains (char *chain_preroute, char *chain_postroute, char *chain_mangle)
{
    char cmd_preroute[IPT_BUF_SIZE] = { '\0' };
    char cmd_postroute[IPT_BUF_SIZE] = { '\0' };
    char cmd_mangle[IPT_BUF_SIZE] = { '\0' };

    if (snprintf (cmd_preroute, IPT_BUF_SIZE, "-t nat -N %s", chain_preroute) <= 0 ||
        snprintf (cmd_postroute, IPT_BUF_SIZE, "-t nat -N %s", chain_postroute) <= 0 ||
        snprintf (cmd_mangle, IPT_BUF_SIZE, "-t mangle -N %s", chain_mangle) <= 0)
    {
        return false;
    }
    send_iptables_cmd (cmd_preroute, IPV4_ONLY);
    send_iptables_cmd (cmd_postroute, IPV4_ONLY);
    send_iptables_cmd (cmd_mangle, IPV4_ONLY);

    return true;
}

/* Flush the chains */
static bool
flush_pcp_rule_chains (char *chain_preroute, char *chain_postroute, char *chain_mangle)
{
    char cmd_preroute[IPT_BUF_SIZE] = { '\0' };
    char cmd_postroute[IPT_BUF_SIZE] = { '\0' };
    char cmd_mangle[IPT_BUF_SIZE] = { '\0' };

    if (snprintf (cmd_preroute, IPT_BUF_SIZE, "-t nat -F %s", chain_preroute) <= 0 ||
        snprintf (cmd_postroute, IPT_BUF_SIZE, "-t nat -F %s", chain_postroute) <= 0 ||
        snprintf (cmd_mangle, IPT_BUF_SIZE, "-t mangle -F %s", chain_mangle) <= 0)
    {
        return false;
    }
    send_iptables_cmd (cmd_preroute, IPV4_ONLY);
    send_iptables_cmd (cmd_postroute, IPV4_ONLY);
    send_iptables_cmd (cmd_mangle, IPV4_ONLY);

    return true;
}

/* Delete the chains */
static bool
delete_pcp_rule_chains (char *chain_preroute, char *chain_postroute, char *chain_mangle)
{
    char cmd_preroute[IPT_BUF_SIZE] = { '\0' };
    char cmd_postroute[IPT_BUF_SIZE] = { '\0' };
    char cmd_mangle[IPT_BUF_SIZE] = { '\0' };

    if (snprintf (cmd_preroute, IPT_BUF_SIZE, "-t nat -X %s", chain_preroute) <= 0 ||
        snprintf (cmd_postroute, IPT_BUF_SIZE, "-t nat -X %s", chain_postroute) <= 0 ||
        snprintf (cmd_mangle, IPT_BUF_SIZE, "-t mangle -X %s", chain_mangle) <= 0)
    {
        return false;
    }
    send_iptables_cmd (cmd_preroute, IPV4_ONLY);
    send_iptables_cmd (cmd_postroute, IPV4_ONLY);
    send_iptables_cmd (cmd_mangle, IPV4_ONLY);

    return true;
}

/* Add jumps to the chains for the new mapping - assuming PCP is enabled */
static bool
append_jump_pcp_rule_chains (char *chain_preroute, char *chain_postroute, char *chain_mangle)
{
    char cmd_preroute[IPT_BUF_SIZE] = { '\0' };
    char cmd_postroute[IPT_BUF_SIZE] = { '\0' };
    char cmd_mangle[IPT_BUF_SIZE] = { '\0' };

    if (snprintf (cmd_preroute, IPT_BUF_SIZE,
                  "-t nat -A " PCP_PREROUTING_CHAIN " -m connmark --mark 1/0x7 -j %s",
                  chain_preroute) <= 0 ||
        snprintf (cmd_postroute, IPT_BUF_SIZE,
                  "-t nat -A " PCP_POSTROUTING_CHAIN " -m connmark --mark 1/0x7 -j %s",
                  chain_postroute) <= 0 ||
        snprintf (cmd_mangle, IPT_BUF_SIZE,
                  "-t mangle -A " PCP_MANGLE_CHAIN " -m connmark --mark 0/0x7 -j %s",
                  chain_mangle) <= 0)
    {
        return false;
    }
    send_iptables_cmd (cmd_preroute, IPV4_ONLY);
    send_iptables_cmd (cmd_postroute, IPV4_ONLY);
    send_iptables_cmd (cmd_mangle, IPV4_ONLY);

    return true;
}

/* Remove jumps to the chains for a mapping */
static bool
remove_jump_pcp_rule_chains (char *chain_preroute, char *chain_postroute, char *chain_mangle)
{
    char cmd_preroute[IPT_BUF_SIZE] = { '\0' };
    char cmd_postroute[IPT_BUF_SIZE] = { '\0' };
    char cmd_mangle[IPT_BUF_SIZE] = { '\0' };

    if (snprintf (cmd_preroute, IPT_BUF_SIZE,
                  "-t nat -D " PCP_PREROUTING_CHAIN " -m connmark --mark 1/0x7 -j %s",
                  chain_preroute) <= 0 ||
        snprintf (cmd_postroute, IPT_BUF_SIZE,
                  "-t nat -D " PCP_POSTROUTING_CHAIN " -m connmark --mark 1/0x7 -j %s",
                  chain_postroute) <= 0 ||
        snprintf (cmd_mangle, IPT_BUF_SIZE,
                  "-t mangle -D " PCP_MANGLE_CHAIN " -m connmark --mark 0/0x7 -j %s",
                  chain_mangle) <= 0)
    {
        return false;
    }
    send_iptables_cmd (cmd_preroute, IPV4_ONLY);
    send_iptables_cmd (cmd_postroute, IPV4_ONLY);
    send_iptables_cmd (cmd_mangle, IPV4_ONLY);

    return true;
}

/* Get the protocol section of the iptables command including the port number if applicable */
static bool
get_protocol_port_str (char *buffer,
                       u_int16_t protocol,
                       u_int16_t port,
                       bool is_sport)
{
    // TODO: internal_port = 0 means DMZ host?
    switch (protocol)
    {
    /* TCP, UDP */
    case 6:
    case 17:
        if (snprintf (buffer, IPT_BUF_SIZE, "-p %u --%cport %u",
                      protocol, is_sport ? 's' : 'd', port) >= 0)
            return true;
        break;
    /* TODO: ICMP, no port number */
//    case 1:
//        if (inverted)
//            return NULL;
//        return get_icmp_match (app);
    default:
        if (snprintf (buffer, IPT_BUF_SIZE, "-p %d", protocol) >= 0)
            return true;
        break;
    }

    return false;
}

/* Create port forwarding from external to internal and mark as allowed */
static bool
ext_to_int_pcp_rule (char *chain_preroute,
                     char *chain_mangle,
                     char *internal_ip_str,
                     char *external_ip_str,
                     u_int16_t internal_port,
                     u_int16_t external_port,
                     u_int16_t protocol)
{
    char cmd_preroute[IPT_BUF_SIZE] = { '\0' };
    char cmd_mangle[IPT_BUF_SIZE] = { '\0' };

    char protocol_port_str[IPT_BUF_SIZE] = { '\0' };

    if (!get_protocol_port_str (protocol_port_str, protocol, external_port, false))
    {
        return false;
    }

    if (snprintf
            (cmd_preroute, IPT_BUF_SIZE,
             "-t nat -A %s -d %s %s -j DNAT --to-destination %s:%u",
             chain_preroute, external_ip_str, protocol_port_str, internal_ip_str, internal_port) <= 0 ||
        snprintf
            (cmd_mangle, IPT_BUF_SIZE,
             "-t mangle -A %s -d %s %s -j CONNMARK --set-mark 1/0x7",
             chain_mangle, external_ip_str, protocol_port_str) <= 0)
    {
        return false;
    }
    send_iptables_cmd (cmd_preroute, IPV4_ONLY);
    send_iptables_cmd (cmd_mangle, IPV4_ONLY);

    return true;
}

/* Create port forwarding from internal to external and mark as allowed */
static bool
int_to_ext_pcp_rule (char *chain_postroute,
                     char *chain_mangle,
                     char *internal_ip_str,
                     char *external_ip_str,
                     u_int16_t internal_port,
                     u_int16_t external_port,
                     u_int16_t protocol)
{
    char cmd_postroute[IPT_BUF_SIZE] = { '\0' };
    char cmd_mangle[IPT_BUF_SIZE] = { '\0' };

    char protocol_port_str[IPT_BUF_SIZE] = { '\0' };

    if (!get_protocol_port_str (protocol_port_str, protocol, internal_port, true))
    {
        return false;
    }

    if (snprintf
            (cmd_postroute, IPT_BUF_SIZE,
             "-t nat -A %s -s %s %s -j SNAT --to-source %s:%u",
             chain_postroute, internal_ip_str, protocol_port_str, external_ip_str, external_port) <= 0 ||
        snprintf
            (cmd_mangle, IPT_BUF_SIZE,
             "-t mangle -A %s -s %s %s -j CONNMARK --set-mark 1/0x7",
             chain_mangle, internal_ip_str, protocol_port_str) <= 0)
    {
        return false;
    }
    send_iptables_cmd (cmd_postroute, IPV4_ONLY);
    send_iptables_cmd (cmd_mangle, IPV4_ONLY);

    return true;
}

/**
 * Add a chain and rule to the nat table to do port forwarding using specified parameters.
 * TODO: IPv6
 * @param index         The rule ID
 * @param application   The name of the application entity
 * @param from          The name of the source entity
 * @param to            The name of the destination entity
 * @return - True on success, else false
 */
bool
write_pcp_port_forwarding_chain (int index,
                                 struct in_addr *internal_ip,
                                 struct in_addr *external_ip,
                                 u_int16_t internal_port,
                                 u_int16_t external_port,
                                 u_int16_t protocol)
{
    char chain_preroute[IPT_BUF_SIZE] = { '\0' };
    char chain_postroute[IPT_BUF_SIZE] = { '\0' };
    char chain_mangle[IPT_BUF_SIZE] = { '\0' };

    char internal_ip_str[INET_ADDRSTRLEN] = { '\0' };
    char external_ip_str[INET_ADDRSTRLEN] = { '\0' };

    if (!inet_ntop (AF_INET, internal_ip, internal_ip_str, INET_ADDRSTRLEN) ||
        !inet_ntop (AF_INET, external_ip, external_ip_str, INET_ADDRSTRLEN))
    {
        return false;
    }

    /* Form the names of the chains */
    if (snprintf (chain_preroute, IPT_BUF_SIZE, PCP_PREROUTING_RULE_FORMAT, index) <= 0 ||
        snprintf (chain_postroute, IPT_BUF_SIZE, PCP_POSTROUTING_RULE_FORMAT, index) <= 0 ||
        snprintf (chain_mangle, IPT_BUF_SIZE, PCP_MANGLE_RULE_FORMAT, index) <= 0)
    {
        return false;
    }

    /* Create the chains in the correct tables */
    if (!create_pcp_rule_chains (chain_preroute, chain_postroute, chain_mangle))
    {
        return false;
    }

    /* Flush the chains */
    if (!flush_pcp_rule_chains (chain_preroute, chain_postroute, chain_mangle))
    {
        return false;
    }

    /* Add jumps to the chains for the new mapping - assuming PCP is enabled */
    if (!append_jump_pcp_rule_chains (chain_preroute, chain_postroute, chain_mangle))
    {
        return false;
    }

    /* Create port forwarding from external to internal and mark as allowed */
    if (!ext_to_int_pcp_rule (chain_preroute, chain_mangle,
                              internal_ip_str, external_ip_str,
                              internal_port, external_port, protocol))
    {
        return false;
    }

    /* Create port forwarding from internal to external and mark as allowed */
    if (!int_to_ext_pcp_rule (chain_postroute, chain_mangle,
                              internal_ip_str, external_ip_str,
                              internal_port, external_port, protocol))
    {
        return false;
    }

    return true;
}

/**
 * Remove the chains for a mapping of the given index from the PCP iptables chains
 * @param index - The rule ID
 * @return - True on success, else false
 */
bool
remove_pcp_port_forwarding_chain (int index)
{
    char chain_preroute[IPT_BUF_SIZE] = { '\0' };
    char chain_postroute[IPT_BUF_SIZE] = { '\0' };
    char chain_mangle[IPT_BUF_SIZE] = { '\0' };

    /* Form the names of the chains */
    if (snprintf (chain_preroute, IPT_BUF_SIZE, PCP_PREROUTING_RULE_FORMAT, index) <= 0 ||
        snprintf (chain_postroute, IPT_BUF_SIZE, PCP_POSTROUTING_RULE_FORMAT, index) <= 0 ||
        snprintf (chain_mangle, IPT_BUF_SIZE, PCP_MANGLE_RULE_FORMAT, index) <= 0)
    {
        return false;
    }

    /* Remove jumps to the chains for the mapping */
    if (!remove_jump_pcp_rule_chains (chain_preroute, chain_postroute, chain_mangle))
    {
        return false;
    }

    /* Flush the chains */
    if (!flush_pcp_rule_chains (chain_preroute, chain_postroute, chain_mangle))
    {
        return false;
    }

    /* Delete the chains */
    if (!delete_pcp_rule_chains (chain_preroute, chain_postroute, chain_mangle))
    {
        return false;
    }

    return true;
}
