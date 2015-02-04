/**
 * Functions to create PCP mappings on iptables.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

#include "pcp_iptables.h"

/* Note: ip6tables is not supported yet */
#define IP4TABLES_CMD "iptables"
#define IP6TABLES_CMD "ip6tables"

#define PCP_PREROUTING_CHAIN "PCP_NAT_PREROUTE_RULES"
#define PCP_POSTROUTING_CHAIN "PCP_NAT_POSTROUTE_RULES"
#define PCP_MANGLE_CHAIN "PCP_MANGLE_RULES"

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
        if (snprintf (tmp, IPT_BUF_SIZE, "%s %s", IP6TABLES_CMD, cmd) < 0)
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
        if (snprintf (tmp, IPT_BUF_SIZE, "%s %s", IP4TABLES_CMD, cmd) < 0)
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
