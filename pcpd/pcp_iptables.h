/**
 * Function declarations for creating PCP mappings on iptables
 */

#ifndef PCP_IPTABLES_H
#define PCP_IPTABLES_H

void pcp_iptables_init (void);

void pcp_iptables_deinit (void);

bool is_ipv4_mapped_ipv6_addr (struct in6_addr *ip6);

struct in_addr convert_ipv6_to_ipv4 (struct in6_addr *ip6);

int write_pcp_port_forwarding_chain (int index,
                                     struct in_addr internal_ip,
                                     struct in_addr external_ip,
                                     u_int16_t internal_port,
                                     u_int16_t external_port,
                                     u_int16_t protocol);

#endif /* PCP_IPTABLES_H */
