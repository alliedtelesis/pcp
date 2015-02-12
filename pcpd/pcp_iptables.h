/**
 * @file pcp_iptables.h
 *
 * Function declarations for managing PCP mappings on iptables.
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

#ifndef PCP_IPTABLES_H
#define PCP_IPTABLES_H

void pcp_iptables_init (void);

void pcp_iptables_deinit (void);

bool is_ipv4_mapped_ipv6_addr (struct in6_addr *ip6);

struct in_addr convert_ipv6_to_ipv4 (struct in6_addr *ip6);

bool write_pcp_port_forwarding_chain (int index,
                                      struct in_addr *internal_ip,
                                      struct in_addr *external_ip,
                                      u_int16_t internal_port,
                                      u_int16_t external_port,
                                      u_int16_t protocol);

bool remove_pcp_port_forwarding_chain (int index);

#endif /* PCP_IPTABLES_H */
