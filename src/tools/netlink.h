/* Pi-hole: A black hole for Internet advertisements
*  (c) 2024 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Netlink prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef NETLINK_H
#define NETLINK_H

#include <arpa/inet.h>
#include "webserver/cJSON/cJSON.h"
#include "webserver/json_macros.h"

#ifdef __FreeBSD__
// FreeBSD replacements for Linux netlink:
// - getifaddrs() provides interface list, addresses, flags, MTU, MAC
// - PF_ROUTE socket provides routing table (default gateway)
// - sysctl NET_RT_DUMP provides ARP/NDP neighbor cache
#include <sys/socket.h>      // socket(), PF_ROUTE
#include <net/if.h>          // getifaddrs(), if_nametoindex(), IF_NAMESIZE
#include <net/if_dl.h>       // struct sockaddr_dl for MAC addresses
#include <net/route.h>       // struct rt_msghdr for route socket
#include <netinet/in.h>      // struct sockaddr_in, in6
#include <ifaddrs.h>         // getifaddrs(), freeifaddrs()
#else
#include <linux/rtnetlink.h>
// IFF_UP, etc.
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/if_addr.h>
#ifndef _NET_IF_ARP_H
#include <linux/if_arp.h>
#endif
#endif

bool nlroutes(cJSON *routes, const bool detailed);
bool nladdrs(cJSON *interfaces, const bool detailed);
bool nllinks(cJSON *interfaces, const bool detailed);
bool nlneigh(cJSON *arp_entries);
void get_gateway_name(char gateway[MAXIFACESTRLEN]);

// Netlink expects that the user buffer will be at least 8kB or a page size of
// the CPU architecture, whichever is bigger. Particular Netlink families may,
// however, require a larger buffer. 32kB buffer is recommended for most
// efficient handling of dumps (larger buffer fits more dumped objects and
// therefore fewer recvmsg() calls are needed).
// (see https://www.kernel.org/doc/html/v6.1/userspace-api/netlink/intro.html)
#define BUFLEN		(32 * 1024)

#define for_each_nlmsg(n, buf, len)					\
	for (n = (struct nlmsghdr*)buf;					\
	     NLMSG_OK(n, (uint32_t)len) && n->nlmsg_type != NLMSG_DONE;	\
	     n = NLMSG_NEXT(n, len))

#define for_each_rattr(n, buf, len)					\
	for (n = (struct rtattr*)buf; RTA_OK(n, len); n = RTA_NEXT(n, len))

struct flag_names {
	uint32_t flag;
	const char *name;
};

#endif // NETLINK_H
