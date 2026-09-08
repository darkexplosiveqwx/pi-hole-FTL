/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Linux capabilities prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef CAPABILITIES_H
#define CAPABILITIES_H

#include <stdbool.h>
#ifndef __FreeBSD__
#include <linux/capability.h>
#else
// FreeBSD has no Linux capabilities (<linux/capability.h>). The FTL call sites
// pass CAP_* identifiers to check_capability(), whose FreeBSD implementation
// ignores the value and simply tests for effective uid 0. Define the handful of
// Linux capability numbers these call sites use (standard Linux values) so the
// portable call sites compile unchanged; they are passed only as opaque tokens.
#define CAP_CHOWN             0
#define CAP_DAC_OVERRIDE      1
#define CAP_FOWNER            3
#define CAP_FSETID            4
#define CAP_KILL              5
#define CAP_SETGID            6
#define CAP_SETUID            7
#define CAP_NET_BIND_SERVICE 10
#define CAP_NET_BROADCAST    11
#define CAP_NET_ADMIN        12
#define CAP_NET_RAW          13
#define CAP_SYS_MODULE       16
#define CAP_SYS_RAWIO        17
#define CAP_SYS_CHROOT       18
#define CAP_SYS_PTRACE       19
#define CAP_SYS_NICE         23
#define CAP_SYS_RESOURCE     24
#define CAP_SYS_TIME         25
#define CAP_MKNOD            27
#define CAP_LEASE            28
#endif

bool check_capability(const unsigned int cap);
bool check_capabilities(void);

#endif //CAPABILITIES_H
