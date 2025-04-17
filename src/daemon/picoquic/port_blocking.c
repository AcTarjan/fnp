#include "picoquic_internal.h"
#include "picoquic_unified_log.h"
#include <stdlib.h>
#include "fnp_sockaddr.h"

/* Picoquic servers running over UDP can be both victims and enablers
 * of reflection attacks.
 *
 * Servers may be targeted by DDOS attacks, which often use reflection
 * through an unwitting UDP-based server to hide the actual source of
 * the attack, and often to amplify the volume of the attack. The
 * reflected attacks will appear as coming from the address and port
 * of the server, such as NTP, DNS, other popular services, and also
 * port number 0 in case of fragmented UDP datagrams. The code
 * protect against those by just dropping packets from a list of
 * such ports. This protection is described in this message to the
 * HTTP WG list:
 * https://lists.w3.org/Archives/Public/ietf-http-wg/2021JulSep/0053.html
 * 
 * The blog entry https://blog.cloudflare.com/reflections-on-reflections/
 * provides a list of UDP ports that Cloudflare saw used in
 * reflection attacks:
 * Count  Proto  Src port
 *  3774   udp    123        NTP
 *  1692   udp    1900       SSDP
 *   438   udp    0          IP fragmentation
 *   253   udp    53         DNS
 *    42   udp    27015      SRCDS
 *    20   udp    19         Chargen
 *    19   udp    20800      Call Of Duty
 *    16   udp    161        SNMP
 *    12   udp    389        CLDAP
 *    11   udp    111        Sunrpc
 *    10   udp    137        Netbios
 *     6   tcp    80         HTTP
 *     5   udp    27005      SRCDS
 *     2   udp    520        RIP
 * 
 * Nick Banks at Microsoft pointed to the filtering list implemented
 * in msquic:
 * https://github.com/microsoft/msquic/blob/main/src/core/binding.c#L1399
 * The list contains a different set than the one defined by cloudflare,
 * with the inclusion of services like mDNS, NetBIOS, etc. 
 *       11211,  // memcache
 *       5353,   // mDNS
 *       1900,   // SSDP
 *       500,    // IKE
 *       389,    // CLDAP
 *       161,    // SNMP
 *       138,    // NETBIOS Datagram Service
 *       137,    // NETBIOS Name Service
 *       123,    // NTP
 *       111,    // Portmap
 *       53,     // DNS
 *       19,     // Chargen
 *       17,     // Quote of the Day
 *       0,      // Unusable
 * Services like mDNS or SSDp are typical local, and thus unlikely to be
 * used for DDOS amplification. Attackers would have difficulties reaching
 * these services from outside the local network. However, the attackers
 * could forge the source address and cause the QUIC servers to bounce 
 * packets towards these services. This kind of "request forgery attacks"
 * is discussed in section 21.5 of RFC 9000. Blocking the port numbers
 * of servers targeted by such attacks provides a layer of protection.
 * 
 * There are a couple of downsides to this protection:
 * - Some of the ports listed here are part of the randomly assigned range,
 *   and a unlucky client could end up using one of these ports.
 * - Even if clients do not use a reserved port, NATs might. Not much recourse
 *   there.
 * - New vulnerable protocols are likely to be created in the future, which
 *   means that the list will have to be updated.
 * - If the server sits behind a firewall, the firewall might be a better
 *   place for maintaining a list of blocked ports.
 * 
 * The implementation provides teo mitigations against these downsides:
 * 
 * - Servers can disable the protection if they don't want it.
 * - Clients can test the port number assigned to their sockets and
 *   pick a new one if they find a collision.
 * 
 */

const u16 picoquic_blocked_port_list[] = {
    27015, /* SRCDS */
    20800, /* Call Of Duty */
    11211, /* memcache */
    5353, /* mDNS */
    1900, /* SSDP */
    520, /* RIP */
    500, /* IKE */
    389, /* CLDAP */
    161, /* SNMP */
    138, /* NETBIOS Datagram Service */
    137, /* NETBIOS Name Service */
    123, /* NTP */
    111, /* Portmap -- used by SUN RPC */
    53, /* DNS */
    19, /* Chargen */
    17, /* Quote of the Day */
    7, /* Echo */
    0, /* Unusable */
};

const int nb_picoquic_blocked_port_list = sizeof(picoquic_blocked_port_list) / sizeof(uint16_t);

bool quic_check_port_blocked(u16 port)
{
    for (size_t i = 0; i < nb_picoquic_blocked_port_list && port <= picoquic_blocked_port_list[i]; i++)
    {
        if (port == picoquic_blocked_port_list[i])
        {
            return true;
        }
    }

    return false;
}

bool quic_check_addr_blocked(const fsockaddr_t* remote)
{
    /* The sockaddr is always in network order. We must translate to
     * host order before performaing the check */
    uint16_t port = UINT16_MAX;

    if (remote->family == FSOCKADDR_IPV4)
    {
        port = ntohs(remote->port);
    }

    return quic_check_port_blocked(port);
}

void quic_disable_port_blocking(quic_context_t* quic, int is_port_blocking_disabled)
{
    quic->is_port_blocking_disabled = is_port_blocking_disabled;
}
