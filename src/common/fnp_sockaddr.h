#ifndef FNP_SOCKADDR_H
#define FNP_SOCKADDR_H

#include "fnp_common.h"



static inline uint32_t ipv4_ston(const char *ip)
{
    if (ip == NULL)
        return 0;
    struct in_addr addr;
    inet_aton(ip, &addr);

    return addr.s_addr;
}

static inline char *ipv4_ntos(uint32_t ip)
{
    struct in_addr addr;
    addr.s_addr = ip;
    return inet_ntoa(addr);
}

typedef struct fnp_addr
{
    u32 ip;
    u16 port;
} faddr_t;

static inline void init_faddr(faddr_t *addr,
                              char *ip, u16 port)
{
    addr->ip = ipv4_ston(ip);
    addr->port = fnp_swap16(port);
}

typedef union fnp_sockaddr
{
    struct
    { //
        u8 pad0;
        u8 proto;
        u16 pad1;
        u32 rip;
        u32 lip;
        u16 rport;
        u16 lport;
    };
    xmm_t xmm;
} fsockaddr_t;

static inline void init_fsockaddr(fsockaddr_t *addr,
                                  u8 proto, faddr_t *local, faddr_t *remote)
{
    addr->pad0 = 0;
    addr->pad1 = 0;
    addr->proto = proto;
    addr->lip = local ? local->ip : 0;
    addr->rip = remote ? remote->ip : 0;
    addr->lport = local ? local->port : 0;
    addr->rport = remote ? remote->port : 0;
}

static inline void copy_fnp_sockaddr(fsockaddr_t *dst, fsockaddr_t *src)
{
    rte_memcpy(dst, src, sizeof(fsockaddr_t));
}

static inline void print_fnp_sockaddr(fsockaddr_t *addr)
{
    FNP_INFO("proto: %d, lip: %s, rip: %s, lport: %d, rport: %d\n",
             addr->proto, addr->lip, addr->rip, addr->lport, addr->rport);
}

static inline void encode_ring_name(char *ring_name, char *prefix, void *addr)
{
    sprintf(ring_name, "%s:%p", prefix, addr);
}

typedef struct fnp_sockinfo
{
    faddr_t addr;
} fsockinfo_t;

#define get_fsockinfo(m) (fsockinfo_t *)(((struct rte_mbuf *)m)->buf_addr)

#endif // FNP_SOCKADDR_H
