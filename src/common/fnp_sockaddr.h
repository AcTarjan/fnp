#ifndef FNP_SOCKADDR_H
#define FNP_SOCKADDR_H

#include "fnp_common.h"

typedef struct fnp_addr
{
    u32 ip;
    u16 port;
} fnp_addr_t;

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
} fnp_sockaddr_t;

static inline void set_fnp_sockaddr(fnp_sockaddr_t *addr,
                                    u8 proto, u32 lip, u32 rip, u16 lport, u16 rport)
{
    addr->pad0 = 0;
    addr->pad1 = 0;
    addr->proto = proto;
    addr->lip = lip;
    addr->rip = rip;
    addr->lport = lport;
    addr->rport = rport;
}

static inline void copy_fnp_sockaddr(fnp_sockaddr_t *dst, fnp_sockaddr_t *src)
{
    rte_memcpy(dst, src, sizeof(fnp_sockaddr_t));
}

static inline void encode_ring_name(char *ring_name, char *prefix, void *addr)
{
    sprintf(ring_name, "%s:%p", prefix, addr);
}

typedef struct fnp_mbufinfo
{
    fnp_addr_t addr;
} fnp_mbufinfo_t;

static inline void print_fnp_sockaddr(fnp_sockaddr_t *addr)
{
    FNP_INFO("proto: %d, lip: %s, rip: %s, lport: %d, rport: %d\n",
             addr->proto, addr->lip, addr->rip, addr->lport, addr->rport);
}

#define fnp_mbufinfo(m) (fnp_mbufinfo_t *)(((struct rte_mbuf *)m)->buf_addr)

#endif // FNP_SOCKADDR_H
