#ifndef FNP_MBUF_H
#define FNP_MBUF_H

#include <rte_mbuf.h>
#include "fnp_sockaddr.h"

typedef struct rte_mbuf fnp_mbuf_t;

typedef struct
{
    fsockaddr_t local;
    fsockaddr_t remote;
} fnp_mbuf_info_t;


static inline fnp_mbuf_info_t* fnp_get_mbuf_info(fnp_mbuf_t* m)
{
    return (fnp_mbuf_info_t*)rte_mbuf_to_priv(m);
}

fnp_mbuf_t* fnp_alloc_mbuf();

void fnp_free_mbuf(fnp_mbuf_t* m);


static inline i32 fnp_get_mbuf_len(fnp_mbuf_t* m)
{
    return rte_pktmbuf_data_len(m);
}

static inline u8* fnp_mbuf_data(fnp_mbuf_t* m)
{
    return rte_pktmbuf_mtod(m, u8 *);
}

static inline void fnp_mbuf_append_data(fnp_mbuf_t* m, i32 len)
{
    rte_pktmbuf_append(m, len);
}

#endif //FNP_MBUF_H
