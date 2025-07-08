#ifndef FNP_MBUF_H
#define FNP_MBUF_H

#include "fnp_socket.h"
#include "fnp_mbuf.h"

typedef struct rte_mbuf fnp_mbuf_t;

static inline fnp_mbuf_t* fnp_alloc_mbuf(const fsocket_t* socket)
{
    return rte_pktmbuf_alloc(socket->pool);
}

static inline void fnp_free_mbuf(fnp_mbuf_t* m)
{
    rte_pktmbuf_free(m);
}

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
