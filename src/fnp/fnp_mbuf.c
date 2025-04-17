#include "fnp.h"
#include "fnp_socket.h"
/************* mbuf api start **************/

inline fnp_mbuf_t fnp_alloc_mbuf(fsocket_t* socket)
{
    return rte_pktmbuf_alloc(socket->pool);
}

inline void fnp_free_mbuf(fnp_mbuf_t m)
{
    rte_pktmbuf_free((struct rte_mbuf*)m);
}

inline i32 fnp_get_mbuf_len(fnp_mbuf_t m)
{
    if (m == NULL)
        return 0;
    return rte_pktmbuf_data_len((struct rte_mbuf*)m);
}

inline void fnp_set_mbuf_len(fnp_mbuf_t m, i32 len)
{
    rte_pktmbuf_append((struct rte_mbuf*)m, len);
}

inline u8* fnp_mbuf_data(fnp_mbuf_t m)
{
    if (m == NULL)
        return NULL;
    return rte_pktmbuf_mtod((struct rte_mbuf*)m, u8 *);
}
