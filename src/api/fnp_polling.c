#include "fnp.h"

#include "fnp_error.h"
#include "fnp_internal.h"

#define FNP_POLLING_BATCH_SIZE 1

int fnp_polling(fnp_socket_t *socket, fnp_handler_func handler, void *arg)
{
    if (unlikely(socket == NULL || socket->shared == NULL || handler == NULL))
    {
        return FNP_ERR_PARAM;
    }

    fnp_mbuf_t *mbufs[FNP_POLLING_BATCH_SIZE] = {0};
    u32 burst = fnp_ring_dequeue_burst(socket->shared->rx, (void **)mbufs, FNP_POLLING_BATCH_SIZE);
    for (u32 i = 0; i < burst; ++i)
    {
        handler(socket, mbufs[i], arg);
        fnp_free_mbuf(mbufs[i]);
    }
    return (int)burst;
}
