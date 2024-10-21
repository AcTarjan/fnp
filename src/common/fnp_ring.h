#ifndef FNP_RING_H
#define FNP_RING_H

#include "fnp_common.h"

typedef struct fnp_ring
{
    // 实际大小为size-1，需要空出一个位置来区分满和空
    i32 size;           /* size of buf */
    i32 head;
    i32 tail;
    u8 buf[0];
} fnp_ring;

fnp_ring* fnp_ring_alloc(i32 size);

static inline void fnp_ring_free(fnp_ring* r) {
    fnp_free(r);
}

static inline i32 fnp_ring_len(fnp_ring* r)
{
    return (r->tail - r->head + r->size) % r->size;
}

static inline i32 fnp_ring_avail(fnp_ring* r)
{
    return r->size - 1 - fnp_ring_len(r);
}

//only write data, don't amend r->tail
i32 fnp_ring_prepush(fnp_ring* r, i32 offset, u8* buf, i32 len);

i32 fnp_ring_push(fnp_ring* r, u8* buf, i32 len);

//only read data, don't amend r->head
i32 fnp_ring_top(fnp_ring* r, u8* buf, i32 offset, i32 len);

i32 fnp_ring_pop(fnp_ring* r, u8* buf, i32 len);


#endif //FNP_RING_H
