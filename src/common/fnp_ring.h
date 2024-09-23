#ifndef FNP_RING_H
#define FNP_RING_H

#include "fnp_common.h"

typedef struct fnp_ring
{
    i32 size;           /* size of buf */
    i32 head;
    i32 tail;
    u8* buf;
} fnp_ring;

fnp_ring* fnp_alloc_ring(i32 size);

void fnp_free_ring(fnp_ring* fr);

i32 fnp_ring_avail(fnp_ring* fr);

i32 fnp_ring_len(fnp_ring* fr);

i32 fnp_ring_prepush(fnp_ring* fr, i32 offset, u8* buf, i32 len);

i32 fnp_ring_push(fnp_ring* fr, u8* buf, i32 len);

i32 fnp_ring_pop(fnp_ring* fr, u8* buf, u32 len);

i32 fnp_ring_top(fnp_ring* fr, u8* buf, i32 offset, i32 len);

#endif //FNP_RING_H
