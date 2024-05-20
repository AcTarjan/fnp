#ifndef FNP_RING_H
#define FNP_RING_H

#include "fnp_common.h"

/* struct fnp_ring is a ring buffer which can realize a ring queue */
struct fnp_ring;
typedef struct fnp_ring fnp_ring_t;

fnp_ring_t* fnp_alloc_ring(i32 size);

void fnp_free_ring(fnp_ring_t* fr);

i32 fnp_ring_avail(fnp_ring_t* fr);

i32 fnp_ring_len(fnp_ring_t* fr);

i32 fnp_ring_pre_push(fnp_ring_t* fr, i32 offset, u8* buf, i32 len);

i32 fnp_ring_push(fnp_ring_t* fr, u8* buf, i32 len);

i32 fnp_ring_pop(fnp_ring_t* fr, u8* buf, u32 len);

i32 fnp_ring_top(fnp_ring_t* fr, u8* buf, i32 offset, i32 len);

i32 fnp_ring_enqueue_bulk(fnp_ring_t* fr, void* obj, i32 len);

i32 fnp_ring_dequeue_bulk(fnp_ring_t* fr, void** obj, i32 len);

#define fnp_ring_enqueue(fr, obj)   \
    fnp_ring_enqueue_bulk((fr), &(obj), 1)

#define fnp_ring_dequeue(fr, obj)   \
    fnp_ring_dequeue_bulk((fr), (obj), 1)

i32 fnp_ring_top_queue(fnp_ring_t* fr, void** obj);

#endif //FNP_RING_H
