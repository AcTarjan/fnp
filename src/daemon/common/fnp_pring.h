#ifndef FNP_FNP_PRING_H
#define FNP_FNP_PRING_H

#include "fnp_common.h"

typedef struct fnp_pring
{
    i32 size;           /* size of buf */
    i32 head;
    i32 tail;
    /* 注意这里有4字节的padding, sizeof(fnp_pring) = 16 */
    void* buf[0];       // buf 8字节对齐
} fnp_pring;


fnp_pring* fnp_pring_alloc(i32 size);

static inline void fnp_pring_free(fnp_pring* r) {
    fnp_free(r);
}

static inline i32 fnp_pring_len(fnp_pring* r) {
    return (r->tail - r->head + r->size) % r->size;
}

static inline i32 fnp_pring_avail(fnp_pring* r) {
    return r->size - 1 - fnp_pring_len(r);
}

bool fnp_pring_enqueue(fnp_pring* r, void* data);

bool fnp_pring_dequeue(fnp_pring* r, void** data);

i32 fnp_pring_enqueue_bulk(fnp_pring* r, void* data[], i32 len);

i32 fnp_pring_dequeue_bulk(fnp_pring* r, void* data[], i32 len);

void* fnp_pring_top(fnp_pring* r, i32 offset);

#endif //FNP_FNP_PRING_H
