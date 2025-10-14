#ifndef FNP_FNP_PRING_H
#define FNP_FNP_PRING_H

#include "../../inc/fnp_common.h"

#include <stdatomic.h>

typedef struct fnp_ring
{
    rte_atomic32_t ref_count;
    u32 size; // size of buf
    u32 mask; // size - 1, size must be power of 2, 等于capacity
    u32 is_mp : 1; //是否多生产者
    u32 is_mc : 1; //是否多消费者
    volatile atomic_uint prod_head;
    volatile atomic_uint prod_tail; //实际的生产者指针
    volatile atomic_uint cons_head;
    volatile atomic_uint cons_tail; //实际的生产者指针

    /* 注意这里有4字节的padding, sizeof(fnp_pring) = 16 */
    void* buf[0]; // buf 8字节对齐
} fnp_ring_t;


fnp_ring_t* fnp_ring_create(i32 size, bool is_mp, bool is_mc);

static inline fnp_ring_t* fnp_ring_clone(fnp_ring_t* r)
{
    if (r == NULL)
        return NULL;
    rte_atomic32_inc(&r->ref_count);
    return r;
}

static inline void fnp_ring_free(fnp_ring_t* r)
{
    if (r == NULL)
        return;
    rte_atomic32_dec(&r->ref_count);
    if (rte_atomic32_read(&r->ref_count) == 0)
        fnp_free(r);
}

static inline u32 fnp_ring_count(const fnp_ring_t* r)
{
    uint32_t prod_tail = r->prod_tail;
    uint32_t cons_tail = r->cons_tail;
    uint32_t count = (prod_tail - cons_tail) & r->mask;
    return (count > r->mask) ? r->mask : count;
}

static inline u32 fnp_ring_free_count(const fnp_ring_t* r)
{
    return r->mask - fnp_ring_count(r);
}

static inline i32 fnp_ring_empty(fnp_ring_t* r)
{
    uint32_t prod_tail = r->prod_tail;
    uint32_t cons_tail = r->cons_tail;
    return cons_tail == prod_tail;
}

u32 fnp_ring_enqueue(fnp_ring_t* r, void* data);

u32 fnp_ring_enqueue_burst(fnp_ring_t* r, void* const * obj_table, u32 len);

u32 fnp_ring_dequeue(fnp_ring_t* r, void** data);

u32 fnp_ring_dequeue_burst(fnp_ring_t* r, void** obj_table, u32 len);

void* fnp_ring_top(fnp_ring_t* r, i32 offset);

#endif //FNP_FNP_PRING_H
