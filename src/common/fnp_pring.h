#ifndef FNP_FNP_PRING_H
#define FNP_FNP_PRING_H

#include "fnp_common.h"

#include <stdatomic.h>

typedef struct fnp_pring
{
    rte_atomic32_t ref_count;
    u32 size; // size of buf
    u32 mask; // size - 1, size must be power of 2
    u32 is_mp : 1; //是否多生产者
    u32 is_mc : 1; //是否多消费者
    volatile atomic_uint prod_head;
    volatile atomic_uint prod_tail; //实际的生产者指针
    volatile atomic_uint cons_head;
    volatile atomic_uint cons_tail; //实际的生产者指针

    /* 注意这里有4字节的padding, sizeof(fnp_pring) = 16 */
    void* buf[0]; // buf 8字节对齐
} fnp_pring_t;


fnp_pring_t* fnp_pring_create(i32 size, bool is_mp, bool is_mc);

static inline fnp_pring_t* fnp_pring_clone(fnp_pring_t* r)
{
    if (r == NULL)
        return NULL;
    rte_atomic32_add(&r->ref_count, 1);
    return r;
}

static inline void fnp_pring_free(fnp_pring_t* r)
{
    if (r == NULL)
        return;
    rte_atomic32_dec(&r->ref_count);
    if (rte_atomic32_read(&r->ref_count) == 0)
        fnp_free(r);
}

static inline i32 fnp_pring_empty(fnp_pring_t* r)
{
    uint32_t prod_tail = r->prod_tail;
    uint32_t cons_tail = r->cons_tail;
    return cons_tail == prod_tail;
}

u32 fnp_pring_enqueue(fnp_pring_t* r, void* data);

u32 fnp_pring_enqueue_burst(fnp_pring_t* r, void* const * obj_table, u32 len);

u32 fnp_pring_dequeue(fnp_pring_t* r, void** data);

u32 fnp_pring_dequeue_burst(fnp_pring_t* r, void** obj_table, u32 len);

void* fnp_pring_top(fnp_pring_t* r, i32 offset);

#endif //FNP_FNP_PRING_H
