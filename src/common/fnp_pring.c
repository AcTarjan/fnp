#include "fnp_pring.h"
#include <stdatomic.h>


fnp_pring_t* fnp_pring_create(i32 size, bool is_mp, bool is_mc)
{
    // size must be power of 2
    if (size < 2 || (size & (size - 1)) != 0)
    {
        return NULL; // size must be a power of 2 and at least 2
    }

    fnp_pring_t* r = fnp_malloc(sizeof(fnp_pring_t) + size * sizeof(void*));
    if (r == NULL)
        return NULL;

    rte_atomic32_set(&r->ref_count, 1);
    r->size = size;
    r->mask = size - 1; // mask is size - 1 to allow bitwise operations
    r->is_mp = is_mp;
    r->is_mc = is_mc;

    r->prod_head = 0;
    r->prod_tail = 0;
    r->cons_head = 0;
    r->cons_tail = 0;

    return r;
}


static __rte_always_inline void
__fnp_ring_update_tail(u32* tail, uint32_t old_val,
                       uint32_t new_val, bool is_mt)
{
    /*
     * If there are other enqueues/dequeues in progress that preceded us,
     * we need to wait for them to complete
     */
    if (is_mt)
        rte_wait_until_equal_32(tail, old_val,
                                memory_order_relaxed);

    atomic_store_explicit(tail, new_val, memory_order_release);
}


static __rte_always_inline u32 __fnp_ring_move_prod_head(fnp_pring_t* r, u32 n, u32* old_head, u32* new_head)
{
    const u32 capacity = r->mask;
    u32 free_entries;
    u32 cons_tail;
    u32 max = n;
    int success;

    *old_head = atomic_load_explicit(&r->prod_head, memory_order_relaxed);
    do
    {
        /* Reset n to the initial burst count */
        n = max;

        /* Ensure the head is read before tail */
        __atomic_thread_fence(memory_order_acquire);

        /* load-acquire synchronize with store-release of ht->tail
         * in update_tail.
         */
        cons_tail = atomic_load_explicit(&r->cons_tail, memory_order_acquire);

        /* The subtraction is done between two unsigned 32bits value
         * (the result is always modulo 32 bits even if we have
         * *old_head > cons_tail). So 'free_entries' is always between 0
         * and capacity (which is < size).
         */
        free_entries = (capacity + cons_tail - *old_head);

        /* check that we have enough room in ring */
        if (unlikely(n > free_entries))
            n = free_entries;

        if (n == 0)
            return 0;

        *new_head = *old_head + n;
        if (r->is_mp)
        {
            /* on failure, *old_head is updated */
            success = atomic_compare_exchange_strong_explicit(&r->prod_head,
                                                              old_head, *new_head,
                                                              memory_order_relaxed,
                                                              memory_order_relaxed);
        }
        else
        {
            r->prod_head = *new_head;
            success = 1;
        }
    }
    while (unlikely(success == 0));
    return n;
}

static __rte_always_inline void
__fnp_ring_enqueue_elems(fnp_pring_t* r, u32 prod_head,
                         const void* obj_table, uint32_t n)
{
    u32 i;
    const uint32_t size = r->size;
    uint32_t idx = prod_head & r->mask;
    uint64_t* ring = (uint64_t*)r->buf;
    const unaligned_uint64_t* obj = (const unaligned_uint64_t*)obj_table;
    if (likely(idx + n <= size))
    {
        for (i = 0; i < (n & ~0x3); i += 4, idx += 4)
        {
            ring[idx] = obj[i];
            ring[idx + 1] = obj[i + 1];
            ring[idx + 2] = obj[i + 2];
            ring[idx + 3] = obj[i + 3];
        }
        switch (n & 0x3)
        {
        case 3:
            ring[idx++] = obj[i++]; /* fallthrough */
        case 2:
            ring[idx++] = obj[i++]; /* fallthrough */
        case 1:
            ring[idx++] = obj[i++];
        }
    }
    else
    {
        for (i = 0; idx < size; i++, idx++)
            ring[idx] = obj[i];
        /* Start at the beginning */
        for (idx = 0; i < n; i++, idx++)
            ring[idx] = obj[i];
    }
}

static __rte_always_inline
unsigned int __fnp_ring_do_enqueue_elem(fnp_pring_t* r, const void* obj_table, u32 n)
{
    u32 prod_head, prod_next;

    n = __fnp_ring_move_prod_head(r, n, &prod_head, &prod_next);
    if (n != 0)
    {
        __fnp_ring_enqueue_elems(r, prod_head, obj_table, n);

        __fnp_ring_update_tail((u32*)(uintptr_t)&r->prod_tail, prod_head, prod_next, r->is_mp);
    }

    return n;
}


// 多生产者并发安全的环形队列入队
u32 fnp_pring_enqueue(fnp_pring_t* r, void* obj)
{
    return __fnp_ring_do_enqueue_elem(r, &obj, 1);
}

u32 fnp_pring_enqueue_burst(fnp_pring_t* r, void* const * obj_table, u32 len)
{
    return __fnp_ring_do_enqueue_elem(r, obj_table, len);
}


static __rte_always_inline u32
__fnp_ring_move_cons_head(fnp_pring_t* r, u32 n, u32* old_head, u32* new_head)
{
    unsigned int max = n;
    uint32_t prod_tail;
    u32 entries;
    int success;

    /* move cons.head atomically */
    *old_head = atomic_load_explicit(&r->cons_head, memory_order_relaxed);
    do
    {
        /* Restore n as it may change every loop */
        n = max;

        /* Ensure the head is read before tail */
        __atomic_thread_fence(memory_order_acquire);

        /* this load-acquire synchronize with store-release of ht->tail
         * in update_tail.
         */
        prod_tail = atomic_load_explicit(&r->prod_tail,
                                         memory_order_acquire);

        /* The subtraction is done between two unsigned 32bits value
         * (the result is always modulo 32 bits even if we have
         * cons_head > prod_tail). So 'entries' is always between 0
         * and size(ring)-1.
         */
        entries = (prod_tail - *old_head);

        /* Set the actual entries for dequeue */
        if (n > entries)
            n = entries;

        if (unlikely(n == 0))
            return 0;

        *new_head = *old_head + n;
        if (unlikely(r->is_mc))
        {
            /* on failure, *old_head will be updated */
            success = atomic_compare_exchange_strong_explicit(&r->cons_head,
                                                              old_head, *new_head,
                                                              memory_order_relaxed,
                                                              memory_order_relaxed);
        }
        else
        {
            r->cons_head = *new_head;
            success = 1;
        }
    }
    while (unlikely(success == 0));
    return n;
}

static __rte_always_inline void
__fnp_ring_dequeue_elems(fnp_pring_t* r, u32 cons_head, void* obj_table, u32 n)
{
    unsigned int i;
    const uint32_t size = r->size;
    uint32_t idx = cons_head & r->mask;
    uint64_t* ring = (uint64_t*)&r->buf;
    unaligned_uint64_t* obj = (unaligned_uint64_t*)obj_table;
    if (likely(idx + n <= size))
    {
        for (i = 0; i < (n & ~0x3); i += 4, idx += 4)
        {
            obj[i] = ring[idx];
            obj[i + 1] = ring[idx + 1];
            obj[i + 2] = ring[idx + 2];
            obj[i + 3] = ring[idx + 3];
        }
        switch (n & 0x3)
        {
        case 3:
            obj[i++] = ring[idx++]; /* fallthrough */
        case 2:
            obj[i++] = ring[idx++]; /* fallthrough */
        case 1:
            obj[i++] = ring[idx++]; /* fallthrough */
        }
    }
    else
    {
        for (i = 0; idx < size; i++, idx++)
            obj[i] = ring[idx];
        /* Start at the beginning */
        for (idx = 0; i < n; i++, idx++)
            obj[i] = ring[idx];
    }
}


static __rte_always_inline u32 __fnp_ring_do_dequeue_elem(fnp_pring_t* r, void* obj_table, u32 n)
{
    u32 cons_head, cons_next;

    n = __fnp_ring_move_cons_head(r, n, &cons_head, &cons_next);
    if (n != 0)
    {
        __fnp_ring_dequeue_elems(r, cons_head, obj_table, n);

        __fnp_ring_update_tail((u32*)(uintptr_t)&r->cons_tail, cons_head, cons_next, r->is_mc);
    }

    return n;
}

// 多生产者并发安全的环形队列入队
u32 fnp_pring_dequeue(fnp_pring_t* r, void** obj_p)
{
    return __fnp_ring_do_dequeue_elem(r, obj_p, 1);
}

u32 fnp_pring_dequeue_burst(fnp_pring_t* r, void** obj_table, u32 len)
{
    return __fnp_ring_do_dequeue_elem(r, obj_table, len);
}

//only read data, don't amend r->head
void* fnp_pring_top(fnp_pring_t* r, i32 offset)
{
    u32 index = (r->cons_tail + offset) & r->mask;
    return r->buf[index];
}
