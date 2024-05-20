#include "fnp_ring.h"
#include <rte_atomic.h>

typedef struct fnp_ring
{
    i32 size;           /* size of buf */
    volatile i32 head;
    volatile i32 tail;
    rte_atomic32_t len;
    u8* buf;
} fnp_ring_t;

fnp_ring_t* fnp_alloc_ring(i32 size)
{
    fnp_ring_t* fr = fnp_malloc(sizeof(fnp_ring_t));
    if(fr == NULL)
        return NULL;

    rte_atomic32_init(&fr->len);
    fr->size = (size + 7) / 8 * 8;
    fr->head = fr->tail = 0;
    fr->buf = fnp_malloc(fr->size);
    if(fr->buf == NULL)
    {
        fnp_free(fr);
        return NULL;
    }

    return fr;
}

void fnp_free_ring(fnp_ring_t* fr)
{
    fnp_free(fr->buf);
    fnp_free(fr);
}

i32 fnp_ring_avail(fnp_ring_t* fr)
{
    i32 len = rte_atomic32_read(&fr->len);
    return fr->size - len;
}

i32 fnp_ring_len(fnp_ring_t* fr)
{
    i32 len = rte_atomic32_read(&fr->len);
    return len;
}

//only write data, don't amend fr->tail
i32 fnp_ring_pre_push(fnp_ring_t* fr, i32 offset, u8* buf, i32 len)
{
    i32 copy = FNP_MIN(len, fnp_ring_avail(fr) - offset);

    //real tail after offset
    i32 tail = (fr->tail + offset) % fr->size;
    if(likely(tail + copy <= fr->size))
        fnp_memcpy(fr->buf + tail, buf, copy);
    else
    {
        u32 first_copy = fr->size - tail;
        fnp_memcpy(fr->buf + tail, buf, first_copy);
        fnp_memcpy( fr->buf, buf + first_copy, copy - first_copy);
    }

    return copy;
}

i32 fnp_ring_push(fnp_ring_t* fr, u8* buf, i32 len)
{
    i32 copy = FNP_MIN(len, fnp_ring_avail(fr));

    if(buf != NULL) {
        if (likely(fr->tail + copy <= fr->size))
            fnp_memcpy(fr->buf + fr->tail, buf, copy);
        else {
            u32 first_copy = fr->size - fr->tail;
            fnp_memcpy(fr->buf + fr->tail, buf, first_copy);
            fnp_memcpy(fr->buf, buf + first_copy, copy - first_copy);
        }
    }

    fr->tail = (fr->tail + copy) % fr->size;
    rte_atomic32_add(&fr->len, copy);

    return copy;
}

i32 fnp_ring_pop(fnp_ring_t* fr, u8* buf, u32 len)
{
    i32 fr_len = rte_atomic32_read(&fr->len);
    i32 copy = FNP_MIN(len, fr_len);

    if(buf != NULL) {
        if (likely(fr->head + copy <= fr->size))
            fnp_memcpy(buf, fr->buf + fr->head, copy);
        else {
            u32 first_copy = fr->size - fr->head;
            fnp_memcpy(buf, fr->buf + fr->head, first_copy);
            fnp_memcpy(buf + first_copy, fr->buf, copy - first_copy);
        }
    }

    fr->head = (fr->head + copy) % fr->size;
    rte_atomic32_sub(&fr->len, copy);

    return copy;
}

i32 fnp_ring_top(fnp_ring_t* fr, u8* buf, i32 offset, i32 len)
{
    i32 fr_len = rte_atomic32_read(&fr->len);
    i32 copy = FNP_MIN(len, fr_len - offset);
    if(copy <= 0)
        return 0;

    i32 new_head = (fr->head + offset) % fr->size;
    if(likely(new_head + copy <= fr->size))
        fnp_memcpy(buf, fr->buf + new_head, copy);
    else
    {
        u32 first_copy = fr->size - new_head;
        fnp_memcpy(buf, fr->buf + new_head, first_copy);
        fnp_memcpy(buf + first_copy, fr->buf ,copy - first_copy);
    }

    return copy;
}

i32 fnp_ring_enqueue_bulk(fnp_ring_t* fr, void* obj, i32 len)
{
    return fnp_ring_push(fr, obj, sizeof(obj) * len) / sizeof(obj);
}

i32 fnp_ring_dequeue_bulk(fnp_ring_t* ur, void** obj, i32 len)
{
    return fnp_ring_pop(ur, obj, sizeof(obj) * len) / sizeof(obj);
}

i32 fnp_ring_top_queue(fnp_ring_t* fr, void** obj)
{
    return fnp_ring_top(fr, obj, 0, sizeof(obj)) / sizeof(obj);
}