#include "fnp_ring.h"
#include <rte_atomic.h>


fnp_ring* fnp_ring_alloc(i32 size)
{
    fnp_ring* r = fnp_malloc(sizeof(fnp_ring) + size);
    if(r == NULL)
        return NULL;

    r->size = size;        //有一个空位不使用，用于判断队列是否满
    r->head = r->tail = 0;

    return r;
}

i32 fnp_ring_prepush(fnp_ring* r, i32 offset, u8* buf, i32 len)
{
    i32 copy = FNP_MIN(len, fnp_ring_avail(r) - offset);
    if(copy <= 0)
        return 0;

    //real tail after offset
    i32 tail = (r->tail + offset) % r->size;
    if(tail + copy <= r->size)
        fnp_memcpy(r->buf + tail, buf, copy);
    else
    {
        u32 first_copy = r->size - tail;
        fnp_memcpy(r->buf + tail, buf, first_copy);
        fnp_memcpy(r->buf, buf + first_copy, copy - first_copy);
    }

    return copy;
}

i32 fnp_ring_push(fnp_ring* r, u8* buf, i32 len)
{
    i32 copy = FNP_MIN(len, fnp_ring_avail(r));
    if(copy <= 0)
        return 0;

    if(buf != NULL) {
        if (r->tail + copy <= r->size)
            fnp_memcpy(r->buf + r->tail, buf, copy);
        else {
            u32 first_copy = r->size - r->tail;
            fnp_memcpy(r->buf + r->tail, buf, first_copy);
            fnp_memcpy(r->buf, buf + first_copy, copy - first_copy);
        }
    }

    r->tail = (r->tail + copy) % r->size;
    return copy;
}

i32 fnp_ring_pop(fnp_ring* r, u8* buf, i32 len)
{
    i32 copy = FNP_MIN(len, fnp_ring_len(r));

    if(buf != NULL) {
        if (r->head + copy <= r->size)
            fnp_memcpy(buf, r->buf + r->head, copy);
        else {
            u32 first_copy = r->size - r->head;
            fnp_memcpy(buf, r->buf + r->head, first_copy);
            fnp_memcpy(buf + first_copy, r->buf, copy - first_copy);
        }
    }

    r->head = (r->head + copy) % r->size;

    return copy;
}

i32 fnp_ring_top(fnp_ring* r, u8* buf, i32 offset, i32 len)
{
    i32 copy = FNP_MIN(len, fnp_ring_len(r) - offset);
    if(copy <= 0)
        return 0;

    i32 new_head = (r->head + offset) % r->size;
    if(new_head + copy <= r->size)
        fnp_memcpy(buf, r->buf + new_head, copy);
    else
    {
        u32 first_copy = r->size - new_head;
        fnp_memcpy(buf, r->buf + new_head, first_copy);
        fnp_memcpy(buf + first_copy, r->buf , copy - first_copy);
    }

    return copy;
}
