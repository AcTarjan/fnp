#include "fnp_ring.h"
#include <rte_atomic.h>



fnp_ring* fnp_alloc_ring(i32 size)
{
    fnp_ring* fr = fnp_malloc(sizeof(fnp_ring));
    if(fr == NULL)
        return NULL;

    fr->size = size + 1;        //有一个空位不使用，用于判断队列是否满
    fr->head = fr->tail = 0;
    fr->buf = fnp_malloc(fr->size);
    if(fr->buf == NULL)
    {
        fnp_free(fr);
        return NULL;
    }

    return fr;
}

void fnp_free_ring(fnp_ring* fr)
{
    fnp_free(fr->buf);
    fnp_free(fr);
}

i32 fnp_ring_avail(fnp_ring* fr)
{
    return fr->size - 1 - fnp_ring_len(fr);
}

i32 fnp_ring_len(fnp_ring* fr)
{
    if (fr->tail >= fr->head)
        return fr->tail - fr->head;
    return fr->size + fr->tail - fr->head;
}

//only write data, don't amend fr->tail
i32 fnp_ring_prepush(fnp_ring* fr, i32 offset, u8* buf, i32 len)
{
    i32 copy = FNP_MIN(len, fnp_ring_avail(fr) - offset);
    if(copy <= 0)
        return 0;

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

i32 fnp_ring_push(fnp_ring* fr, u8* buf, i32 len)
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
    return copy;
}

i32 fnp_ring_pop(fnp_ring* fr, u8* buf, u32 len)
{
    i32 copy = FNP_MIN(len, fnp_ring_len(fr));

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

    return copy;
}

i32 fnp_ring_top(fnp_ring* fr, u8* buf, i32 offset, i32 len)
{
    i32 copy = FNP_MIN(len, fnp_ring_len(fr) - offset);
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
