#include "fnp_pring.h"

fnp_pring* fnp_pring_alloc(i32 size) {
    fnp_pring* r = fnp_malloc(sizeof(fnp_pring) + size * sizeof(void*));
    if (r == NULL)
        return NULL;
    r->size = size;
    r->head = r->tail = 0;
    return r;
}

bool fnp_pring_enqueue(fnp_pring* r, void* data) {
    if (fnp_pring_avail(r) == 0)
        return false;

    r->buf[r->tail] = data;

    // 插入数据会导致tail下标越界，越界处理：越界了就回到开始位置
    r->tail = (r->tail + 1) % r->size;
    return true;
}

bool fnp_pring_dequeue(fnp_pring* r, void** data) {
    if (fnp_pring_len(r) == 0)
        return false;

    *data = r->buf[r->head];

    // 删除数据会导致head下标越界，越界处理：越界了就回到开始位置
    r->head = (r->head + 1) % r->size;
    return true;
}

i32 fnp_pring_enqueue_bulk(fnp_pring* r, void* data[], i32 len) {
    i32 copy = FNP_MIN(len, fnp_pring_avail(r));

    if(r->tail + copy <= r->size) {
        fnp_memcpy(r->buf + r->tail, data, copy * sizeof(void*));
    } else {
        i32 first = r->size - r->tail;
        fnp_memcpy(r->buf + r->tail, data, first * sizeof(void*));
        fnp_memcpy(r->buf, data + first, (copy - first) * sizeof(void*));
    }

    r->tail = (r->tail + copy) % r->size;
    return copy;
}

i32 fnp_pring_dequeue_bulk(fnp_pring* r, void* data[], i32 len) {
    i32 copy = FNP_MIN(len, fnp_pring_len(r));

    if(r->head + copy <= r->size) {
        fnp_memcpy(data, r->buf + r->head, copy * sizeof(void*));
    } else {
        i32 first = r->size - r->head;
        fnp_memcpy(data, r->buf + r->head, first * sizeof(void*));
        fnp_memcpy(data + first, r->buf, (copy - first) * sizeof(void*));
    }
    r->head = (r->head + copy) % r->size;
    return copy;
}

//only read data, don't amend r->head
void* fnp_pring_top(fnp_pring* r, i32 offset)
{
    if (offset >= fnp_pring_avail(r))
        return NULL;

    i32 index = (r->head + offset) % r->size;
    return r->buf[index];
}