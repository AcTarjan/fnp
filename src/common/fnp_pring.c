#include "fnp_pring.h"

fnp_pring* fnp_alloc_pring(i32 size) {
    fnp_pring* ring = fnp_malloc(sizeof(fnp_pring));
    ring->size = size;
    ring->head = ring->tail = 0;
    ring->data = fnp_malloc(sizeof(void*) * (size+1));
    return ring;
}


void fnp_free_pring(fnp_pring* ring) {
    fnp_free(ring->data);
    fnp_free(ring);
}

i32 fnp_pring_data_len(fnp_pring* fr) {
    if (fr->tail > fr->head) {
        return fr->tail - fr->head;
    } else {
        return fr->tail + fr->size + 1 - fr->head;
    }
}

i32 fnp_pring_free_len(fnp_pring* fr) {
    return fr->size - fnp_pring_data_len(fr);
}

bool fnp_pring_is_full(fnp_pring* ring) {
    return (ring->tail+1) % (ring->size+1) == ring->head;
}

bool fnp_pring_is_empty(fnp_pring* ring) {
    return ring->head == ring->tail;
}


bool fnp_pring_enqueue(fnp_pring* ring, void* data) {
    if (fnp_pring_is_full(ring))
        return false;

    ring->data[ring->tail] = data;
    ring->tail++;

    // 插入数据会导致tail下标越界，越界处理：越界了就回到开始位置
    ring->tail %= ring->size+1;
    return true;
}

bool fnp_pring_dequeue(fnp_pring* ring, void** data) {
    if (fnp_pring_is_empty(ring))
        return false;

    *data = ring->data[ring->head];
    ring->head++;

    // 删除数据会导致head下标越界，越界处理：越界了就回到开始位置
    ring->head %= ring->size+1;
    return true;
}

i32 fnp_pring_enqueue_bulk(fnp_pring* ring, void** data, i32 len) {
    i32 i = 0;
    for (i = 0; i < len; i++) {
        if (!fnp_pring_enqueue(ring, data[i]))
            break;
    }
    return i;
}

i32 fnp_pring_dequeue_bulk(fnp_pring* ring, void** data, i32 len) {
    i32 i = 0;
    for (i = 0; i < len; i++) {
        if (!fnp_pring_dequeue(ring, &data[i]))
            break;
    }
    return i;
}