#ifndef FNP_FNP_PRING_H
#define FNP_FNP_PRING_H

#include "fnp_common.h"

typedef struct fnp_pring
{
    i32 size;           /* size of buf */
    i32 head;
    i32 tail;
    void** data;
} fnp_pring;


fnp_pring* fnp_alloc_pring(i32 size);

bool fnp_pring_is_full(fnp_pring* ring);

bool fnp_pring_is_empty(fnp_pring* ring);

i32 fnp_pring_data_len(fnp_pring* fr);

i32 fnp_pring_free_len(fnp_pring* fr);

void fnp_free_pring(fnp_pring* ring);

bool fnp_pring_enqueue(fnp_pring* ring, void* data);

bool fnp_pring_dequeue(fnp_pring* ring, void** data);

i32 fnp_pring_enqueue_bulk(fnp_pring* ring, void** data, i32 len);

i32 fnp_pring_dequeue_bulk(fnp_pring* ring, void** data, i32 len);

#endif //FNP_FNP_PRING_H
