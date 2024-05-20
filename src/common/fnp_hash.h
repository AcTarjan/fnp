#ifndef FNP_HASH_H
#define FNP_HASH_H

#include "fnp_common.h"

struct fnp_hash;
typedef struct fnp_hash fnp_hash_t;

struct fnp_hash* fnp_alloc_hash(i32 entries, i16 key_len);

void fnp_free_hash(struct fnp_hash* h);

i32 fnp_lookup_hash(fnp_hash_t *h, void *key, void **value);

i32 fnp_add_hash(fnp_hash_t *h, void* key, void* value);

void fnp_del_hash(struct fnp_hash* h, void* key);

i32 fnp_hash_iterate(fnp_hash_t *h, void **key, void **data, i32* next);

#endif //FNP_HASH_H
