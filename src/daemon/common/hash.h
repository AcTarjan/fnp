#ifndef FNP_HASH_H
#define FNP_HASH_H

#include "rte_hash.h"

typedef struct rte_hash rte_hash;

rte_hash *hash_create(char *name, uint32_t entries, uint32_t key_len);

void hash_free(rte_hash *h);

bool hash_add(rte_hash *h, void *key, void *data);

bool hash_lookup(rte_hash *h, void *key, void **data);

bool hash_del(rte_hash *h, void *key);

bool hash_iterate(rte_hash *h, void **key, void **data, uint32_t *next);

#endif // FNP_HASH_H
