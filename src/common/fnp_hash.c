#include "fnp_hash.h"

#include <string.h>

#define HASH_BUCKET_ENTRIES         8

typedef struct hash_node
{
    struct hash_node* next;
    u8* key;
    void* value;
} hash_node_t;

typedef struct fnp_hash
{
    i32 entries;               /**< Total table entries. */
    i16 key_len;
    hash_node_t** lists;
    i32 min_index;
} fnp_hash_t;

fnp_hash_t* fnp_alloc_hash(i32 entries, i16 key_len)
{
    fnp_hash_t* h = fnp_malloc(sizeof(fnp_hash_t));
    if(unlikely(h == NULL))
    {
        return NULL;
    }

    h->lists = fnp_zmalloc(entries * sizeof(hash_node_t*));
    if(unlikely(h->lists == NULL))
    {
        fnp_free(h);
        return NULL;
    }

    h->entries = entries;
    h->key_len = key_len;
    h->min_index = entries;
    return h;
}

void fnp_free_hash(fnp_hash_t* h)
{
    for(i32 i = 0; i < h->entries; ++i)
    {
        hash_node_t* cur = h->lists[i];
        while (cur != NULL)
        {
            hash_node_t* next = cur->next;
            fnp_free(cur->key);
            fnp_free(cur);
            cur = next;
        }
    }

    fnp_free(h->lists);
    fnp_free(h);
}

u32 hash_func(u8* key, i16 len)
{
    u32 val = 0;
    for(i32 i = 0; i < len; ++i)
    {
        val += key[i];
    }

    return val;
}

i32 fnp_lookup_hash(fnp_hash_t *h, void *key, void **value)
{
    i32 index = hash_func(key, h->key_len) % h->entries;
    h->min_index = FNP_MIN(index, h->min_index);
    hash_node_t* cur = h->lists[index];
    while (cur != NULL)
    {
        if(memcmp(key, cur->key, h->key_len) == 0)
        {
            if(value != NULL)
                *value = cur->value;
            return 1;
        }
        cur = cur->next;
    }

    return 0;
}

i32 fnp_add_hash(fnp_hash_t *h, void* key, void* value)
{
    i32 index = hash_func(key, h->key_len) % h->entries;
    hash_node_t* cur = h->lists[index];
    while (cur != NULL)
    {
        if(memcmp(key, cur->key, h->key_len) == 0)
        {
            cur->value = value;
            return 0;
        }
        cur = cur->next;
    }

    hash_node_t* node = fnp_malloc(sizeof(hash_node_t));
    if(unlikely(node == NULL))
        return 1;

    node->key = fnp_malloc(h->key_len);
    if(unlikely(node->key == NULL))
    {
        fnp_free(node);
        return 1;
    }
    memcpy(node->key, key, h->key_len);
    node->value = value;
    node->next = h->lists[index];

    h->lists[index] = node;
    return 0;
}

void fnp_del_hash(fnp_hash_t* h, void* key)
{
    i32 index = hash_func(key, h->key_len) % h->entries;
    hash_node_t* cur = h->lists[index];
    hash_node_t* prev = NULL;
    while (cur != NULL)
    {
        if(memcmp(key, cur->key, h->key_len) == 0)
        {
            if(prev == NULL)
                h->lists[index] = cur->next;
            else
                prev->next = cur->next;

            fnp_free(cur->key);
            fnp_free(cur);
            return;
        }
        prev = cur;
        cur = cur->next;
    }
}

i32 fnp_hash_iterate(fnp_hash_t *h, void **key, void **data, i32* next)
{
    for(i32 i = *next; i < h->entries; i++) {
        if(h->lists[i] != NULL) {
            *key = h->lists[i]->key;
            *data = h->lists[i]->value;
            *next = i+1;
            return 1;
        }
    }
    return 0;
}