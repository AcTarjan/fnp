#include "hash.h"
#include "rte_jhash.h"


rte_hash* hash_create(char* name, uint32_t entries, uint32_t key_len) {
    unsigned int id = rte_socket_id();
    struct rte_hash_parameters params = {
        .name = name,
        .entries = entries,
        .key_len = key_len,
        .hash_func = rte_jhash,
//        .hash_func_init_val = 0,
        .socket_id = id,
    };
    return rte_hash_create(&params);
}


void hash_free(rte_hash* h) {
    rte_hash_free(h);
}

bool hash_add(rte_hash* h, void* key, void* data) {
    return rte_hash_add_key_data(h, key, data) == 0;
}

bool hash_lookup(rte_hash* h, void* key, void** data) {

    return rte_hash_lookup_data(h, key, data) >= 0;
}

bool hash_del(rte_hash* h, void* key) {
    return rte_hash_del_key(h, key) >= 0;
}

bool hash_iterate(rte_hash* h, void* key, void** data, uint32_t* next) {
    return rte_hash_iterate(h, key, data, next) >= 0;
}
