#include "fnp_hash.h"

int main() {
    fnp_hash_t* h = fnp_alloc_hash(256, 4);
    int key = 10;
    int value = 100;
    int* p = &value;
    int ret = fnp_add_hash(h, &key, p);
    printf("add: %d\n", ret);
    int* pp = NULL;
    fnp_lookup_hash(h, &key, &pp);
    printf("%p %d\n", pp, *pp);
}