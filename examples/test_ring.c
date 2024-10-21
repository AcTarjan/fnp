#include "fnp_pring.h"

void test_pring() {
    fnp_pring* r = fnp_pring_alloc(1000);
    int test = 88;

    printf("test addr: %p\n", &test);
    int* p[20] = {};
    for(int i = 0; i < 20; i++)
        p[i] = &test;

    printf("%p %d\n", r, sizeof(*r));
    printf("%p\n", &r->buf);
    fnp_pring_enqueue(r, &test);

    int* pp[20] = {0};

    fnp_pring_dequeue(r, (void**)pp);
    for(int i = 0; i < 1; i++)
        printf("%p %d\n",pp[i], *pp[i]);
}


int main()
{

}