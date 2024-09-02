#include "fnp_ring.h"
#include <pthread.h>
#include <unistd.h>

fnp_ring_t* r;

void* enqueue() {
    int size = 100;
    int index = 0;
    int** arr = fnp_malloc(8 * size);


    while (1)
    {
        for (int i = 0; i < size; ++i) {
            arr[i] = fnp_malloc(4);
            *arr[i] = index++;
        }
        int num = 0;
        while (num < size)
        {
            num += fnp_ring_enqueue(r, arr[num]);
        }

    }
}


int main()
{
    r = fnp_alloc_ring(2048);
    printf("%p", r);
    pthread_t thread;
    pthread_create(&thread, NULL, enqueue, NULL);

    int* arr[100];

    int next = 0;
    while (1) {
        int num = fnp_ring_dequeue_bulk(r, &arr, 100);
        for (int i = 0; i < num; ++i) {
            int now = *arr[i];
            printf("now: %d ", now);
            if(now != next) {
                printf("\n error!!!!\n");
                break;
            }
            fnp_free(arr[i]);
            next++;
        }
        printf("\n");
        fflush(stdout);
        sleep(1);
    }
}