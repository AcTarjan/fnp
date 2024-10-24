#include <stdio.h>
#define __USE_GNU
#include <pthread.h>
#include <sched.h>

#include "../inc/fnp.h"

#include "exp_common.h"

void set_pthread_affinity(int core_id)
{
    pthread_t tid = pthread_self();

    cpu_set_t cpu_mask;
    CPU_ZERO(&cpu_mask);    // 初始化set集，将set置为空
    CPU_SET(core_id, &cpu_mask);  //选择core_id
    int ret = pthread_setaffinity_np(tid, sizeof(cpu_set_t), &cpu_mask);
    if (ret != 0)
    {
        printf("fail to bind core\n");
    }

    cpu_set_t cpu_get;
    pthread_getaffinity_np(tid, sizeof(cpu_set_t), &cpu_get);
    if(CPU_ISSET(core_id, &cpu_get))
    {
        printf("pthread %lu set core %d successfully\n", tid, core_id);
    }
}

void* process(void* conn) {
    set_pthread_affinity(7);
    FILE *file;  // 文件指针
    pthread_t pid = pthread_self();
    // 打开文件（如果不存在则创建）
    char filename[100];
    sprintf(filename, "./output/dpdk-%lu.dat", pid);
    if ((file = fopen(filename, "wb")) == NULL) {
        printf("%lu fail to open file.\n", pid);
        return NULL;
    }

    uint8_t buf[2000];
    uint64_t last = 0;
    uint64_t count = 0;
    printf("%lu start to recv data...\n", pid);
    while (1) {
        int32_t ret = fnp_tcp_recv(conn, buf, 2000);
        count += ret;
        if(ret == 0) {
            printf("%lu finish to recv: %llu\n",pid, count);
            break;
        }
        if (count - last > 1000000) {
            showBw(count - last);
            last = count;
        }

        int32_t w = fwrite(buf, 1, ret, file);
        if(w != ret) {
            printf("%lu write error\n", pid);
            break;
        }

        int32_t send_ret = tcp_send(conn, buf, ret);
        if(ret != w || ret != send_ret) {
            printf("%lu send error! %d:%d\n", pid,ret, send_ret);
            break;
        }
    }
    printf("%lu start to close file\n", pid);
    fclose(file);
    printf("%lu start to close this conn\n", pid);
    fnp_tcp_close(conn);
    return NULL;
}

int main(void)
{
    fnp_init("fnp.yaml");

    void* param = fnp_sock_param2("192.168.11.222", 18888, NULL, 0);

    void* sock = fnp_tcp_listen(param);

    while (1) {
        void *conn = fnp_tcp_accept(sock);
        pthread_t pthread;
        pthread_create(&pthread, NULL, process, conn);
        printf("pthread %lu process a new conn\n", pthread);
    }
}
