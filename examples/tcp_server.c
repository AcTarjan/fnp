#include <stdio.h>
#include "fnp_ring.h"
#include "../inc/fnp.h"

void* process(void* conn) {
    FILE *file;  // 文件指针
    pthread_t pid = pthread_self();
    // 打开文件（如果不存在则创建）
    char filename[100];
    sprintf(filename, "dpdk-%lu.dat", pid);
    if ((file = fopen(filename, "wb")) == NULL) {
        printf("%lu fail to open file.\n", pid);
        return NULL;
    }

    u8 buf[2000];
    u64 count = 0;
    printf("%lu start to recv data...\n", pid);
    while (1) {
        i32 ret = fnp_tcp_recv(conn, buf, 1024);
        count += ret;
        if(ret == 0) {
            printf("%lu finish to recv: %llu\n",pid, count);
            break;
        }

        i32 w = fwrite(buf, 1, ret, file);
        if(w != ret) {
            printf("%lu write error\n", pid);
            break;
        }

        i32 send_ret = fnp_tcp_send(conn, buf, ret);
        if(ret != w || ret != send_ret) {
            printf("%lu send error! %d\n", pid, send_ret);
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
    fnp_init(NULL);

    u32 lip = fnp_ipv4_ston("192.168.11.66");
    u32 lport = fnp_swap_16(18888);
    void* sock = fnp_tcp_listen(lip, lport);

    while (1) {
        void *conn = fnp_tcp_accept(sock);
        pthread_t pthread;
        pthread_create(&pthread, NULL, process, conn);
        printf("pthread %lu process a new conn\n", pthread);
    }
}
