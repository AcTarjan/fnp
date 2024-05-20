#include <stdio.h>
#include "fnp_ring.h"
#include "../inc/fnps.h"


int main(void)
{
    fnp_init(NULL);

    u32 lip = fnp_ipv4_ston("192.168.222.66");
    u32 lport = fnp_swap_16(28888);
    void* sock = fnp_tcp_listen(lip, lport);
    void* conn = fnp_tcp_accept(sock);

    FILE *file;  // 文件指针

    // 打开文件（如果不存在则创建）
    if ((file = fopen("tcp_recv.txt", "wb")) == NULL) {
        printf("Error opening file.\n");
        return ;
    }

    u8 buf[2000];
    u64 count = 0;
    while (1) {
        i32 ret = fnp_tcp_recv(conn, buf, 1024);
        count += ret;
        if(ret == 0) {
            printf("recv end: %llu\n", count);
            fclose(file);
            break;
        }
        i32 w = fwrite(buf, 1, ret, file);
        if(w != ret) {
            printf("write error\n");
        }

//        rte_delay_us_sleep(10000);
        i32 send_ret = fnp_tcp_send(conn, buf, ret);
        if(ret != w || ret != send_ret) {
            printf("error!!!!\n");
        }
        printf("count: %llu \n", count);
//        rte_delay_us_sleep(1000);
    }

    fnp_tcp_close(conn);
    fnp_tcp_close(sock);

    return 0;
}
