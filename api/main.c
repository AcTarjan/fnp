#include <netinet/in.h>

#include "fnp_api.h"

int main()
{
    fnp_init();

    uint32_t ip = fnp_ipv4_ston("192.168.11.222");
    uint16_t port = htons(12345);
    void* socket = fnp_socket(IPPROTO_UDP, ip, port, 0, 0);

    int ret = fnp_bind(socket,0);
    if (ret < 0)
    {
        printf("bind failed: %d\n", ret);
        return -1;
    }



    while (1)
    {
        struct rte_mbuf* m = fnp_recv(socket);
        char* data = rte_pktmbuf_mtod(m, char*);
        int len = rte_pktmbuf_data_len(m);
        printf("recv %d: %s\n",len, data);
        rte_pktmbuf_free(m);
    }
}