#include "tcp_api.h"

u32 fnp_ipv4_ston(const char* ip)
{
    if (ip == NULL)
        return 0;
    struct in_addr addr;
    inet_aton(ip, &addr);

    return addr.s_addr;
}

void fnp_ipv4_ntos(u32 ip)
{
    u8 seg1 = ip & 0xff;
    u8 seg2 = (ip >> 8) & 0xff;
    u8 seg3 = (ip >> 16) & 0xff;
    u8 seg4 = (ip >> 24) & 0xff;
    printf("%u.%u.%u.%u\n",seg1,seg2,seg3,seg4);
}


void* fnp_sock_param2(char* lip, uint16_t lport, char* rip, uint16_t rport) {
    sock_param* param = fnp_malloc(sizeof(sock_param));
    param->lip = fnp_ipv4_ston(lip);
    param->lport = fnp_swap_16(lport);
    param->rip = fnp_ipv4_ston(rip);
    param->rport = fnp_swap_16(rport);

    return param;
}

void* fnp_sock_param(uint32_t lip, uint16_t lport, uint32_t rip, uint16_t rport) {
    sock_param* param = fnp_malloc(sizeof(sock_param));
    param->lip = lip;
    param->lport = lport;
    param->rip = rip;
    param->rport = rport;

    return param;
}



void* fnp_tcp_bind(void* param) {
    if(unlikely(hash_lookup(fnp.tcpTbl, param, NULL)))
    {
        printf("socket exits\n");
        return NULL;
    }

    return tcp_bind_sock(param);
}

void* fnp_tcp_listen(void* param) {
    if(unlikely(hash_lookup(fnp.tcpTbl, param, NULL)))
    {
        printf("socket exits\n");
        return NULL;
    }

    return tcp_listen((sock_param*) param);
}

void* fnp_tcp_connect(void* param) {
    if(unlikely(hash_lookup(fnp.tcpTbl, param, NULL)))
    {
        printf("socket exits\n");
        return NULL;
    }

    return tcp_connect((sock_param*)param);
}

void* fnp_tcp_accept(void* sk) {
    return tcp_accept((tcp_sock*)sk);
}

int fnp_tcp_send(void* sk, u8* buf, int len) {
    return tcp_send((tcp_sock*)sk, buf, len);
}

int fnp_tcp_recv(void* sk, u8* buf, int len) {
    return tcp_recv((tcp_sock*)sk, buf, len);
}

void fnp_tcp_close(void* sk) {
    tcp_close((tcp_sock*)sk);
}