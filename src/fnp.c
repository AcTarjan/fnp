#include "tcp_sock.h"

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

    return tcp_bind(param);
}

void* fnp_tcp_listen(void* param) {
    if(unlikely(hash_lookup(fnp.tcpTbl, param, NULL)))
    {
        printf("socket exits\n");
        return NULL;
    }

    return tcp_listen(param);
}

void* fnp_tcp_connect(void* param) {
    if(unlikely(hash_lookup(fnp.tcpTbl, param, NULL)))
    {
        printf("socket exits\n");
        return NULL;
    }

    return tcp_connect(param);
}

void* fnp_tcp_accept(void* sock) {
    tcp_sock * sk = (tcp_sock *) sock;

    tcp_sock* conn = NULL;
    while (1) {
        if(fnp_pring_dequeue(sk->accept, (void**)&conn)) {
            if (tcp_state(conn) != TCP_CLOSED) {
                break;
            }
            sk->can_free = true;
        }
    }
    return conn;
}