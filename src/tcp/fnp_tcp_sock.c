#include <unistd.h>
#include "fnp_tcp.h"
#include "fnp_init.h"
#include "fnp_tcp_ofo.h"

//enum tcp_state {
//    TCP_CLOSED, TCP_LISTEN, TCP_SYN_SENT, TCP_SYN_RECV,
//    TCP_ESTABLISHED, TCP_CLOSE_WAIT, TCP_LAST_ACK, TCP_FIN_WAIT_1,
//    TCP_FIN_WAIT_2, TCP_CLOSING, TCP_TIME_WAIT, TCP_STATE_END
//};

char* tcp_state_str[11] = {
    "TCP_CLOSED", "TCP_LISTEN", "TCP_SYN_SENT", "TCP_SYN_RECV",
    "TCP_ESTABLISHED", "TCP_CLOSE_WAIT", "TCP_LAST_ACK", "TCP_FIN_WAIT_1",
    "TCP_FIN_WAIT_2", "TCP_CLOSING", "TCP_TIME_WAIT",
};

void *fnp_tcp_sock(u32 lip, u16 lport, u32 rip, u16 rport)
{
    tcp_sock_t* sk = fnp_malloc(sizeof(tcp_sock_t));
    if(unlikely(sk == NULL))
        return NULL;

    sk->lip = lip;
    sk->lport = lport;
    sk->rip = rip;
    sk->rport = rport;
    sk->iface = &conf.ifaces[0];
    if(unlikely(fnp_lookup_hash(conf.tcpSockTbl, &sk->key, NULL)))
    {
        printf("socket exits\n");
        fnp_free(sk);
        return NULL;
    }

    sk->txbuf = fnp_alloc_ring(100 * 1024);
    if(unlikely(sk->txbuf == NULL))
    {
        fnp_free(sk);
        return NULL;
    }

    sk->rxbuf = fnp_alloc_ring(100 * 1024);
    if(unlikely(sk->rxbuf == NULL))
    {
        fnp_free_ring(sk->txbuf);
        fnp_free(sk);
        return NULL;
    }

    sem_init(&sk->sem, 1, 0);
    sk->ofo_head = tcp_malloc_ofo_seg();
    if(sk->ofo_head == NULL) {
        fnp_free_ring(sk->txbuf);
        fnp_free_ring(sk->rxbuf);
        fnp_free(sk);
        return NULL;
    }

    sk->parent = NULL;
    sk->state = TCP_CLOSED;
    sk->iss = time(NULL);
    sk->snd_una = sk->iss;
    sk->snd_nxt = sk->iss;
    sk->snd_max = sk->iss;
    sk->adv_wnd = 1024*10;
    sk->cwnd = 2;           //2个mss
    sk->dup_ack = 0;
    sk->max_snd_wnd = 0;
    sk->rcv_wnd = 1024 * 10;
    for(int i = 0; i < TCPT_NTIMERS; i++)
        rte_timer_init(&sk->timers[i]);

    if(unlikely(fnp_add_hash(conf.tcpSockTbl, &sk->key, sk)))
    {
        fnp_free(sk->ofo_head);
        fnp_free_ring(sk->txbuf);
        fnp_free_ring(sk->rxbuf);
        fnp_free(sk);
    }

    return sk;
}

void tcp_free_sock(void* sock) {
    tcp_sock_t* sk = (tcp_sock_t*) sock;

    fnp_del_hash(conf.tcpSockTbl, &sk->key);
    tcp_free_ofo_seg(sk->ofo_head);
    fnp_free_ring(sk->txbuf);
    fnp_free_ring(sk->rxbuf);
    fnp_free(sk);
}

