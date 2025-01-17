#include <unistd.h>
#include "tcp_sock.h"
#include "fnp_init.h"
#include "tcp_ofo.h"


char* tcp_state_str[11] = {
    "TCP_CLOSED", "TCP_LISTEN", "TCP_SYN_SENT", "TCP_SYN_RECV",
    "TCP_ESTABLISHED", "TCP_CLOSE_WAIT", "TCP_LAST_ACK", "TCP_FIN_WAIT_1",
    "TCP_FIN_WAIT_2", "TCP_CLOSING", "TCP_TIME_WAIT",
};

void tcp_set_state(tcp_sock_t* sk, i32 state)
{
    i32 old_state = tcp_state(sk);
    sk->state = state;
    printf("state from %s to %s\n", tcp_state_str[old_state], tcp_state_str[state]);
}

tcp_sock_t* tcp_sock_ipv4(ipv4_5tuple_t* key)
{
    tcp_sock_t* sk = fnp_malloc(sizeof(tcp_sock_t));
    if(unlikely(sk == NULL))
        return NULL;

    sock_t* sock = &sk->sock;
    rte_memcpy(&sock->key, key, sizeof(ipv4_5tuple_t));
    sk->user_req = 0;
    sk->iface = fnp_iface_get(0);
    sk->can_free = true;

    sk->txbuf = fnp_ring_alloc(TCP_TXBUF_SIZE);
    if(unlikely(sk->txbuf == NULL))
    {
        fnp_free(sk);
        return NULL;
    }

    sk->rxbuf = fnp_ring_alloc(TCP_RXBUF_SIZE);
    if(unlikely(sk->rxbuf == NULL))
    {
        fnp_ring_free(sk->txbuf);
        fnp_free(sk);
        return NULL;
    }

    sk->parent = NULL;
    sk->state = TCP_CLOSED;
    sk->iss = time(NULL);
    sk->snd_una = sk->iss;
    sk->snd_nxt = sk->iss;
    sk->snd_max = sk->iss;
    sk->mss = TCP_MSS;
    sk->rcv_wnd_scale = TCP_WS_SHIFT;
    sk->cwnd = 2;           //2个mss
    sk->dup_ack = 0;
    sk->ofo_root.root = sk->ofo_root.max = NULL;
    sk->max_snd_wnd = 0;
    for(int i = 0; i < TCPT_NTIMERS; i++)
        rte_timer_init(&sk->timers[i]);

    return sk;
}

//
// bool tcp_lookup_sock(tcp_segment* cb, tcp_sock_t** sk)
// {
//     sock_param param = {cb->lip, cb->rip, cb->lport, cb->rport};
//     if(unlikely(!hash_lookup(fnp.tcpTbl, &param, (void**)sk)))
//     {
//         param.rip = 0;
//         param.rport = 0;
//         return hash_lookup(fnp.tcpTbl, &param, (void**)sk);
//     }
//
//     return true;
// }

// socket释放的时机：
// 被用户使用的socket，需要由用户主动释放，但最终还是在协议栈中释放
// 没有被用户使用的socket，由协议栈自动释放
void tcp_free_sock(tcp_sock_t* sk) {
    if(tcp_state(sk) == TCP_LISTEN) {
        fnp_pring_free(sk->accept);
        fnp_free(sk);
        return;
    }

    fnp_ring_free(sk->txbuf);
    fnp_ring_free(sk->rxbuf);
    fnp_free(sk);
}

