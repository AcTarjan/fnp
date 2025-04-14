#include "tcp_sock.h"

#include "fnp_context.h"
#include "tcp_ofo.h"

char *tcp_state_str[11] = {
    "TCP_CLOSED",
    "TCP_LISTEN",
    "TCP_SYN_SENT",
    "TCP_SYN_RECV",
    "TCP_ESTABLISHED",
    "TCP_CLOSE_WAIT",
    "TCP_LAST_ACK",
    "TCP_FIN_WAIT_1",
    "TCP_FIN_WAIT_2",
    "TCP_CLOSING",
    "TCP_TIME_WAIT",
};

void tcp_set_state(tcp_sock_t *sock, i32 state)
{
    i32 old_state = sock->state;
    sock->state = state;
    FNP_INFO("%s: state from %s to %s\n", sock->socket.name,
             tcp_state_str[old_state], tcp_state_str[state]);
}

tcp_sock_t *create_tcp_sock()
{
    tcp_sock_t *sock = fnp_zmalloc(sizeof(tcp_sock_t));
    if (sock == NULL)
        return NULL;

    sock->txbuf = fnp_pring_alloc(TCP_TXBUF_SIZE);
    if (unlikely(sock->txbuf == NULL))
    {
        fnp_free(sock);
        return -1;
    }

    sock->parent = NULL;
    sock->state = TCP_CLOSED;
    sock->iss = time(NULL);
    sock->tx_offset = 0;
    sock->snd_una = sock->iss;
    sock->snd_nxt = sock->iss;
    sock->snd_max = sock->iss;
    sock->mss = TCP_MSS;
    sock->rcv_wnd_scale = TCP_WS_SHIFT;
    sock->cwnd = 2; // 2个mss
    sock->dup_ack = 0;
    sock->ofo_root.root = sock->ofo_root.max = NULL;
    sock->max_snd_wnd = 0;
    sock->fin_sent = 0;
    for (int i = 0; i < TCPT_NTIMERS; i++)
        rte_timer_init(&sock->timers[i]);

    return sock;
}

// socket释放的时机：
// 被用户使用的socket，需要由用户主动释放，但最终还是在协议栈中释放
// 没有被用户使用的socket，由协议栈自动释放
void free_tcp_sock(tcp_sock_t *sock)
{
    // listen socket没有txbuf
    if (sock->txbuf != NULL)
        fnp_pring_free(sock->txbuf);

    fnp_free(sock);
}