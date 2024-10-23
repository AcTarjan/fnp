#include <unistd.h>
#include "tcp_sock.h"
#include "fnp_init.h"
#include "tcp_in.h"
#include "tcp_out.h"
#include "tcp_ofo.h"


char* tcp_state_str[11] = {
    "TCP_CLOSED", "TCP_LISTEN", "TCP_SYN_SENT", "TCP_SYN_RECV",
    "TCP_ESTABLISHED", "TCP_CLOSE_WAIT", "TCP_LAST_ACK", "TCP_FIN_WAIT_1",
    "TCP_FIN_WAIT_2", "TCP_CLOSING", "TCP_TIME_WAIT",
};


void tcp_closed_recv(tcp_sock* sk, tcp_segment* seg) {}
void tcp_closed_send(tcp_sock* sk) {
    if(sk->can_free)
        tcp_free_sock(sk);
}
void tcp_listen_send(tcp_sock* sk) {}

tcp_recv_func tcp_recv[TCP_STATE_END];
tcp_send_func tcp_send[TCP_STATE_END];

void tcp_register() {
    tcp_recv[TCP_CLOSED] = tcp_closed_recv;
    tcp_recv[TCP_LISTEN] = tcp_LISTEN_recv;
    tcp_recv[TCP_SYN_SENT] = tcp_SYN_SENT_recv;
    tcp_recv[TCP_SYN_RECV] = tcp_SYN_RECV_recv;
    tcp_recv[TCP_ESTABLISHED] = tcp_ESTAB_data;
    tcp_recv[TCP_CLOSE_WAIT] = tcp_ESTAB_data;
    tcp_recv[TCP_LAST_ACK] = tcp_ESTAB_data;
    tcp_recv[TCP_FIN_WAIT_1] = tcp_ESTAB_data;
    tcp_recv[TCP_FIN_WAIT_2] = tcp_ESTAB_data;
    tcp_recv[TCP_CLOSING] = tcp_ESTAB_data;
    tcp_recv[TCP_TIME_WAIT] = tcp_ESTAB_data;

    tcp_send[TCP_CLOSED] = tcp_closed_send;
    tcp_send[TCP_LISTEN] = tcp_listen_send;
    tcp_send[TCP_SYN_SENT] = tcp_syn_send;
    tcp_send[TCP_SYN_RECV] = tcp_syn_send;
    tcp_send[TCP_ESTABLISHED] = tcp_data_send;
    tcp_send[TCP_CLOSE_WAIT] = tcp_data_send;
    tcp_send[TCP_LAST_ACK] = tcp_data_send;
    tcp_send[TCP_FIN_WAIT_1] = tcp_data_send;
    tcp_send[TCP_FIN_WAIT_2] = tcp_data_send;
    tcp_send[TCP_CLOSING] = tcp_data_send;
    tcp_send[TCP_TIME_WAIT] = tcp_data_send;
}

i32 tcp_init() {
    fnp.tcpTbl = hash_create("TcpSocketTable",1024, sizeof(sock_param));
    if(fnp.tcpTbl == NULL) {
        printf( "alloc tcp sock table error!\n");
        return -1;
    }

    tcp_register();

    return 0;
}

void* tcp_bind(sock_param* param)
{
    tcp_sock* sk = fnp_malloc(sizeof(tcp_sock));
    if(unlikely(sk == NULL))
        return NULL;

    sk->param = param;
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

    if(unlikely(!hash_add(fnp.tcpTbl, param, sk)))
    {
        fnp_ring_free(sk->txbuf);
        fnp_ring_free(sk->rxbuf);
        fnp_free(sk);
        return NULL;
    }

    return sk;
}

// socket释放的时机：
// 被用户使用的socket，需要由用户主动释放，但最终还是在协议栈中释放
// 没有被用户使用的socket，由协议栈自动释放
void tcp_free_sock(void* sock) {
    tcp_sock* sk = (tcp_sock*) sock;
    hash_del(fnp.tcpTbl, sk->param);
    fnp_free(sk->param);

    if(tcp_state(sk) == TCP_LISTEN) {
        fnp_pring_free(sk->accept);
        fnp_free(sk);
        return;
    }

    fnp_ring_free(sk->txbuf);
    fnp_ring_free(sk->rxbuf);
    fnp_free(sk);
}

void* tcp_listen(sock_param* param) {
    tcp_sock* sock = fnp_malloc(sizeof(tcp_sock));
    tcp_set_state(sock, TCP_LISTEN);
    sock->accept = fnp_pring_alloc(TCP_LISTEN_BACKLOG);
    if(sock->accept == NULL) {
        fnp_free(sock);
        return NULL;
    }

    sock->param = param;

    if(!hash_add(fnp.tcpTbl, param, sock))
    {
        fnp_pring_free(sock->accept);
        fnp_free(sock);
        return NULL;
    }

    return sock;
}


void* tcp_connect(sock_param* param)
{
    tcp_sock* sk = tcp_bind(param);
    if (sk == NULL)
        return NULL;

    sk->user_req |= TCP_USER_CONNECT;

    /* wait to establish completely */
    while (1) {
        i32 state = tcp_state(sk);
        if(state == TCP_ESTABLISHED)
            return sk;
        if (state == TCP_CLOSED)        //connect failed
            return NULL;
    }
}

static inline bool tcp_still_send(tcp_sock *sk) {
    u32 state = tcp_state(sk);
    if (state == TCP_ESTABLISHED || state == TCP_CLOSE_WAIT) {
        return true;
    }
    return false;
}


i32 fnp_tcp_send(void* sock, u8* buf, i32 len)
{
    tcp_sock* sk = (tcp_sock*) sock;
    if(tcp_still_send(sk)) {
        while (fnp_ring_avail(sk->txbuf) < len);
        return fnp_ring_push(sk->txbuf, buf, len);
    }
    else
        return 0;
}

static inline bool tcp_still_recv(tcp_sock* sk) {
    i32 state = tcp_state(sk);
    if(state == TCP_ESTABLISHED ||
       state == TCP_FIN_WAIT_1 ||
       state == TCP_FIN_WAIT_2 ) {  //可以接收数据
        return true;
    }

    if(fnp_ring_len(sk->rxbuf) > 0) {
        return true;
    }

    return false;
}


i32 fnp_tcp_recv(void* sock, u8* buf, i32 len)
{
    tcp_sock* sk = (tcp_sock*) sock;

    while (tcp_still_recv(sk)) {
        i32 ret = fnp_ring_pop(sk->rxbuf, buf, len);
        if(ret != 0) {
            return ret;
        }
    }

    return 0;
}

void fnp_tcp_close(void* sock)
{
    tcp_sock* sk = sock;
    i32 state = tcp_state(sk);

    if(state == TCP_CLOSED || state ==  TCP_SYN_SENT
       || state == TCP_LISTEN) {
        tcp_set_state(sk, TCP_CLOSED);
        tcp_free_sock(sk);
        return;
    }

    //wait for sending all data
    while (fnp_ring_len(sk->txbuf) > 0);

    sk->user_req |= TCP_USER_CLOSE;
}

void tcp_set_state(tcp_sock* sk, i32 state)
{
    i32 old_state = tcp_state(sk);
    sk->state = state;
    printf("state from %s to %s\n", tcp_state_str[old_state], tcp_state_str[state]);
}