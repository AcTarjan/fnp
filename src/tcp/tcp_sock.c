#include <unistd.h>
#include "tcp_sock.h"
#include "fnp_init.h"
#include "tcp_in.h"
#include "tcp_out.h"
#include "tcp_ofo.h"

fnp_hash_t* tcpSockTbl;

char* tcp_state_str[11] = {
    "TCP_CLOSED", "TCP_LISTEN", "TCP_SYN_SENT", "TCP_SYN_RECV",
    "TCP_ESTABLISHED", "TCP_CLOSE_WAIT", "TCP_LAST_ACK", "TCP_FIN_WAIT_1",
    "TCP_FIN_WAIT_2", "TCP_CLOSING", "TCP_TIME_WAIT",
};


i32 fnp_tcp_init() {
    tcpSockTbl = fnp_alloc_hash(1024, sizeof(tcp_sock_key_t));
    if(tcpSockTbl == NULL){
        printf( "alloc tcp sock table error!\n");
        return -1;
    }

    return 0;
}



void* fnp_tcp_sock(u32 id, u16 port, u32 rip, u16 rport)
{
    tcp_sock_t* sk = fnp_malloc(sizeof(tcp_sock_t));
    if(unlikely(sk == NULL))
        return NULL;

    sk->id = id;
    sk->port = port;
    sk->rip = rip;
    sk->rport = rport;
    sk->user_req = 0;
    if(unlikely(fnp_lookup_hash(tcpSockTbl, &sk->key, NULL)))
    {
        printf("socket exits\n");
        fnp_free(sk);
        return NULL;
    }

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

    if(unlikely(fnp_add_hash(tcpSockTbl, &sk->key, sk)))
    {
        fnp_ring_free(sk->txbuf);
        fnp_ring_free(sk->rxbuf);
        fnp_free(sk);
    }

    return sk;
}

i32 fnp_lookup_sock(tcp_sock_key_t* key, tcp_sock_t** sk) {
    return fnp_lookup_hash(tcpSockTbl, key, (void**)sk);
}

void tcp_free_sock(void* sock) {
    tcp_sock_t* sk = (tcp_sock_t*) sock;
    fnp_del_hash(tcpSockTbl, &sk->key);

    if(tcp_state(sk) == TCP_LISTEN) {
        fnp_pring_free(sk->accept);
        fnp_free(sk);
        return;
    }

    fnp_ring_free(sk->txbuf);
    fnp_ring_free(sk->rxbuf);
    fnp_free(sk);
}

void* fnp_tcp_listen(u16 id, u16 port) {
    tcp_sock_t* sock = fnp_malloc(sizeof(tcp_sock_t));
    tcp_set_state(sock, TCP_LISTEN);
    sock->accept = fnp_pring_alloc(TCP_LISTEN_BACKLOG);
    if(sock->accept == NULL) {
        fnp_free(sock);
        return NULL;
    }
    sock->id = id;
    sock->port = fnp_swap_16(port);
    sock->rip = 0;
    sock->rport = 0;

    if(fnp_add_hash(tcpSockTbl, &sock->key, sock))
    {
        fnp_pring_free(sock->accept);

        fnp_free(sock);
        return NULL;
    }

    return sock;
}


void* fnp_tcp_connect(u16 id, u16 port, u32 rip, u16 rport)
{
    tcp_sock_t* sk = fnp_tcp_sock(id, port, rip, rport);
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

i32 fnp_tcp_send(void* sock, u8* buf, i32 len)
{
    tcp_sock_t* sk = (tcp_sock_t*) sock;
    if(tcp_can_send(sk)) {
        while (fnp_ring_avail(sk->txbuf) < len);
        return fnp_ring_push(sk->txbuf, buf, len);
    }
    else
        return 0;
}

i32 fnp_tcp_recv(void* sock, u8* buf, i32 len)
{
    tcp_sock_t* sk = (tcp_sock_t*) sock;

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
    tcp_sock_t* sk = sock;
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

    while (tcp_state(sk) != TCP_CLOSED) ;   //wait for closing completely
    tcp_free_sock(sk);
}

void* fnp_tcp_accept(void* sock) {
    tcp_sock_t * sk = (tcp_sock_t *) sock;

    tcp_sock_t* conn = NULL;
    while (fnp_pring_dequeue(sk->accept, (void**)&conn) == 0);

    return conn;
}

void tcp_set_state(tcp_sock_t* sk, i32 state)
{
    i32 old_state = tcp_state(sk);
    sk->state = state;
    printf("state from %s to %s\n", tcp_state_str[old_state], tcp_state_str[state]);
    switch (state) {
        case TCP_LISTEN:
            sk->tcp_recv = tcp_listen_recv;
            break;
        case TCP_SYN_SENT:
            sk->tcp_recv = tcp_syn_sent_recv;
            sk->tcp_send = tcp_syn_send;
            break;
        case TCP_SYN_RECV:
            sk->tcp_recv = tcp_syn_recv_recv;
            sk->tcp_send = tcp_syn_send;
            break;
        default:
            sk->tcp_recv = tcp_data_recv;
            sk->tcp_send = tcp_data_send;
            break;
    }
}