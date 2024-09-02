#include <unistd.h>
#include "fnp_tcp_sock.h"
#include "fnp_init.h"
#include "fnp_tcp_ofo.h"


char* tcp_state_str[11] = {
    "TCP_CLOSED", "TCP_LISTEN", "TCP_SYN_SENT", "TCP_SYN_RECV",
    "TCP_ESTABLISHED", "TCP_CLOSE_WAIT", "TCP_LAST_ACK", "TCP_FIN_WAIT_1",
    "TCP_FIN_WAIT_2", "TCP_CLOSING", "TCP_TIME_WAIT",
};

void* fnp_tcp_sock(u32 lip, u16 lport, u32 rip, u16 rport)
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

void* fnp_tcp_listen(u32 lip, u16 lport) {
    tcp_sock_t* sk = fnp_tcp_sock(lip, lport, 0, 0);
    sk->accept = fnp_alloc_ring(64);
    if(sk->accept == NULL) {
        printf("fail to alloc accept ring");
        tcp_free_sock(sk);
        return NULL;
    }
    tcp_set_state(sk, TCP_LISTEN);
    return sk;
}

void* fnp_tcp_accept(void* sock) {
    tcp_sock_t* sk = (tcp_sock_t*) sock;
    i32 state = tcp_state(sk);
    if(state != TCP_LISTEN)
        return NULL;

    tcp_sock_t* conn = NULL;
    while (fnp_ring_dequeue(sk->accept, (void**)&conn) == 0);

    return conn;
}

i32 fnp_tcp_connect(void* sock)
{
    tcp_sock_t* sk = (tcp_sock_t*) sock;
    i32 state = tcp_state(sk);

    if(state != TCP_CLOSED)
        return 1;

    tcp_set_state(sk, TCP_SYN_SENT);

    /* wait to establish completely */
    while (1) {
        state = tcp_state(sk);
        if(state == TCP_ESTABLISHED)
            return 0;
        if (state == TCP_CLOSED)        //connect failed
            return 1;
    }
}

i32 fnp_tcp_send(void* sock, u8* buf, i32 len)
{
    tcp_sock_t* sk = (tcp_sock_t*) sock;
    if(tcp_can_send(sk))
        return fnp_ring_push(sk->txbuf, buf, len);
    else
        return 0;
}

i32 fnp_tcp_recv(void* sock, u8* buf, i32 len)
{
    tcp_sock_t* sk = (tcp_sock_t*) sock;

    while (tcp_can_recv(sk)) {
        i32 ret = fnp_ring_pop(sk->rxbuf, buf, len);
        if(ret != 0)
            return ret;
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

    while (fnp_ring_len(sk->txbuf) != 0) ;      //wait for sending all data
    if(state == TCP_CLOSE_WAIT)
        tcp_set_state(sk, TCP_LAST_ACK);
    else
        tcp_set_state(sk, TCP_FIN_WAIT_1);

    while (tcp_state(sk) != TCP_CLOSED) ;   //wait for closing completely
    tcp_free_sock(sk);
}
