#include <unistd.h>
#include "fnp_tcp.h"


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
    while (fnp_ring_dequeue(sk->accept, &conn) == 0)
        sleep(1);

    return conn;
}

i32 fnp_tcp_send(void* sock, u8* buf, i32 len)
{
    tcp_sock_t* sk = (tcp_sock_t*) sock;
    i32 state = tcp_state(sk);

    if(state == TCP_ESTABLISHED || state == TCP_CLOSE_WAIT)
        return fnp_ring_push(sk->txbuf, buf, len);
    else
        return 0;
}

i32 fnp_tcp_recv(void* sock, u8* buf, i32 len)
{
    tcp_sock_t* sk = (tcp_sock_t*) sock;

    while (1) {
        i32 ret = fnp_ring_pop(sk->rxbuf, buf, len);
        if(ret != 0)
            return ret;

        i32 state = tcp_state(sk);
        if(state != TCP_ESTABLISHED &&
        state != TCP_FIN_WAIT_1 &&
        state != TCP_FIN_WAIT_2)
            break;
    }

    return 0;
}

void fnp_tcp_connect(void* sock)
{
    tcp_sock_t* sk = (tcp_sock_t*) sock;
    i32 state = tcp_state(sk);

    if(state != TCP_CLOSED)
        return ;

    tcp_set_state(sk, TCP_SYN_SENT);

    /* wait to establish completely */
    sem_wait(&sk->sem);
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

    //wait to close
    sem_wait(&sk->sem);
}