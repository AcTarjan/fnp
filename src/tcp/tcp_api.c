#include "tcp_api.h"

tcp_sock* tcp_listen(sock_param* param) {
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

tcp_sock* tcp_accept(tcp_sock* sk) {
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

tcp_sock* tcp_connect(sock_param* param)
{
    tcp_sock* sk = tcp_bind_sock(param);
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

i32 tcp_send(tcp_sock* sk, u8* buf, i32 len)
{
    u32 state = tcp_state(sk);


    if(state == TCP_ESTABLISHED || state == TCP_CLOSE_WAIT) {
        while (fnp_ring_avail(sk->txbuf) < len && tcp_state(sk) != TCP_CLOSED);
        return fnp_ring_push(sk->txbuf, buf, len);
    } else
        return 0;
}

static inline bool tcp_still_recv(tcp_sock* sk) {
    i32 state = tcp_state(sk);

    if(state == TCP_CLOSED)
        return false;

    if(state == TCP_ESTABLISHED ||
       state == TCP_FIN_WAIT_1 ||
       state == TCP_FIN_WAIT_2 ) {  //可以接收数据
        return true;
    }


    //接收到FIN，但是还有数据未接收
    if(fnp_ring_len(sk->rxbuf) > 0) {
        return true;
    }

    return false;
}


i32 tcp_recv(tcp_sock* sk, u8* buf, i32 len)
{

    while (tcp_still_recv(sk)) {
        i32 ret = fnp_ring_pop(sk->rxbuf, buf, len);
        if(ret != 0) {
            return ret;
        }
    }

    return 0;
}

void tcp_close(tcp_sock* sk)
{
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
