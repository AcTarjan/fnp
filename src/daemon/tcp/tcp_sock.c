#include "tcp_sock.h"

#include "fnp_context.h"
#include "tcp_ofo.h"
#include "tcp_in.h"
#include "tcp_out.h"

char* tcp_state_str[11] = {
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

void tcp_set_state(tcp_sock_t* sock, tcp_state_t state)
{
    tcp_state_t old_state = sock->state;
    sock->state = state;
    FNP_INFO("%p: state from %s to %s\n", sock, tcp_state_str[old_state], tcp_state_str[state]);
}


static tcp_recv_func tcp_recv[TCP_STATE_END];
static tcp_send_func tcp_send[TCP_STATE_END];

void init_tcp_layer()
{
    tcp_recv[TCP_NEW] = tcp_closed_recv;
    tcp_recv[TCP_LISTEN] = tcp_listen_recv;
    tcp_recv[TCP_SYN_SENT] = tcp_synsent_recv;
    tcp_recv[TCP_SYN_RECV] = tcp_synrecv_recv;
    tcp_recv[TCP_ESTABLISHED] = tcp_estab_recv;
    tcp_recv[TCP_CLOSE_WAIT] = tcp_estab_recv;
    tcp_recv[TCP_LAST_ACK] = tcp_estab_recv;
    tcp_recv[TCP_FIN_WAIT_1] = tcp_estab_recv;
    tcp_recv[TCP_FIN_WAIT_2] = tcp_estab_recv;
    tcp_recv[TCP_CLOSING] = tcp_estab_recv;
    tcp_recv[TCP_TIME_WAIT] = tcp_estab_recv;
    tcp_recv[TCP_CLOSED] = tcp_closed_recv;

    tcp_send[TCP_NEW] = tcp_empty_send;
    tcp_send[TCP_LISTEN] = tcp_empty_send;
    tcp_send[TCP_SYN_SENT] = tcp_syn_send;
    tcp_send[TCP_SYN_RECV] = tcp_syn_send;
    tcp_send[TCP_ESTABLISHED] = tcp_data_send;
    tcp_send[TCP_CLOSE_WAIT] = tcp_data_send;
    tcp_send[TCP_LAST_ACK] = tcp_data_send;
    tcp_send[TCP_FIN_WAIT_1] = tcp_data_send;
    tcp_send[TCP_FIN_WAIT_2] = tcp_data_send;
    tcp_send[TCP_CLOSING] = tcp_data_send;
    tcp_send[TCP_TIME_WAIT] = tcp_data_send;
    tcp_send[TCP_CLOSED] = tcp_closed_send;
}


static void tcp_handler(tcp_sock_t* sock)
{
    // 处理用户请求
    fsocket_t* socket = fsocket(sock);
    if (socket->request_syn)
    {
        tcp_set_state(sock, TCP_SYN_SENT);
    }
    else if (socket->request_close)
    {
        //修改TCP的状态, 发送FIN
        if (tcp_get_state(sock) == TCP_CLOSE_WAIT)
            tcp_set_state(sock, TCP_LAST_ACK);
        else
            tcp_set_state(sock, TCP_FIN_WAIT_1);
    }

    struct rte_mbuf* mbufs[32];

    // 从应用层接收数据，放到缓存中
    if (tcp_get_state(sock) != TCP_LISTEN)
    {
        i32 avail = FNP_MIN(fnp_pring_avail(sock->txbuf), 32);
        u32 num = fnp_pring_dequeue_bulk(socket->tx, mbufs, avail);
        if (num > 0)
        {
            // mbuf融合，送进发送队列
            // printf("recv %d mbufs from app\n", num);
            fnp_pring_enqueue_bulk(sock->txbuf, mbufs, num);
        }
    }

    // 发送缓存中的TCP数据
    i32 state = tcp_get_state(sock);
    tcp_send[state](sock);
}


tcp_sock_t* tcp_create_sock(fsockaddr_t* local, fsockaddr_t* remote, void* conf)
{
    tcp_sock_t* sock = fnp_zmalloc(sizeof(tcp_sock_t));
    if (sock == NULL)
        return NULL;

    fsocket_t* socket = fsocket(sock);
    socket->handler = tcp_handler;
    if (remote == NULL) //服务端socket
    {
        tcp_set_state(sock, TCP_LISTEN);
        return sock;
    }

    sock->txbuf = fnp_pring_create(TCP_TXBUF_SIZE);
    if (unlikely(sock->txbuf == NULL))
    {
        fnp_free(sock);
        return NULL;
    }


    tcp_set_state(sock, TCP_NEW);
    sock->parent = NULL;
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
void free_tcp_sock(tcp_sock_t* sock)
{
    // listen socket没有txbuf
    if (sock->txbuf != NULL)
        fnp_pring_free(sock->txbuf);

    fnp_free(sock);
}
