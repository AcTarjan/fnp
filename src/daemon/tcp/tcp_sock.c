#include "tcp_sock.h"

#include "fnp_context.h"
#include "fnp_worker.h"
#include "tcp_ofo.h"
#include "tcp_in.h"
#include "tcp_out.h"
#include "tcp_timer.h"

char* tcp_state_str[TCP_STATE_END] = {
    "TCP_NEW",
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
    "TCP_CLOSED",
};

static inline void tcp_close_sock(tcp_sock_t* sock)
{
    // TODO: tcp sock从当前worker的epoll删除，停止定时器，其它由master线程删除
    fsocket_t* socket = fsocket(sock);
    free_fsocket(socket);
}

void tcp_set_state(tcp_sock_t* sock, tcp_state_t state)
{
    tcp_state_t old_state = sock->state;
    sock->state = state;
    // FNP_INFO("%p: state from %s to %s\n", sock, tcp_state_str[old_state], tcp_state_str[state]);
    if (state == TCP_SYN_SENT || state == TCP_SYN_RECV)
    {
        // 发送SYN包
        tcp_send_syn(sock);
    }
    else if (state == TCP_LAST_ACK || state == TCP_FIN_WAIT_1)
    {
        // 发送FIN包
        tcp_send_fin(sock);
    }
    else if (state == TCP_CLOSED)
    {
        // 关闭socket
        tcp_close_sock(sock);
    }
}


void init_tcp_layer()
{
    tcp_send_init();

    tcp_recv_init();
}


tcp_sock_t* tcp_create_sock(fsockaddr_t* local, fsockaddr_t* remote, void* conf)
{
    tcp_sock_t* sock = fnp_zmalloc(sizeof(tcp_sock_t));
    if (sock == NULL)
        return NULL;

    if (remote == NULL || remote->ip == 0) //服务端socket
    {
        tcp_set_state(sock, TCP_LISTEN);
        return sock;
    }

    sock->state = TCP_NEW;
    sock->parent = NULL;
    sock->ipv4_ring = fnp_ring_create(1024 * 16, false, false);
    if (sock->ipv4_ring == NULL)
    {
        printf("Failed to create ipv4_ring ring\n");
        return NULL;
    }

    u64 tsc = fnp_get_tsc();
    init_congestion_algorithm(&sock->cc_algo, congestion_algo_cubic, tsc);

    sock->iss = time(NULL);
    sock->snd_una = sock->iss;
    sock->snd_nxt = sock->iss;
    sock->max_snd_wnd = 0;
    sock->mss = TCP_MSS;
    sock->rcv_wnd_scale = TCP_WS_SHIFT;
    sock->dup_ack = 0;
    tcp_ofo_tree_init(&sock->ofo_tree);
    sock->fin_sent = 0;

    //初始化定时器
    rte_timer_init(&sock->retransmit_timer);
    rte_timer_init(&sock->ack_timer);
    rte_timer_init(&sock->msl_timer);

    return sock;
}

// socket释放的时机：
// 被用户使用的socket，需要由用户主动释放，但最终还是在协议栈中释放
// 没有被用户使用的socket，由协议栈自动释放
void free_tcp_sock(tcp_sock_t* sock)
{
    // 停止定时器, 避免rte_timer_manager函数core
    tcp_stop_retransmit_timer(sock);
    tcp_stop_ack_timer(sock);
    tcp_stop_2msl_timer(sock);

    // 释放pending list中所有的rte_mbuf
    fnp_list_node_t* node = fnp_list_first(&sock->pending_list);
    while (node != NULL)
    {
        // 进入重传
        fnp_list_node_t* next = node->next;
        free_mbuf(node->value);
        node = next;
    }

    // 释放ofo tree中的所有rte_mbuf
    tcp_ofo_seg* seg = NULL;
    while ((seg = tcp_ofo_first_seg(sock)) != NULL)
    {
        tcp_ofo_dequeue_seg(sock, seg);
        free_mbuf(seg->data);
    }

    fnp_free(sock);
}

void tcp_handle_fsocket_event(fsocket_t* socket, u64 event)
{
    tcp_sock_t* sock = (tcp_sock_t*)socket;
    tcp_send(sock);
}
