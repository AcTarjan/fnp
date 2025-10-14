#include <unistd.h>

#include "tcp_ofo.h"
#include "tcp_in.h"

#include <rte_mbuf.h>
#include <rte_tcp.h>

#include "fnp_worker.h"


/* stream data 管理 */
int tcp_ofo_node_compare(void* l, void* r)
{
    /* Offset values are from 0 to 2^62-1, which means we are not worried with rollover */
    tcp_ofo_seg* lnode = l;
    tcp_ofo_seg* rnode = r;

    // return (int64_t)(lnode->offset - rnode->offset);
    return SEQ_LT(lnode->seq, rnode->seq);
}

picosplay_node_t* tcp_ofo_node_create(void* value)
{
    return &((tcp_ofo_seg*)value)->node;
}

void* tcp_ofo_node_value(picosplay_node_t* node)
{
    return (void*)((char*)node - offsetof(tcp_ofo_seg, node));
}

static void tcp_ofo_node_delete(void* tree, picosplay_node_t* node)
{
    // tcp_ofo_seg* ofo_seg = (tcp_ofo_seg*)tcp_ofo_node_value(node);
}

void tcp_ofo_tree_init(picosplay_tree_t* tree)
{
    picosplay_init_tree(tree, tcp_ofo_node_compare,
                        tcp_ofo_node_create, tcp_ofo_node_delete,
                        tcp_ofo_node_value);
}


tcp_ofo_seg* tcp_ofo_first_seg(tcp_sock_t* sock)
{
    picosplay_node_t* node = picosplay_first(&sock->ofo_tree);
    return tcp_ofo_node_value(node);
}

void tcp_ofo_enqueue_seg(tcp_sock_t* sock, tcp_ofo_seg* ofo_seg)
{
    picosplay_insert(&sock->ofo_tree, ofo_seg);
}

void tcp_ofo_dequeue_seg(tcp_sock_t* sock, tcp_ofo_seg* ofo_seg)
{
    picosplay_delete_hint(&sock->ofo_tree, &ofo_seg->node);
}

tcp_ofo_seg* tcp_ofo_init(tcp_segment* seg)
{
    struct rte_mbuf* m = clone_mbuf(seg->data);
    if (unlikely(m == NULL))
    {
        return NULL;
    }

    tcp_ofo_seg* ofo = (tcp_ofo_seg*)rte_mbuf_to_priv(m);
    ofo->data = m;
    ofo->flags = seg->flags;
    ofo->seq = seg->seq;
    ofo->end_seq = seg->seq + seg->data_len;

    return ofo;
}

void tcp_ofo_handle_seg(tcp_sock_t* sock)
{
    fsocket_t* socket = fsocket(sock);
    tcp_ofo_seg* seg = NULL;
    while (unlikely((seg = tcp_ofo_first_seg(sock)) != NULL))
    {
        if (SEQ_LT(sock->rcv_nxt, seg->seq))
        {
            return;
        }

        i32 cross_len = (i32)(sock->rcv_nxt - seg->seq);
        if (rte_pktmbuf_adj(seg->data, cross_len) == NULL)
        {
            tcp_ofo_dequeue_seg(sock, seg);
            continue;
        }

        if (unlikely(tcp_deliver_data_to_app(socket, seg->data) == 0))
        {
            return;
        }

        if (unlikely(seg->flags & RTE_TCP_FIN_FLAG))
            tcp_handle_fin(sock);

        tcp_ofo_dequeue_seg(sock, seg);
    }
}
