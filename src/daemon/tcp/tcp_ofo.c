#include <unistd.h>

#include "tcp_ofo.h"

#include <rte_mbuf.h>

#define rb_to_ofo_seg(node) (tcp_ofo_seg *)(node)

tcp_ofo_seg* tcp_ofo_malloc(tcp_segment* seg)
{
    tcp_ofo_seg* ofo = (tcp_ofo_seg*)fnp_malloc(sizeof(tcp_ofo_seg));
    if (!ofo)
    {
        return NULL;
    }

    ofo->node.right = ofo->node.left = NULL;
    ofo->node.parent_and_color = 0;
    ofo->seq = seg->seq;
    ofo->end_seq = seg->seq + seg->data_len;
    ofo->flags = seg->flags;
    ofo->data = seg->data;

    return ofo;
}

void tcp_ofo_free(tcp_ofo_seg* seg)
{
    rte_pktmbuf_free(seg->data);
    fnp_free(seg);
}

// 前提条件 old.seq == new.seq
static inline void swap_ofo_seg(tcp_ofo_seg* old, tcp_ofo_seg* new)
{
    if (SEQ_GT(new->end_seq, old->end_seq))
    {
        // 包含该seg，替换该node，只替换数据
        old->end_seq = new->end_seq;
        old->flags |= new->flags;
        struct rte_mbuf* old_mbuf = old->data;
        old->data = new->data;

        new->data = old_mbuf;
        tcp_ofo_free(new); // 释放该乱序段
        return;
    }

    // new.end_seq <= old.end_seq
    old->flags |= new->flags; // 更新一下标记
    tcp_ofo_free(new); // 释放该乱序段
}

// 插入一个乱序报文段[seq,end_seq)
// 根据seq进行排序, 如果seq相同，则根据end_seq的大小进行替换
// 需要更新flags，避免FIN标记丢失
void tcp_ofo_enqueue(rb_tree* rbt, tcp_ofo_seg* seg)
{
    rb_node* node = &seg->node;
    rb_node* parent = NULL;
    rb_node** link = &rbt->root;
    u32 seq = seg->seq;
    u32 end_seq = seg->end_seq;

    // 红黑树为空
    if (!rbt->root)
    {
        rb_link_node(node, NULL, link);
        rbtree_insert(rbt, node);
        rbt->max = node;
        return;
    }

    tcp_ofo_seg* last = rb_to_ofo_seg(rbt->max);
    // 与最后一个比较, 避免遍历
    if (seq == last->seq)
    {
        swap_ofo_seg(last, seg);
        return;
    }

    if (SEQ_GT(seq, last->seq)) // 直接与最后一个比较，避免遍历
    {
        link = &rbt->max->right;
        parent = rbt->max;
        rbt->max = node; // 更新最大的
    }
    else
    {
        // 遍历找到插入位置
        while (*link)
        {
            parent = *link;
            tcp_ofo_seg* cur_seg = rb_to_ofo_seg(parent);
            if (SEQ_LT(seq, cur_seg->seq)) // seq < cur.seq
            {
                link = &parent->left;
            }
            else if (SEQ_GT(seq, cur_seg->seq)) // seq > cur.seq
            {
                link = &parent->right;
            }
            else
            {
                swap_ofo_seg(cur_seg, seg);
                return;
            }
        }
    }

    // 插入
    rb_link_node(node, parent, link);
    // 插入后调整红黑树
    rbtree_insert(rbt, &seg->node);
}

u8 tcp_ofo_dequeue(tcp_sock_t* sock)
{
    fsocket_t* socket = &sock->socket;
    rb_tree* rbt = &sock->ofo_root;
    tcp_ofo_seg* seg = NULL;
    rb_node* node = rb_first(rbt);
    u32 rcv_nxt = sock->rcv_nxt;
    u8 flags = 0;
    while (node != NULL)
    {
        seg = rb_to_ofo_seg(node);
        // rcv_nxt < seg->seq, 说明还是乱序
        if (SEQ_LT(rcv_nxt, seg->seq))
        {
            break;
        }

        rb_node* next = rb_next(node);
        rb_erase(rbt, node);
        node = next;
        flags |= seg->flags;

        // seq <= rcv_nxt < end_seq，存在未提交的数据
        if (SEQ_LT(rcv_nxt, seg->end_seq))
        {
            // 去掉重复的数据
            // 更新rcv_nxt
            // FNP_INFO("update rcv_nxt from %u to %u\n", rcv_nxt, seg->end_seq);

            u32 cross_seq = rcv_nxt - seg->seq; // 检查是否有重复数据
            rte_pktmbuf_adj(seg->data, cross_seq);
            if (fnp_pring_enqueue(socket->rx, seg->data) != 0) // 传递给应用层
            {
                fnp_free(seg);
                FNP_ERR("enqueue ofo data error!!!\n");
                break;
            }
            rcv_nxt = seg->end_seq; // 此时更新
            fnp_free(seg); // 不能释放seg中的data
        }
        else // rcv_nxt >= end_seq, 已经全部提交到应用层了，直接释放。
        {
            tcp_ofo_free(seg);
        }
    }

    // 更新sock的rcv_nxt
    sock->rcv_nxt = rcv_nxt;
    return flags;
}
