#include <unistd.h>

#include "tcp_ofo.h"
#include "tcp_comm.h"

#define rb_to_ofo_seg(node) (tcp_ofo_seg*)(node)

tcp_ofo_seg* tcp_ofo_malloc(u32 seq, u16 len, u8 flags) {
    tcp_ofo_seg* seg = (tcp_ofo_seg*)fnp_malloc(sizeof(tcp_ofo_seg));
    if(!seg) {
        return NULL;
    }

    seg->node.right = seg->node.left = NULL;
    seg->node.parent_and_color = 0;
    seg->seq = seq;
    seg->end_seq = seq + len;
    seg->flags = flags;
    return seg;
}

// 插入一个报文段
u32 tcp_ofo_enqueue(rb_tree* rbt, tcp_ofo_seg* seg)
{
    rb_node* node = &seg->node;
    rb_node* parent = NULL;
    rb_node** link = &rbt->root;
    u32 seq = seg->seq;
    u32 end_seq = seg->end_seq;
    u32 ret = seg->seq;

    //红黑树为空
    if(!rbt->root) {
        rb_link_node(node, NULL, link);
        rbt->max = node;
        rbtree_insert(rbt, node);
        return seg->seq;
    }

    //尝试与最后一个合并
    tcp_ofo_seg* last = rb_to_ofo_seg(rbt->max);
    if(SEQ_GE(seq, last->seq) && SEQ_LE(seq, last->end_seq)) {
        u32 tmp = last->end_seq;
        if (SEQ_GT(end_seq, last->end_seq)) {
            last->end_seq = end_seq;
        }

        last->flags |= seg->flags;
        fnp_free(seg);
        return tmp;
    }

    //与最后一个比较, 避免遍历
    if(SEQ_GT(seq, last->end_seq)) {
        link = &rbt->max->right;
        parent = rbt->max;
        goto insert;
    }

    //找到插入位置
    while (*link) {
        parent = *link;
        tcp_ofo_seg* cur_seg = rb_to_ofo_seg(parent);

        //seq < cur->seq
        if(SEQ_LT(seq, cur_seg->seq)) {
            link = &parent->left;
            continue;
        }

        //cur->seq <= seq <= cur->end_seq
        if(SEQ_LE(seq, cur_seg->end_seq)) {
            //end_seq <= cur->end_seq, cur完全包含node
            if(SEQ_LE(end_seq, cur_seg->end_seq)) {
                cur_seg->flags |= seg->flags;
                fnp_free(seg);
                return end_seq;
            }

            //end_seq > cur->end_seq, node包含cur或者部分包含cur
            ret = cur_seg->end_seq;     //从这开始拷贝
            cur_seg->end_seq = end_seq;
            cur_seg->flags |= seg->flags;
            fnp_free(seg);

            //将cur_node替换为node
            node = &cur_seg->node;
            seg = rb_to_ofo_seg(node);
            seq = seg->seq;
            end_seq = seg->end_seq;
            goto merge_right;
        }
        link = &parent->right;
    }

    insert:
    //插入, 没有修改parent的孩子指针, 指向node
    rb_link_node(node, parent, link);
    //插入后调整红黑树
    rbtree_insert(rbt, &seg->node);

    //向右合并
    merge_right:
    tcp_ofo_seg* next_seg = NULL;
    /* Remove other segments covered by skb. */
    while ((next_seg = rb_to_ofo_seg(rb_next(node))) != NULL) {
        if (SEQ_LT(end_seq, next_seg->seq))
            break;
        if (SEQ_LE(end_seq, next_seg->end_seq)) {
            next_seg->seq = seq;
            next_seg->flags |= seg->flags;

            //可以合并, 删掉seg，而不是next_seg，因为next_seg可能是最后一个，删掉后max为空
            rb_erase(rbt, &seg->node);
            fnp_free(seg);
            break;
        }

        // seg 完全包含 next_seg
        rb_erase(rbt, &next_seg->node);
        fnp_free(next_seg);
    }
    /* seg后没有报文段了, seg是最后一个报文段! */
    if (!next_seg)
        rbt->max = node;
    return ret;
}

u8 tcp_ofo_dequeue(rb_tree* rbt, u32* rcv_nxt)
{
    tcp_ofo_seg* seg = NULL;
    rb_node* node = rb_first(rbt);
    u8 flags = 0;

    while(node != NULL) {
        seg = rb_to_ofo_seg(node);
        // rcv_nxt < seg->seq, 说明还是乱序
        if(SEQ_LT(*rcv_nxt, seg->seq)) {
            break;
        }

        if(SEQ_LE(*rcv_nxt, seg->end_seq)) {
            *rcv_nxt = seg->end_seq;
            flags = seg->flags;

            rb_erase(rbt, node);
            fnp_free(seg);
            return flags;
        }

        rb_node* next = rb_next(node);
        rb_erase(rbt, node);
        fnp_free(seg);
        node = next;
    }

    return flags;
}
