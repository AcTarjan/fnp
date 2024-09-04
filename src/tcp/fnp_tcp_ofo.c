#include "inc/fnp_tcp_ofo.h"
#include "inc/fnp_tcp_comm.h"

typedef struct tcp_ofo_segment {
    struct tcp_ofo_segment* next;
    u32 seq;
    i32 len;
    //data stores in sk.rx_buf by pre_push
} tcp_ofo_seg;

struct tcp_ofo_segment* tcp_malloc_ofo_seg() {
    tcp_ofo_seg* seg = fnp_malloc(sizeof(tcp_ofo_seg));
    seg->next = NULL;
    return seg;
}

void tcp_free_ofo_seg(struct tcp_ofo_segment* seg) {
    tcp_ofo_seg* now = seg;
    tcp_ofo_seg* next;
    while (now != NULL) {
        next = now->next;
        fnp_free(now);
        now = next;
    }
}

void tcp_ofo_insert(struct tcp_ofo_segment* head, u32* seq, i32* len) {
    tcp_ofo_seg* last = head;
    tcp_ofo_seg* now = last->next;
    while (now != NULL) {
        //seq_end < now.seq  在now的前面
        if(SEQ_LT(*seq + *len - 1, now->seq)) {
            tcp_ofo_seg* seg = fnp_malloc(sizeof(tcp_ofo_seg));
            seg->next = now;
            seg->seq = *seq;
            seg->len = *len;
            last->next = seg;
            return ;
        } else if(SEQ_LT(now->seq + now->len - 1, *seq)) {   //now.seq_end < seq 在now的后面
            last = now;
            now = now->next;
        } else {    //两个seg有交集
            if(SEQ_LE(*seq, now->seq)) {    //seq <= now.seq
                if(SEQ_LE(*seq + *len - 1, now->seq + now->len - 1)) {   // seq_end <= now.seq_end
                    *len = (i32)(now->seq - *seq);
                    now->seq = *seq;
                    now->len += *len;
                    return;
                } else {    //seq_end > now.seq_end
                    now->seq = *seq;
                    now->len = *len;
                }
            } else {    //seq > now.seq
                if(SEQ_GT(*seq + *len - 1, now->seq + now->len - 1)) {   //seq_end > now.seq_end
                    *len = (i32)(*seq - now->seq + *len - now->len);
                    *seq = now->seq + now->len;
                    now->len += *len;
                    return ;
                } else {
                    *len = 0;
                    return;
                }
            }
        }
    }

    tcp_ofo_seg* seg = fnp_malloc(sizeof(tcp_ofo_seg));
    seg->next = NULL;
    seg->seq = *seq;
    seg->len = *len;
    last->next = seg;
}

i32 tcp_ofo_top(struct tcp_ofo_segment* head, u32* rcv_nxt) {
    tcp_ofo_seg* top = head->next;
    if (top == NULL)
        return 0;

    //rcv_nxt < seq
    if(SEQ_LT(*rcv_nxt, top->seq)) {
        return 0;
    }

    head->next = top->next;
    if(SEQ_LT(*rcv_nxt, top->seq + top->len))
        *rcv_nxt = top->seq + top->len;
    fnp_free(top);
    return 1;
}

bool tcp_ofo_is_empty(struct tcp_ofo_segment* head) {
    return head->next == NULL;
}

void tcp_ofo_print(struct tcp_ofo_segment* head) {
    tcp_ofo_seg* now = head->next;
    while (now != NULL) {
        printf("tcp ofo seg: %u %d\n", now->seq, now->len);
        now = now->next;
    }
}