#include "tcp.h"
#include "tcp_comm.h"
#include "tcp_sock.h"
#include "tcp_in.h"
#include "tcp_out.h"
#include <rte_ip.h>

static tcp_recv_func tcp_recv[TCP_STATE_END];
static tcp_send_func tcp_send[TCP_STATE_END];

void tcp_register() {
    tcp_recv[TCP_CLOSED] = tcp_closed_recv;
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

    tcp_send[TCP_CLOSED] = tcp_closed_send;
    tcp_send[TCP_LISTEN] = tcp_listen_send;
    tcp_send[TCP_SYN_SENT] = tcp_syn_send;
    tcp_send[TCP_SYN_RECV] = tcp_syn_send;
    tcp_send[TCP_ESTABLISHED] = tcp_data_send;
    tcp_send[TCP_CLOSE_WAIT] = tcp_data_send;
    tcp_send[TCP_LAST_ACK] = tcp_data_send;
    tcp_send[TCP_FIN_WAIT_1] = tcp_data_send;
    tcp_send[TCP_FIN_WAIT_2] = tcp_data_send;
    tcp_send[TCP_CLOSING] = tcp_data_send;
    tcp_send[TCP_TIME_WAIT] = tcp_data_send;
}

static inline void tcp_decode_option(tcp_option* opt, u8* bytes, u8 len) {
    opt->mss = 0;
    opt->wnd_scale = 255;   //  不能为0, 用来区分没有窗口扩展和窗口扩展为0
    opt->permit_sack = false;

    u8 index = 0;
    while (index < len) {
        switch (bytes[index]) {
            case 0:         // EOL
                return;
            case 1: {         // NOP
                index++;
                break;
            }
            case 2: {         //MSS
                u16* mss = bytes + index + 2;
                opt->mss = fnp_swap_16(*mss);
                index += 4;
                break;
            }
            case 3: {  // Window Scale
                opt->wnd_scale = bytes[index + 2];
                index += 3;
                break;
            }
            case 4: {
                opt->permit_sack = true;
                index += 2;
                break;
            }
            default: {
                u8 olen = bytes[index + 1];
                index += olen;
            }
        }
    }
}

static inline void tcp_seg_init(rte_mbuf* m, tcp_segment* seg)
{
    struct rte_ipv4_hdr* ipv4Hdr = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr*);
    u8 ipv4_hdr_len = rte_ipv4_hdr_len(ipv4Hdr);
    struct rte_tcp_hdr* tcpHdr = (struct rte_tcp_hdr*) rte_pktmbuf_adj(m, ipv4_hdr_len);

    seg->iface_id = m->port;
    seg->rip = ipv4Hdr->src_addr;
    seg->lip = ipv4Hdr->dst_addr;
    seg->rport = tcpHdr->src_port;
    seg->lport = tcpHdr->dst_port;
    seg->flags = tcpHdr->tcp_flags;
    seg->hdr_len = tcpHdr->data_off >> 2;
    seg->seq = fnp_swap_32(tcpHdr->sent_seq);
    seg->ack = fnp_swap_32(tcpHdr->recv_ack);
    seg->rx_win = fnp_swap_16(tcpHdr->rx_win);
    seg->data_len = fnp_swap_16(ipv4Hdr->total_length) - ipv4_hdr_len - seg->hdr_len;

    if (seg_has_opt(seg)) {
        u8 *opt_bytes = rte_pktmbuf_mtod_offset(m, u8*, TCP_HDR_MIN_LEN);
        tcp_decode_option(&seg->opt, opt_bytes, seg->hdr_len - TCP_HDR_MIN_LEN);
    }

    seg->data = rte_pktmbuf_adj(m, seg->hdr_len);
}

// 可以将连接置为CLOSED状态, 但不能tcp_free_sock释放资源, 由用户调用tcp_free_sock释放资源
void tcp_recv_mbuf(rte_mbuf* m)
{
    tcp_sock* sk = NULL;
    tcp_segment seg;
    tcp_seg_init(m, &seg);

    if(unlikely(!tcp_lookup_sock(&seg, &sk) ||
        tcp_state(sk) == TCP_CLOSED)) {  //没有该连接
        printf("can't find socket\n");
        if(!seg_set_rst(&seg))     //不是RST包
            tcp_send_rst(&seg);
        fnp_mbuf_free(m);
        return ;
    }

    //不同的状态具有不同的处理函数, 避免使用switch-case
    tcp_recv[tcp_state(sk)](sk, &seg);
    fnp_mbuf_free(m);
}

static inline void tcp_handle_user_req(tcp_sock* sk) {
    // 处理用户调用
    if (sk->user_req & TCP_USER_CLOSE) {
        sk->user_req &= ~TCP_USER_CLOSE;
        if(tcp_state(sk) == TCP_CLOSE_WAIT)
            tcp_set_state(sk, TCP_LAST_ACK);
        else
            tcp_set_state(sk, TCP_FIN_WAIT_1);
        sk->can_free = true;
    }

    if (sk->user_req & TCP_USER_CONNECT) {
        sk->user_req &= ~TCP_USER_CONNECT;
        tcp_set_state(sk, TCP_SYN_SENT);
    }

}

void tcp_output() {
    u8* key;  tcp_sock* sk; u32 next = 0; i32 state;
    while (hash_iterate(fnp.tcpTbl, &key, (void**)&sk, &next)) {
        state = tcp_state(sk);
        tcp_handle_user_req(sk);
        tcp_send[state](sk);
    }
}

i32 tcp_init() {
    fnp.tcpTbl = hash_create("TcpSocketTable",1024, sizeof(sock_param));
    if(fnp.tcpTbl == NULL) {
        printf( "alloc tcp sock table error!\n");
        return -1;
    }

    tcp_register();

    return 0;
}