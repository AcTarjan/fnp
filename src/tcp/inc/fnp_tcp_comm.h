#ifndef FNP_FNP_TCP_COMM_H
#define FNP_FNP_TCP_COMM_H

#define TCP_HDR_MIN_LEN             20
#define TCP_MAX_SEG_SIZE             1460


#define	TCPT_NTIMERS	5
#define	TCPT_REXMT	0		    /* retransmit */
#define	TCPT_PERSIST	1		/* retransmit persistance */
#define	TCPT_DELAY_ACK	2		/* delay ack */
#define	TCPT_KEEP	3	        /* keep alive */
#define	TCPT_2MSL	4		    /* 2*msl quiet time timer */

#define TCP_MIN_CWND            2
#define TCP_MAX_CWND            1024
#define TCP_THRESHOLD           32


#define seg_set_rst(seg)   ((seg)->flags & RTE_TCP_RST_FLAG)
#define seg_set_ack(seg)   ((seg)->flags & RTE_TCP_ACK_FLAG)
#define seg_set_syn(seg)   ((seg)->flags & RTE_TCP_SYN_FLAG)
#define seg_set_fin(seg)   ((seg)->flags & RTE_TCP_FIN_FLAG)
#define seg_set_urg(seg)   ((seg)->flags & RTE_TCP_URG_FLAG)
#define seg_set_psh(seg)   ((seg)->flags & RTE_TCP_PSH_FLAG)
#define seg_set_ece(seg)   ((seg)->flags & RTE_TCP_ECE_FLAG)
#define seg_set_cwr(seg)   ((seg)->flags & RTE_TCP_CWR_FLAG)

#define SEQ_LT(seq0, seq1)    ((int)((seq0) - (seq1)) < 0)
#define SEQ_LE(seq0, seq1)    ((int)((seq0) - (seq1)) <= 0)
#define SEQ_GT(seq0, seq1)    ((int)((seq0) - (seq1)) > 0)
#define SEQ_GE(seq0, seq1)    ((int)((seq0) - (seq1)) >= 0)



enum tcp_state {
    TCP_CLOSED, TCP_LISTEN, TCP_SYN_SENT, TCP_SYN_RECV,
    TCP_ESTABLISHED, TCP_CLOSE_WAIT, TCP_LAST_ACK, TCP_FIN_WAIT_1,
    TCP_FIN_WAIT_2, TCP_CLOSING, TCP_TIME_WAIT, TCP_STATE_END
};
extern char* tcp_state_str[11];


#endif //FNP_FNP_TCP_COMM_H
