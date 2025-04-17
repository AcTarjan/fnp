#ifndef QUIC_COMMON_H
#define QUIC_COMMON_H
/*
 * 包含quic常用的定义和结构体
 */

#include "picohash.h"
#include "fnp_splay.h"
#include "picoquic.h"
#include "picoquic_utils.h"
#include "fnp_socket.h"
#include "fnp_quic_common.h"


#ifndef PICOQUIC_MAX_PACKET_SIZE
#define PICOQUIC_MAX_PACKET_SIZE 1536
#endif
#define PICOQUIC_MIN_SEGMENT_SIZE 256
#define PICOQUIC_ENFORCED_INITIAL_MTU 1200
#define PICOQUIC_ENFORCED_INITIAL_CID_LENGTH 8
#define PICOQUIC_PRACTICAL_MAX_MTU 1440
#define PICOQUIC_MIN_STREAM_DATA_FRAGMENT 512
#define PICOQUIC_RETRY_SECRET_SIZE 64
#define PICOQUIC_RETRY_TOKEN_PAD_SIZE 26
#define PICOQUIC_DEFAULT_0RTT_WINDOW (10 * PICOQUIC_ENFORCED_INITIAL_MTU)
#define PICOQUIC_NB_PATH_TARGET 8
#define PICOQUIC_NB_PATH_DEFAULT 2
#define PICOQUIC_MAX_PACKETS_IN_POOL 0x2000
#define PICOQUIC_STORED_IP_MAX 16

#define PICOQUIC_INITIAL_RTT 250000ull                        /* 250 ms */
#define PICOQUIC_TARGET_RENO_RTT 100000ull                    /* 100 ms */
#define PICOQUIC_TARGET_SATELLITE_RTT 610000ull               /* 610 ms, practical maximum for non-pathological RTT */
#define PICOQUIC_INITIAL_RETRANSMIT_TIMER 250000ull           /* 250 ms */
#define PICOQUIC_INITIAL_MAX_RETRANSMIT_TIMER 1000000ull      /* one second */
#define PICOQUIC_LARGE_RETRANSMIT_TIMER 2000000ull            /* two seconds */
#define PICOQUIC_MIN_RETRANSMIT_TIMER 50000ull                /* 50 ms */
#define PICOQUIC_ACK_DELAY_MAX 10000ull                       /* 10 ms */
#define PICOQUIC_ACK_DELAY_MAX_DEFAULT 25000ull               /* 25 ms, per protocol spec */
#define PICOQUIC_ACK_DELAY_MIN 1000ull                        /* 1 ms */
#define PICOQUIC_ACK_DELAY_MIN_MAX_VALUE 0xFFFFFFull          /* max value that can be negotiated by peers */
#define PICOQUIC_RACK_DELAY 10000ull                          /* 10 ms */
#define PICOQUIC_MAX_ACK_DELAY_MAX_MS 0x4000ull               /* 2<14 ms */
#define PICOQUIC_TOKEN_DELAY_LONG (24 * 60 * 60 * 1000000ull) /* 24 hours */
#define PICOQUIC_TOKEN_DELAY_SHORT (2 * 60 * 1000000ull)      /* 2 minutes */
#define PICOQUIC_CID_REFRESH_DELAY (5 * 1000000ull)           /* if idle for 5 seconds, refresh the CID */
#define PICOQUIC_MTU_LOSS_THRESHOLD 10                        /* if threshold of full MTU packetlost, reset MTU */

#define PICOQUIC_BANDWIDTH_ESTIMATE_MAX 10000000000ull /* 10 GB per second */
#define PICOQUIC_BANDWIDTH_TIME_INTERVAL_MIN 1000
#define PICOQUIC_BANDWIDTH_MEDIUM 2000000 /* 16 Mbps, threshold for coalescing 10 packets per ACK with long delays */
#define PICOQUIC_MAX_BANDWIDTH_TIME_INTERVAL_MIN 1000
#define PICOQUIC_MAX_BANDWIDTH_TIME_INTERVAL_MAX 15000

#define PICOQUIC_SPURIOUS_RETRANSMIT_DELAY_MAX 1000000ull /* one second */
#define PICOQUIC_MICROSEC_SILENCE_MAX 120000000ull  /* 120 seconds for now */
#define PICOQUIC_MICROSEC_HANDSHAKE_MAX 30000000ull /* 30 seconds for now */
#define PICOQUIC_MICROSEC_WAIT_MAX 10000000ull      /* 10 seconds for now */

#define PICOQUIC_MICROSEC_STATELESS_RESET_INTERVAL_DEFAULT 100000ull /* max 10 stateless reset by second by default */

#define PICOQUIC_CWIN_INITIAL (10 * PICOQUIC_MAX_PACKET_SIZE)
#define PICOQUIC_CWIN_MINIMUM (2 * PICOQUIC_MAX_PACKET_SIZE)

#define PICOQUIC_PRIORITY_BYPASS_MAX_RATE 125000
#define PICOQUIC_PRIORITY_BYPASS_QUANTUM 2560

#define PICOQUIC_DEFAULT_CRYPTO_EPOCH_LENGTH (1 << 22)

#define PICOQUIC_DEFAULT_SIMULTANEOUS_LOGS 32
#define PICOQUIC_DEFAULT_HALF_OPEN_RETRY_THRESHOLD 64

#define PICOQUIC_PN_RANDOM_MIN 0xffff
#define PICOQUIC_PN_RANDOM_RANGE 0x10000

#define PICOQUIC_SPIN_RESERVE_MOD_256 17

#define PICOQUIC_CHALLENGE_REPEAT_MAX 3

#define PICOQUIC_ALPN_NUMBER_MAX 32

#define PICOQUIC_MAX_ACK_RANGE_REPEAT 4
#define PICOQUIC_MIN_ACK_RANGE_REPEAT 2

#define PICOQUIC_DEFAULT_HOLE_PERIOD 256


/*
 * Types of frames.
 */
typedef enum
{
    picoquic_frame_type_padding = 0x00,
    picoquic_frame_type_ping = 0x01,
    picoquic_frame_type_ack = 0x02,
    picoquic_frame_type_ack_ecn = 0x03,
    picoquic_frame_type_reset_stream = 0x04,
    picoquic_frame_type_stop_sending = 0x05,
    picoquic_frame_type_crypto_hs = 0x06,
    picoquic_frame_type_new_token = 0x07,
    picoquic_frame_type_stream_range_min = 0x08,
    picoquic_frame_type_stream_range_max = 0x0f,
    picoquic_frame_type_max_data = 0x10,
    picoquic_frame_type_max_stream_data = 0x11,
    picoquic_frame_type_max_streams_bidir = 0x12,
    picoquic_frame_type_max_streams_unidir = 0x13,
    picoquic_frame_type_data_blocked = 0x14,
    picoquic_frame_type_stream_data_blocked = 0x15,
    picoquic_frame_type_streams_blocked_bidir = 0x16,
    picoquic_frame_type_streams_blocked_unidir = 0x17,
    picoquic_frame_type_new_connection_id = 0x18,
    // picoquic_frame_type_path_new_connection_id = 0x15228c09,
    picoquic_frame_type_retire_connection_id = 0x19,
    // picoquic_frame_type_path_retire_connection_id = 0x15228c0a,
    picoquic_frame_type_path_challenge = 0x1a,
    picoquic_frame_type_path_response = 0x1b,
    picoquic_frame_type_connection_close = 0x1c,
    picoquic_frame_type_application_close = 0x1d,
    picoquic_frame_type_handshake_done = 0x1e
    //
    // picoquic_frame_type_datagram = 0x30,
    // picoquic_frame_type_datagram_l = 0x31,
    // picoquic_frame_type_ack_frequency = 0xAF,
    // picoquic_frame_type_immediate_ack = 0x1F,
    // picoquic_frame_type_time_stamp = 757,
    // picoquic_frame_type_path_ack = 0x15228c00,
    // picoquic_frame_type_path_ack_ecn = 0x15228c01,
    // picoquic_frame_type_path_abandon = 0x15228c05,
    // picoquic_frame_type_path_backup = 0x15228c07,
    // picoquic_frame_type_path_available = 0x15228c08,
    // picoquic_frame_type_bdp = 0xebd9,
    // picoquic_frame_type_max_path_id = 0x15228c0c,
    // picoquic_frame_type_paths_blocked = 0x15228c0d,
    // picoquic_frame_type_path_cid_blocked = 0x15228c0e,
    // picoquic_frame_type_observed_address_v4 = 0x9f81a6,
    // picoquic_frame_type_observed_address_v6 = 0x9f81a7
} picoquic_frame_type_enum_t;

/* PMTU discovery requirement status */
typedef enum
{
    picoquic_pmtu_discovery_not_needed = 0,
    picoquic_pmtu_discovery_optional,
    picoquic_pmtu_discovery_required
} picoquic_pmtu_discovery_status_enum;

/* Quic defines 4 epochs, which are used for managing the crypto contexts
 */
#define PICOQUIC_NUMBER_OF_EPOCHS 4
#define PICOQUIC_NUMBER_OF_EPOCH_OFFSETS (PICOQUIC_NUMBER_OF_EPOCHS + 1)

typedef enum
{
    picoquic_epoch_initial = 0,
    picoquic_epoch_0rtt = 1,
    picoquic_epoch_handshake = 2,
    picoquic_epoch_1rtt = 3
} picoquic_epoch_enum;

/*
 * Nominal packet types. These are the packet types used internally by the
 * implementation. The wire encoding depends on the version.
 */
typedef enum
{
    picoquic_packet_error = 0,
    picoquic_packet_version_negotiation,
    picoquic_packet_initial,
    picoquic_packet_retry,
    picoquic_packet_handshake,
    picoquic_packet_0rtt_protected,
    picoquic_packet_1rtt_protected,
    picoquic_packet_type_max
} picoquic_packet_type_enum;


/* Data structure used to hold chunk of stream data before in sequence delivery */
// 存储用户发送的流数据包和接收到的流数据包
typedef struct st_quic_stream_data_t
{
    picosplay_node_t stream_data_node;
    struct rte_mbuf* mbuf;
    struct st_quic_stream_data_t* next_stream_data;
    uint64_t stream_id;
    int fin : 1; //是否是fin数据包
    int enqueue_app : 1; //是否入队应用层, 应该由应用层释放
    uint64_t offset; //数据在流中的偏移量
    int length; //数据的长度
    uint8_t* bytes; //数据的起始位置
} quic_stream_data_t;

//
// /* Data structure used to hold chunk of stream data queued by application */
// typedef struct st_picoquic_stream_queue_node_t
// {
//     picoquic_quic_t* quic;
//     struct st_picoquic_stream_queue_node_t* next_stream_data;
//     uint64_t offset; /* Stream offset of the first octet in "bytes" */
//     size_t length; /* Number of octets in "bytes" */
//     uint8_t* bytes;
// } picoquic_stream_queue_node_t;

/*
 * The simple packet structure is used to store packets that
 * have been sent but are not yet acknowledged.
 * Packets are stored in unencrypted format.
 * The checksum length is the difference between encrypted and unencrypted.
 */

typedef struct st_quic_packet_t
{
    struct rte_mbuf* mbuf; //实际关联的mbuf, 仅包括QUIC Packet的payload数据
    struct st_quic_packet_t* packet_next;
    struct st_quic_packet_t* packet_previous;
    struct st_picoquic_path_t* send_path;
    picosplay_node_t queue_data_repeat_node;
    uint64_t sequence_number;
    uint64_t send_time;
    uint64_t delivered_prior;
    uint64_t delivered_time_prior;
    uint64_t delivered_sent_prior;
    uint64_t lost_prior;
    uint64_t inflight_prior;
    size_t data_repeat_frame;
    size_t data_repeat_index;

    int buf_size; // 可用的最大长度, checksum_overhead + header_length + payload_length
    int length; // 数据包的总长度, header_length + payload_length
    u8* bytes; // 数据包的实际存储, header + payload
    int checksum_overhead; // 数据包的校验和开销
    int header_length; // 数据包的头部长度

    /* Handling of data repeat queue requires sorting by priority,
     * stream_id, stream_offset, data_length
     */
    // uint64_t data_repeat_priority;
    // uint64_t data_repeat_stream_id;
    // uint64_t data_repeat_stream_offset;
    // size_t data_repeat_stream_data_length;


    // size_t offset;
    picoquic_packet_type_enum ptype;
    picoquic_packet_context_enum pc;
    unsigned int is_evaluated : 1;
    //即该包是否会促使对方发送 ACK（确认）帧。比如，包含数据或控制帧的包通常是 ACK-eliciting；而纯 ACK 包本身不是 ACK-eliciting。
    //这个标志用于判断是否需要对该包的发送进行丢包检测和重传。
    unsigned int is_ack_eliciting : 1;
    unsigned int is_mtu_probe : 1;
    unsigned int is_multipath_probe : 1;
    unsigned int is_ack_trap : 1; //表示该包是一个ACK陷阱包，该包的主要目的是用于诱发对方发送ack的数据包
    unsigned int delivered_app_limited : 1;
    unsigned int sent_cwin_limited : 1;
    // unsigned int is_preemptive_repeat : 1;
    // unsigned int was_preemptively_repeated : 1;
    unsigned int is_queued_to_path : 1;
    unsigned int is_queued_for_retransmit : 1;
    unsigned int is_queued_for_spurious_detection : 1;
    unsigned int is_queued_for_data_repeat : 1;
} quic_packet_t;

//
// static inline u8* quic_packet_get_data(quic_packet_t* packet, int offset)
// {
//     return rte_pktmbuf_mtod_offset(packet->mbuf, u8*, offset);
// }
//
// static inline int quic_packet_get_data_len(quic_packet_t* packet)
// {
//     return rte_pktmbuf_data_len(packet->mbuf);
// }
//
// static inline u8* quic_packet_get_data_tail(quic_packet_t* packet)
// {
//     int data_len = quic_packet_get_data_len(packet);
//     return rte_pktmbuf_mtod_offset(packet->mbuf, u8*, data_len);
// }
//
// static inline u8* quic_packet_get_data_max(quic_packet_t* packet)
// {
//     int data_max = packet->buf_size - packet->checksum_overhead - packet->header_length;
//     return rte_pktmbuf_mtod_offset(packet->mbuf, u8*, data_max);
// }
//
// static inline int quic_packet_get_packet_len(quic_packet_t* packet)
// {
//     return packet->header_length + rte_pktmbuf_data_len(packet->mbuf);
// }
//
// static inline int quic_packet_get_avail_len(quic_packet_t* packet)
// {
//     return packet->buf_size - quic_packet_get_packet_len(packet);
// }
//
// // 删除头部len字节的数据
// static inline void quic_packet_adj_data(quic_packet_t* packet, int len)
// {
//     rte_pktmbuf_adj(packet->mbuf, len);
// }
//
// // 在尾部添加len字节的数据
// static inline void quic_packet_append_data(quic_packet_t* packet, u8* data, int len)
// {
//     int buf_len = rte_pktmbuf_data_len(packet->mbuf);
//     u8* buf = rte_pktmbuf_mtod_offset(packet->mbuf, u8*, buf_len);
//     rte_memcpy(buf, data, len);
//     rte_pktmbuf_append(packet->mbuf, len);
// }


/*
 * Frame queue. This is used for miscellaneous packets. It is also used for
 * various tests, allowing for fault injection.
 *
 * misc_frame（杂项帧）在 QUIC 协议实现中，通常用于承载那些不属于标准流数据、ACK、握手等主要类型的数据帧。
 * 它的作用是扩展协议功能：允许实现自定义或扩展的帧类型，比如路径挑战、路径响应、流量控制、拥塞控制、连接ID管理等。
 * Misc frames are sent at the next opportunity.
 * TODO: consider flagging MISC frames with expected packet type or epoch,
 * to avoid creating unexpected protocol errors.
 *
 * The misc frame are allocated in meory as blobs, starting with the
 * misc_frame_header, followed by the misc frame content.
 */

typedef struct st_picoquic_misc_frame_header_t
{
    struct st_picoquic_misc_frame_header_t* next_misc_frame;
    struct st_picoquic_misc_frame_header_t* previous_misc_frame;
    size_t length;
    picoquic_packet_context_enum pc;
    int is_pure_ack;
} picoquic_misc_frame_header_t;

/* Per epoch sequence/packet context.
 * There are three such contexts:
 * 0: Application (0-RTT and 1-RTT)
 * 1: Handshake
 * 2: Initial
 * The context holds all the data required to manage sending and
 * resending of packets.
 */

typedef struct st_picoquic_packet_context_t
{
    uint64_t send_sequence; /* picoquic_decode_ack_frame */
    uint64_t next_sequence_hole;
    uint64_t retransmit_sequence;
    uint64_t highest_acknowledged;
    uint64_t latest_time_acknowledged; /* time at which the highest acknowledged was sent */
    uint64_t highest_acknowledged_time; /* time at which the highest ack was received */
    quic_packet_t* pending_last; //待重传队列尾部
    quic_packet_t* pending_first; //待重传队列首部
    quic_packet_t* retransmitted_newest; //已重传的最新包
    quic_packet_t* retransmitted_oldest; // 已重传的最旧包
    quic_packet_t* preemptive_repeat_ptr;
    /* monitor size of queues */
    uint64_t retransmitted_queue_size;
    /* ECN Counters */
    uint64_t ecn_ect0_total_remote;
    uint64_t ecn_ect1_total_remote;
    uint64_t ecn_ce_total_remote;
    /* Flags */
    unsigned int ack_of_ack_requested : 1; /* TODO: Initialized, unused */
} picoquic_packet_context_t;


/*
 * SACK dashboard item, part of connection context. Each item
 * holds a range of packet numbers that have been received.
 * The same structured is reused in stream management to hold
 * a range of bytes that have been received.
 */

typedef struct st_picoquic_sack_item_t
{
    picosplay_node_t node;
    uint64_t start_of_sack_range;
    uint64_t end_of_sack_range;
    uint64_t time_created;
    int nb_times_sent[2];
} picoquic_sack_item_t;

typedef struct st_picoquic_sack_range_count_t
{
    int range_counts[PICOQUIC_MAX_ACK_RANGE_REPEAT];
} picoquic_sack_range_count_t;

typedef struct st_picoquic_sack_list_t
{
    picosplay_tree_t ack_tree;
    uint64_t ack_horizon; //指接收方已确认接收的最高序号数据包。所有序号低于或等于这个边界的数据包都被认为已成功接收。
    int64_t horizon_delay;
    picoquic_sack_range_count_t rc[2];
} picoquic_sack_list_t;


/* Per epoch ack context.
 * There are three such contexts:
 * 0: Application (0-RTT and 1-RTT)
 * 1: Handshake
 * 2: Initial
 * The context holds all the data required to manage acknowledgments
 */
typedef struct st_picoquic_ack_context_track_t
{
    uint64_t highest_ack_sent; /* picoquic_format_ack_frame */
    uint64_t highest_ack_sent_time; /* picoquic_format_ack_frame */
    uint64_t time_oldest_unack_packet_received; /* picoquic_is_ack_needed: 第一个还没有被ACK的数据包 */

    unsigned int ack_needed : 1; /* picoquic_format_ack_frame */
    unsigned int ack_after_fin : 1; /* picoquic_format_ack_frame */
    unsigned int out_of_order_received : 1; /* picoquic_is_ack_needed */
    unsigned int is_immediate_ack_required : 1;
} picoquic_ack_context_track_t;

typedef struct st_picoquic_ack_context_t
{
    picoquic_sack_list_t sack_list; /* picoquic_format_ack_frame */
    uint64_t time_stamp_largest_received; /* picoquic_format_ack_frame */
    picoquic_ack_context_track_t act[2];
    uint64_t crypto_rotation_sequence; /* Lowest sequence seen with current key */

    /* ECN Counters */
    uint64_t ecn_ect0_total_local; /* picoquic_format_ack_frame */
    uint64_t ecn_ect1_total_local; /* picoquic_format_ack_frame */
    uint64_t ecn_ce_total_local; /* picoquic_format_ack_frame */
    /* Flags */
    unsigned int sending_ecn_ack : 1; /* picoquic_format_ack_frame, picoquic_ecn_accounting */
} picoquic_ack_context_t;

/* Local CID.
 * Local CID are created on demand, and stashed in the CID list.
 * When the CID is created, it is registered in the QUIC context as
 * pointing to the local connection. We manage collisions, so two
 * connections do not use the same context.
 * When a CID is associated with a path, we set a pointer from the
 * path to the entry in the CID list. If a CID is retired, these pointers
 * are nullified.
 */
typedef struct st_picoquic_local_cnxid_t
{
    struct st_picoquic_local_cnxid_t* next;
    quic_cnx_t* registered_cnx;
    picohash_item hash_item;
    uint64_t path_id;
    uint64_t sequence;
    uint64_t create_time;
    quic_connection_id_t cnx_id;
    unsigned int is_acked;
} picoquic_local_cnxid_t;

typedef struct st_picoquic_local_cnxid_list_t
{
    struct st_picoquic_local_cnxid_list_t* next_list;
    uint64_t unique_path_id;
    uint64_t local_cnxid_sequence_next;
    uint64_t local_cnxid_retire_before;
    uint64_t local_cnxid_oldest_created;
    int nb_local_cnxid;
    int nb_local_cnxid_expired;
    unsigned int is_demoted : 1;
    uint64_t demotion_time;
    picoquic_local_cnxid_t* local_cnxid_first;
} picoquic_local_cnxid_list_t;

/* Remote CID.
 * Remote CID are received from the peer. RCID #0 is received during the
 * handshake, RCID#1 MAY be received as part of server's transport parameters,
 * all other RCID are received in New CID frames. */
typedef struct st_picoquic_remote_cnxid_t
{
    struct st_picoquic_remote_cnxid_t* next;
    uint64_t sequence;
    quic_connection_id_t cnx_id;
    uint8_t reset_secret[PICOQUIC_RESET_SECRET_SIZE];
    int nb_path_references;
    unsigned int needs_removal : 1;
    unsigned int retire_sent : 1;
    unsigned int retire_acked : 1;
    picoquic_packet_context_t pkt_ctx;
} picoquic_remote_cnxid_t;

// 为每个path创建一个stash来存储remote cid
typedef struct st_picoquic_remote_cnxid_stash_t
{
    struct st_picoquic_remote_cnxid_stash_t* next_stash;
    uint64_t unique_path_id;
    uint64_t retire_cnxid_before;
    picoquic_remote_cnxid_t* cnxid_stash_first;
    unsigned int is_in_use : 1;
} picoquic_remote_cnxid_stash_t;


/*
 * 无状态数据包 is used to temporarily store
 * stateless packets before they can be sent by servers.
 * 本身就是一个rte_mbuf
 */
typedef struct st_picoquic_stateless_packet_t
{
    union
    {
        fmbuf_info_t info;

        struct
        {
            fsockaddr_t local;
            fsockaddr_t remote;
        };
    };

    struct st_picoquic_stateless_packet_t* next_packet;
    struct rte_mbuf* mbuf; //picoquic_stateless_packet_t属于哪一个rte_mbuf
    unsigned char received_ecn;
    uint64_t receive_time;
    uint64_t cnxid_log64;
    quic_connection_id_t initial_cid;
    picoquic_packet_type_enum ptype;
    u8* bytes; //指向rte_mbuf的实际数据部分
} picoquic_stateless_packet_t;

/*
 * Stream head.
 * Stream contains bytes of data, which are not always delivered in order.
 * When in order data is available, the application can read it,
 * or a callback can be set.
 *
 * Streams are maintained in the context of connections, which includes:
 *
 * - a list of open streams, managed as a "splay"
 * - a subset of "output" streams, managed as a double linked list
 *
 * For each stream, the code maintains a list of received stream segments, managed as
 * a "splay" of "stream data nodes".
 *
 * Two input modes are supported. If streams are marked active, the application receives
 * a callback and provides data "just in time". Other streams can just push data using
 * "picoquic_add_to_stream", and the data segments will be listed in the "send_queue".
 * Segments in the send queue will be sent in order, and the "active" poll for data
 * will only happen when all segments are sent.
 *
 * The stream structure holds a variety of parameters about the state of the stream.
 */

typedef struct st_quic_stream_t
{
    fnp_quic_stream_t socket;
    picosplay_node_t stream_node; /* splay of streams in connection context */
    struct st_quic_stream_t* next_output_stream; /* link in the list of output streams */
    struct st_quic_stream_t* previous_output_stream;
    quic_cnx_t* cnx;
    uint64_t stream_id;
    struct st_picoquic_path_t* affinity_path; /* Path for which affinity is set, or NULL if none */
    uint64_t consumed_offset; /* amount of data consumed by the application */
    uint64_t fin_offset; /* If the fin mark is received, index of the byte after last */
    uint64_t maxdata_local; /* 本地可以接收的最大数据 */
    uint64_t maxdata_local_acked; /* highest value in max stream data frame acked by the peer */
    uint64_t maxdata_remote; /* 对方可以接收的最大数据 */
    uint64_t last_time_data_sent;
    picosplay_tree_t rx_stream_data_tree; // 保存收到的乱序的报文段
    picosplay_tree_t tx_stream_data_tree; //保存所有待发送的流数据(包括需要重传的流数据), 依次根据priority, offset和stream id排序
    uint64_t sent_offset; /* Amount of data sent in the stream */
    // picoquic_stream_queue_node_t* send_queue; /* if the stream is not "active", list of data segments ready to send */
    picoquic_sack_list_t sack_list; /* Track which parts of the stream were acknowledged by the peer */
    /* Stream priority -- lowest is most urgent */
    uint8_t stream_priority;
    /* Flags describing the state of the stream */
    unsigned int fin_sent : 1; /* Fin sent to peer */
    unsigned int fin_received : 1; /* Fin received from peer */
    unsigned int reset_sent : 1; /* Reset stream sent to peer */
    unsigned int reset_acked : 1; /* Reset stream acked by the peer */
    unsigned int stop_sending_sent : 1; /* Stop sending was sent to peer */
    unsigned int max_stream_updated : 1;
    /* After stream was closed in both directions, the max stream id number was updated */
    unsigned int stream_data_blocked_sent : 1;
    /* If stream_data_blocked has been sent to peer, and no data sent on stream since */
    unsigned int is_output_stream : 1; /* If stream is listed in the output list */
    unsigned int is_closed : 1; /* Stream is closed, closure is accouted for */
    unsigned int is_discarded : 1;
    /* There should be no more callback for that stream, the application has discarded it */
} quic_stream_t;

/*
 * Pacing uses a set of per path variables:
 * - rate: bytes per second.
 * - evaluation_time: last time the path was evaluated.
 * - bucket_max: maximum value (capacity) of the leaky bucket.
 * - packet_time_microsec: max of (packet_time_nano_sec/1024, 1) microsec.
 * Internal variables:
 * - bucket_nanosec: number of nanoseconds of transmission time that are allowed.
 * - packet_time_nanosec: number of nanoseconds required to send a full size packet.
 */
typedef struct st_picoquic_pacing_t
{
    uint64_t rate;
    uint64_t evaluation_time;
    int64_t bucket_max;
    uint64_t packet_time_microsec;
    uint64_t quantum_max;
    uint64_t rate_max;
    int bandwidth_pause;
    /* High precision variables should only be used inside pacing.c */
    int64_t bucket_nanosec;
    int64_t packet_time_nanosec;
} picoquic_pacing_t;

/* Tuple context.
 * Tuple context are created to hold address and port pairs used to contact peers.
 * Address pairs are "verified" by successful path challenge/response exchanges.
 * On the client side, they are placed in "validated" or "backup" state by
 * local interactions. On the server side, they move from "backup" to
 * "validated" when the client starts using them.
 *
 * The tuple context contains the data necessary for managing the challenge/response.
 */
typedef struct st_picoquic_tuple_t
{
    /* Path for which the tuple is registered */
    uint64_t unique_path_id;
    /* Next tuple registered for this path */
    struct st_picoquic_tuple_t* next_tuple;
    /* Peer address. */
    fsockaddr_t peer_addr;
    /* Local address, on the local network */
    fsockaddr_t local_addr;
    /* Selected interface */
    unsigned long if_index;
    /* Address observed by the peer */
    fsockaddr_t observed_addr;
    /* CNXID used for probing this tuple. */
    picoquic_remote_cnxid_t* p_remote_cnxid;
    picoquic_local_cnxid_t* p_local_cnxid;
    /* Manage the publishing of observed addresses */
    int nb_observed_repeat;
    uint64_t observed_time;
    /* Challenge used for this path */
    uint64_t challenge_response;
    uint64_t challenge[PICOQUIC_CHALLENGE_REPEAT_MAX];
    uint64_t challenge_time;
    uint64_t demotion_time;
    uint64_t challenge_time_first;
    uint64_t is_nat_rebinding;
    uint8_t challenge_repeat_count;
    /* Flags */
    unsigned int is_backup;
    unsigned int challenge_required : 1;
    unsigned int challenge_verified : 1;
    unsigned int challenge_failed : 1;
    unsigned int response_required : 1;
    unsigned int to_preferred_address : 1;
} picoquic_tuple_t;

/*
 * Per path context.
 * Path contexts are created:
 * - At the beginning of the connection for path[0]
 * - When sending or receiving packets to a or from new addresses and ports.
 *
 * When a path is created, it is assigned a local connection id and a remote connection ID.
 * After that, the path has to be validated by a successful challenge/response.
 *
 * If multipath is supported, paths remain in the list until they are abandoned.
 *
 * As soon as a path is validated, it moves to position 0. The old path[0] moves to the
 * last position, and is marked as deprecated. After about 1 RTT, the path resource
 * are freed. (TODO: once we actually support multipath, change that behavior.)
 * (TODO: servers should only validate the path after receiving non-probing frames from
 * the client.)
 *
 * Congestion control and spin bit management are path specific.
 * Packet numbering is global, see packet context.
 */
typedef struct st_picoquic_path_t
{
    fsockaddr_t registered_peer_addr;
    picohash_item net_id_hash_item;
    struct st_quic_cnx_t* cnx;
    uint64_t unique_path_id;
    void* app_path_ctx;
    /* If using unique path id multipath */
    //ack上下文，维护已接收到的数据包序号，用于生成ack帧，当ack帧被确认时，删除对应的数据包序号
    picoquic_ack_context_t ack_ctx;
    picoquic_packet_context_t pkt_ctx;
    /* First tuple is the one used by default for the path */
    picoquic_tuple_t* first_tuple;
    /* Manage the transmission of observed addresses */
    /* TODO: tie management to path/tuple creation. */
    uint64_t observed_address_received;
    uint64_t observed_sequence_sent;
    unsigned int observed_addr_acked : 1;
    /* Manage path probing logic */
    uint64_t last_non_path_probing_pn;
    uint64_t demotion_time;
    /* Last time a packet was sent on this path. */
    uint64_t last_sent_time;
    uint64_t status_sequence_to_receive_next;
    uint64_t status_sequence_sent_last;
    /* Last 1-RTT "non path validating" packet received on this path */
    /* flags */
    unsigned int mtu_probe_sent : 1;
    unsigned int path_is_published : 1;
    unsigned int path_is_backup : 1;
    unsigned int path_is_demoted : 1;
    unsigned int path_abandon_received : 1;
    unsigned int path_abandon_sent : 1;
    unsigned int current_spin : 1;
    unsigned int last_bw_estimate_path_limited : 1;
    unsigned int path_cid_rotated : 1;
    unsigned int is_nat_challenge : 1;
    unsigned int is_cc_data_updated : 1;
    unsigned int is_multipath_probe_needed : 1;
    unsigned int was_local_cnxid_retired : 1;
    unsigned int is_ssthresh_initialized : 1;
    unsigned int is_token_published : 1;
    unsigned int is_ticket_seeded : 1; /* Whether the current ticket has been updated with RTT and CWIN */
    unsigned int is_bdp_sent : 1;
    unsigned int is_nominal_ack_path : 1;
    unsigned int is_ack_lost : 1;
    unsigned int is_ack_expected : 1;
    unsigned int is_datagram_ready : 1;
    unsigned int is_pto_required : 1; /* Should send PTO probe */
    unsigned int is_probing_nat : 1; /* When path transmission is scheduled only for NAT probing */
    unsigned int is_lost_feedback_notified : 1; /* Lost feedback has been notified */
    unsigned int is_cca_probing_up : 1; /* congestion control algorithm is seeking more bandwidth */
    unsigned int rtt_is_initialized : 1; /* RTT was measured at least once. */
    unsigned int sending_path_cid_blocked_frame : 1; /* Sending a path CID blocked, not acked yet. */

    /* Management of retransmissions in a path.
     * The "path_packet" variables are used for the RACK algorithm, per path, to avoid
     * declaring packets lost just because another path is delivering them faster.
     * The "number of retransmit" counts the number of unsuccessful retransmissions; it
     * is reset to zero if a new packet is acknowledged.
     */
    uint64_t last_packet_received_at;
    uint64_t last_loss_event_detected;
    uint64_t nb_retransmit; /* Number of timeout retransmissions since last ACK */
    uint64_t total_bytes_lost; /* Sum of length of packet lost on this path */
    uint64_t nb_losses_found;
    uint64_t nb_timer_losses;
    uint64_t nb_spurious; /* Number of spurious retransmissions for the path */

    /* Loss bit data */
    uint64_t nb_losses_reported;
    uint64_t q_square;
    /* Time measurement */
    uint64_t max_ack_delay;
    uint64_t rtt_sample;
    uint64_t one_way_delay_sample;
    uint64_t smoothed_rtt;
    uint64_t rtt_variant;
    uint64_t retransmit_timer; //重传定时器
    uint64_t rtt_min;
    uint64_t rtt_max;
    uint64_t max_spurious_rtt;
    uint64_t max_reorder_delay;
    uint64_t max_reorder_gap;
    uint64_t latest_sent_time;
    uint64_t rtt_packet_previous_period;
    uint64_t rtt_time_previous_period;
    uint64_t nb_rtt_estimate_in_period;
    uint64_t sum_rtt_estimate_in_period;
    uint64_t max_rtt_estimate_in_period;
    uint64_t min_rtt_estimate_in_period;

    /* MTU */
    size_t send_mtu;
    size_t send_mtu_max_tried;

    /* Bandwidth measurement */
    uint64_t delivered; /* The total amount of data delivered so far on the path */
    uint64_t delivered_last; /* Amount delivered by last bandwidth estimation */
    uint64_t delivered_time_last; /* time last delivered packet was delivered */
    uint64_t delivered_sent_last; /* time last delivered packet was sent */
    uint64_t delivered_limited_index;
    uint64_t delivered_last_packet;
    uint64_t bandwidth_estimate; /* In bytes per second */
    uint64_t bandwidth_estimate_max; /* Maximum of bandwidth estimate over life of path */
    uint64_t max_sample_acked_time; /* Time max sample was delivered */
    uint64_t max_sample_sent_time; /* Time max sample was sent */
    uint64_t max_sample_delivered; /* Delivered value at time of max sample */
    uint64_t peak_bandwidth_estimate; /* In bytes per second, measured on short interval with highest bandwidth */

    uint64_t bytes_sent; /* Total amount of bytes sent on the path */
    uint64_t received; /* Total amount of bytes received from the path */
    uint64_t receive_rate_epoch; /* Time of last receive rate measurement */
    uint64_t received_prior; /* Total amount received at start of epoch */
    uint64_t receive_rate_estimate; /* In bytes per second */
    uint64_t receive_rate_max; /* In bytes per second */

    /* Congestion control state */
    uint64_t cwin;
    uint64_t bytes_in_transit;
    uint64_t last_sender_limited_time;
    uint64_t last_cwin_blocked_time;
    uint64_t last_time_acked_data_frame_sent;
    void* congestion_alg_state;
    picoquic_pacing_t pacing;

    /* MTU safety tracking */
    uint64_t nb_mtu_losses;

    /* Debug MP */
    int lost_after_delivered;
    int responder;
    int challenger;
    int polled;
    int paced;
    int congested;
    int selected;
    int nb_delay_outliers;

    /* Path quality callback. These variables store the delta set for signaling
     * and the threshold computed based on these deltas and the latest published value.
     */
    uint64_t rtt_update_delta;
    uint64_t pacing_rate_update_delta;
    uint64_t rtt_threshold_low;
    uint64_t rtt_threshold_high;
    uint64_t pacing_rate_threshold_low;
    uint64_t pacing_rate_threshold_high;
    uint64_t receive_rate_threshold_low;
    uint64_t receive_rate_threshold_high;

    /* BDP parameters sent by the server to be stored at client */
    uint64_t rtt_min_remote;
    uint64_t cwin_remote;
    uint8_t ip_client_remote[16];
    uint8_t ip_client_remote_length;
} picoquic_path_t;

/* Crypto context. There are four such contexts:
 * 0: Initial context, with encryption based on a version dependent key,
 * 1: 0-RTT context
 * 2: Handshake context
 * 3: Application data
 */
typedef struct st_picoquic_crypto_context_t
{
    void* aead_encrypt;
    void* aead_decrypt;
    void* pn_enc; /* Used for PN encryption */
    void* pn_dec; /* Used for PN decryption */
} picoquic_crypto_context_t;

/*
 * Definition of the session ticket store and connection token
 * store that can be associated with a
 * client context.
 */
typedef enum
{
    picoquic_tp_0rtt_max_data = 0,
    picoquic_tp_0rtt_max_stream_data_bidi_local = 1,
    picoquic_tp_0rtt_max_stream_data_bidi_remote = 2,
    picoquic_tp_0rtt_max_stream_data_uni = 3,
    picoquic_tp_0rtt_max_streams_id_bidir = 4,
    picoquic_tp_0rtt_max_streams_id_unidir = 5,
    picoquic_tp_0rtt_rtt_local = 6,
    picoquic_tp_0rtt_cwin_local = 7,
    picoquic_tp_0rtt_rtt_remote = 8,
    picoquic_tp_0rtt_cwin_remote = 9
} picoquic_tp_0rtt_enum;

#define PICOQUIC_NB_TP_0RTT 10

typedef struct st_picoquic_stored_ticket_t
{
    struct st_picoquic_stored_ticket_t* next_ticket;
    char* sni;
    char* alpn;
    uint8_t* ip_addr;
    uint64_t tp_0rtt[PICOQUIC_NB_TP_0RTT];
    uint8_t* ticket;
    uint64_t time_valid_until;
    uint16_t sni_length;
    uint16_t alpn_length;
    uint32_t version;
    uint16_t ticket_length;
    uint8_t ip_addr_length;
    uint8_t ip_addr_client_length;
    uint8_t* ip_addr_client;
    unsigned int was_used : 1;
} picoquic_stored_ticket_t;


typedef struct st_picoquic_stored_token_t
{
    struct st_picoquic_stored_token_t* next_token;
    char const* sni;
    uint8_t const* token;
    uint8_t const* ip_addr;
    uint64_t time_valid_until;
    uint16_t sni_length;
    uint16_t token_length;
    uint8_t ip_addr_length;
    unsigned int was_used : 1;
} picoquic_stored_token_t;

typedef struct st_picoquic_issued_ticket_t
{
    struct st_picoquic_issued_ticket_t* next_ticket;
    struct st_picoquic_issued_ticket_t* previous_ticket;
    picohash_item hash_item;
    uint64_t ticket_id;
    uint64_t creation_time;
    uint64_t rtt;
    uint64_t cwin;
    uint8_t ip_addr[16];
    uint8_t ip_addr_length;
} picoquic_issued_ticket_t;

/*
 * Transport parameters, as defined by the QUIC transport specification.
 * The initial code defined the type as an enum, but the binary representation
 * of the enum type is not strictly defined in C. Values like "0xff02de1"
 * could end up represented as a negative integer, and then converted to
 * the 64 bit representation "0xffffffffff02de1", which is not good.
 * We changed that to using macro for definition.
 */
typedef uint64_t picoquic_tp_enum;
#define picoquic_tp_original_connection_id 0
#define picoquic_tp_idle_timeout 1
#define picoquic_tp_stateless_reset_token 2
#define picoquic_tp_max_packet_size 3
#define picoquic_tp_initial_max_data 4
#define picoquic_tp_initial_max_stream_data_bidi_local 5
#define picoquic_tp_initial_max_stream_data_bidi_remote 6
#define picoquic_tp_initial_max_stream_data_uni 7
#define picoquic_tp_initial_max_streams_bidi 8
#define picoquic_tp_initial_max_streams_uni 9
#define picoquic_tp_ack_delay_exponent 10
#define picoquic_tp_max_ack_delay 11
#define picoquic_tp_disable_migration 12
#define picoquic_tp_server_preferred_address 13
#define picoquic_tp_active_connection_id_limit 14
#define picoquic_tp_handshake_connection_id 15
#define picoquic_tp_retry_connection_id 16
#define picoquic_tp_max_datagram_frame_size 32 /* per draft-pauly-quic-datagram-05 */
#define picoquic_tp_test_large_chello 3127
#define picoquic_tp_enable_loss_bit 0x1057
#define picoquic_tp_min_ack_delay 0xff04de1bull
#define picoquic_tp_enable_time_stamp 0x7158 /* x&1 */
#define picoquic_tp_grease_quic_bit 0x2ab2
#define picoquic_tp_version_negotiation 0x11
#define picoquic_tp_enable_bdp_frame 0xebd9                   /* per draft-kuhn-quic-0rtt-bdp-09 */
#define picoquic_tp_initial_max_path_id 0x0f739bbc1b666d0dull /* per draft quic multipath 13 */
#define picoquic_tp_address_discovery 0x9f81a176              /* per draft-seemann-quic-address-discovery */

/* Callback for converting binary log to quic log at the end of a connection.
 * This is kept private for now; and will only be set through the "set quic log"
 * API.
 */
typedef int (*picoquic_autoqlog_fn)(quic_cnx_t* cnx);

/* Callback used for the performance log
 */
typedef int (*picoquic_performance_log_fn)(quic_context_t* quic, quic_cnx_t* cnx, int should_delete);

/* QUIC context, defining the tables of connections,
 * open sockets, etc.
 */
typedef struct st_quic_context
{
    fsocket_t socket;
    fsocket_t* udp_socket;
    void* tls_master_ctx;
    // picoquic_stream_data_cb_fn default_callback_fn;
    // void* default_callback_ctx;
    congestion_algorithm_id_t default_congestion_alg;
    fnp_pring_t* pending_cnxs; // 只有服务端存在
    char const* default_sni;
    char const* default_alpn;
    picoquic_alpn_select_fn alpn_select_fn;
    uint8_t reset_seed[PICOQUIC_RESET_SECRET_SIZE];
    uint8_t retry_seed[PICOQUIC_RETRY_SECRET_SIZE];
    // uint64_t* p_simulated_time;
    uint8_t hash_seed[16];
    char const* ticket_file_name;
    char const* token_file_name;
    picoquic_stored_ticket_t* p_first_ticket;
    picoquic_stored_token_t* p_first_token;
    picosplay_tree_t token_reuse_tree; /* detection of token reuse */
    uint8_t local_cnxid_length;
    uint8_t default_stream_priority;
    uint64_t local_cnxid_ttl; /* Max time to live of Connection ID in microsec, init to "forever" */
    uint32_t mtu_max;
    uint32_t padding_multiple_default;
    uint32_t padding_minsize_default;
    uint32_t sequence_hole_pseudo_period; /* Optimistic ack defense */
    picoquic_pmtud_policy_enum default_pmtud_policy;
    picoquic_spinbit_version_enum default_spin_policy;
    picoquic_lossbit_version_enum default_lossbit_policy;
    uint32_t default_multipath_option;
    uint64_t default_handshake_timeout;
    uint64_t crypto_epoch_length_max; /* Default packet interval between key rotations */
    uint32_t max_simultaneous_logs;
    uint32_t current_number_of_open_logs;
    uint32_t max_half_open_before_retry;
    uint32_t current_number_half_open;
    uint32_t current_number_connections;
    uint32_t tentative_max_number_connections;
    uint32_t max_number_connections;
    uint64_t stateless_reset_next_time; /* Next time Stateless Reset or VN packet can be sent */
    uint64_t stateless_reset_min_interval; /* Enforced interval between two stateless reset packets */
    uint64_t cwin_max; /* max value of cwin per connection */
    /* Flags */
    unsigned int check_token : 1;
    unsigned int force_check_token : 1;
    unsigned int provide_token : 1;
    unsigned int unconditional_cnx_id : 1;
    unsigned int client_zero_share : 1;
    unsigned int server_busy : 1;
    unsigned int is_cert_store_not_empty : 1;
    unsigned int use_long_log : 1;
    unsigned int should_close_log : 1;
    unsigned int enable_sslkeylog : 1; /* Enable the SSLKEYLOG feature */
    unsigned int use_unique_log_names : 1; /* Add 64 bit random number to log names for uniqueness */
    unsigned int dont_coalesce_init : 1; /* test option to turn of packet coalescing on server */
    unsigned int one_way_grease_quic_bit : 1; /* Grease of QUIC bit, but do not announce support */
    unsigned int random_initial : 2; /* Randomize the initial PN number */
    unsigned int packet_train_mode : 1; /* Tune pacing for sending packet trains */
    unsigned int use_constant_challenges : 1; /* Use predictable challenges when producing constant logs. */
    unsigned int use_low_memory : 1; /* if possible, use low memory alternatives, e.g. for AES */
    unsigned int is_preemptive_repeat_enabled : 1; /* enable premptive repeat on new connections */
    unsigned int enforce_client_only : 1; /* Do not authorize incoming connections */
    unsigned int test_large_server_flight : 1; /* Use TP to ensure server flight is at least 8K */
    unsigned int is_port_blocking_disabled : 1; /* Do not check client port on incoming connections */
    unsigned int are_path_callbacks_enabled : 1; /* Enable path specific callbacks by default */
    unsigned int use_predictable_random : 1; /* For logging tests */
    picoquic_stateless_packet_t* pending_stateless_packet;

    struct st_quic_cnx_t* cnx_list;
    struct st_quic_cnx_t* cnx_last;
    picosplay_tree_t cnx_wake_tree;

    struct st_quic_cnx_t* cnx_in_progress;

    picohash_table* table_cnx_by_id;
    picohash_table* table_cnx_by_net;
    picohash_table* table_cnx_by_icid;
    picohash_table* table_cnx_by_secret;

    picohash_table* table_issued_tickets;
    picoquic_issued_ticket_t* table_issued_tickets_first;
    picoquic_issued_ticket_t* table_issued_tickets_last;
    size_t table_issued_tickets_nb;

    // picoquic_packet_t* p_first_packet;
    // int nb_packets_in_pool;
    // int nb_packets_allocated;
    // int nb_packets_allocated_max;

    // quic_stream_data_t* p_first_data_node;
    // int nb_data_nodes_in_pool;
    // int nb_data_nodes_allocated;
    // int nb_data_nodes_allocated_max;

    picoquic_connection_id_cb_fn cnx_id_callback_fn;
    void* cnx_id_callback_ctx;

    void* aead_encrypt_ticket_ctx;
    void* aead_decrypt_ticket_ctx;
    void** retry_integrity_sign_ctx;
    void** retry_integrity_verify_ctx;

    struct st_ptls_verify_certificate_t* verify_certificate_callback;
    picoquic_free_verify_certificate_ctx free_verify_certificate_callback_fn;

    picoquic_tp_t default_tp;

    picoquic_fuzz_fn fuzz_fn;
    void* fuzz_ctx;
    int wake_file;
    int wake_line;

    /* Global flow control enforcement */
    uint64_t max_data_limit;

    /* Path quality callback. These variables store the default values
     * of the min deltas required to perform path quality signaling.
     */
    uint64_t rtt_update_delta;
    uint64_t pacing_rate_update_delta;

    /* Logging APIS */
    void* F_log;
    char* binlog_dir;
    char* qlog_dir;
    picoquic_autoqlog_fn autoqlog_fn;
    struct st_picoquic_unified_logging_t* text_log_fns;
    struct st_picoquic_unified_logging_t* bin_log_fns;
    struct st_picoquic_unified_logging_t* qlog_fns;
    picoquic_performance_log_fn perflog_fn;
    void* v_perflog_ctx;
} quic_context_t;

/*
 * Per connection context.
 */
typedef struct st_quic_cnx_t
{
    fsocket_t socket;
    quic_context_t* quic;
    /* Management of context retrieval tables */

    struct st_quic_cnx_t* next_in_table;
    struct st_quic_cnx_t* previous_in_table;

    /* Proposed version, may be zero if there is no reference.
     * Rejected version that triggered reception of a Version negotiation packet, zero by default.
     * Desired version, target of possible compatible negotiation.
     */
    uint32_t proposed_version;
    uint32_t rejected_version;
    uint32_t desired_version;
    int version_index;

    /* Series of flags showing the state or choices of the connection */
    unsigned int is_0RTT_accepted : 1; /* whether 0-RTT is accepted */
    unsigned int remote_parameters_received : 1; /* whether remote parameters where received */
    unsigned int client_mode : 1; /* Is this connection the client side? */
    unsigned int key_phase_enc : 1; /* Key phase used in outgoing packets */
    unsigned int key_phase_dec : 1; /* Key phase expected in incoming packets */
    unsigned int zero_rtt_data_accepted : 1; /* Peer confirmed acceptance of zero rtt data */
    unsigned int sending_ecn_ack : 1; /* ECN data has been received, should be copied in acks */
    unsigned int sent_blocked_frame : 1; /* Blocked frame has been sent */
    unsigned int stream_blocked_bidir_sent : 1;
    /* If stream_blocked has been sent to peer and no stream limit update since */
    unsigned int stream_blocked_unidir_sent : 1;
    /* If stream_blocked has been sent to peer and no stream limit update since */
    unsigned int max_stream_data_needed : 1; /* If at least one stream needs more data */
    unsigned int path_demotion_needed : 1; /* If at least one path was recently demoted */
    unsigned int tuple_demotion_needed : 1; /* if at least one tuple should be deleted */
    unsigned int alt_path_challenge_needed : 1; /* If at least one alt path challenge is needed or in progress */
    unsigned int is_handshake_finished : 1;
    /* If there are no more packets to ack or retransmit in initial  or handshake contexts */
    unsigned int is_handshake_done_acked : 1; /* If the peer has acked the handshake done packet */
    unsigned int is_new_token_acked : 1;
    /* Has the peer acked a new token? This assumes at most one new token sent per connection */
    unsigned int is_1rtt_received : 1; /* If at least one 1RTT packet has been received */
    unsigned int is_1rtt_acked : 1; /* If at least one 1RTT packet has been acked by the peer */
    unsigned int has_successful_probe : 1; /* At least one probe was successful */
    unsigned int grease_transport_parameters : 1; /* Exercise greasing of transport parameters */
    unsigned int test_large_chello : 1; /* Add a greasing parameter to test sending CHello on multiple packets */
    unsigned int initial_validated : 1; /* Path has been validated, DOS amplification protection is lifted */
    unsigned int initial_repeat_needed : 1; /* Path has not been validated, repeated initial was received */
    unsigned int is_loss_bit_enabled_incoming : 1; /* Read the loss bits in incoming packets */
    unsigned int is_loss_bit_enabled_outgoing : 1; /* Insert the loss bits in outgoing packets */
    unsigned int recycle_sooner_needed : 1; /* There may be a need to recycle "sooner" packets */
    unsigned int is_time_stamp_enabled : 1; /* Read time stamp on on incoming */
    unsigned int is_time_stamp_sent : 1; /* Send time stamp with ACKS */
    unsigned int is_pacing_update_requested : 1; /* Whether the application subscribed to pacing updates */
    unsigned int is_path_quality_update_requested : 1; /* Whether the application subscribed to path quality updates */
    unsigned int is_hcid_verified : 1; /* Whether the HCID was received from the peer */
    unsigned int do_grease_quic_bit : 1; /* Negotiated grease of QUIC bit */
    unsigned int quic_bit_greased : 1; /* Indicate whether the quic bit was greased at least once */
    unsigned int quic_bit_received_0 : 1; /* Indicate whether the quic bit was received as zero at least once */
    unsigned int is_half_open : 1; /* for server side connections, created but not yet complete */
    unsigned int did_receive_short_initial : 1; /* whether peer sent unpadded initial packet */
    unsigned int ack_ignore_order_local : 1;
    /* Request peer to not generate immediate ack if out of order packet received */
    unsigned int ack_ignore_order_remote : 1; /* Peer requested no immediate ack if out of order packet received */
    unsigned int are_path_callbacks_enabled : 1; /* Enable path specific callbacks */
    unsigned int is_preemptive_repeat_enabled : 1; /* Preemptive repat of packets to reduce transaction latency */
    unsigned int do_version_negotiation : 1; /* Whether compatible version negotiation is activated */
    unsigned int cwin_notified_from_seed : 1; /* cwin was reset from a seeded value */
    unsigned int is_datagram_ready : 1; /* Active polling for datagrams */
    unsigned int is_immediate_ack_required : 1; /* Should send an ACK asap */
    unsigned int is_multipath_enabled : 1; /* Unique path ID extension has been negotiated */
    unsigned int is_lost_feedback_notification_required : 1; /* CC algorithm requests lost feedback notification */
    unsigned int is_forced_probe_up_required : 1; /* application wants "probe up" if CC requests it */
    unsigned int is_address_discovery_receiver : 1; /* receive the address discovery extension */
    unsigned int is_subscribed_to_path_allowed : 1;
    /* application wants to be advised if it is now possible to create a path */
    unsigned int is_notified_that_path_is_allowed : 1;
    /* application wants to be advised if it is now possible to create a path */

    /* PMTUD policy */
    picoquic_pmtud_policy_enum pmtud_policy;
    /* Spin bit policy */
    picoquic_spinbit_version_enum spin_policy;
    /* Idle timeout in microseconds */
    uint64_t idle_timeout;
    /* Local and remote parameters */
    picoquic_tp_t local_parameters;
    picoquic_tp_t remote_parameters;
    /* Padding policy */
    uint32_t padding_multiple;
    uint32_t padding_minsize;
    /* Value of RTT and CWIN remembered from previous connections */
    uint8_t seed_ip_addr[PICOQUIC_STORED_IP_MAX];
    uint8_t seed_ip_addr_length;
    uint64_t seed_rtt_min;
    uint64_t seed_cwin;
    /* Identification of ticket issued to the current connection,
     * and if present of the ticket used to resume the connection.
     * On server this is the unique sequence number of the ticket.
     * On client this is the creation time of the ticket.
     */
    uint64_t issued_ticket_id;
    uint64_t resumed_ticket_id;

    /* On clients, document the SNI and ALPN expected from the server */
    /* TODO: there may be a need to propose multiple ALPN */
    char const* sni;
    char const* alpn;
    /* On clients, receives the maximum 0RTT size accepted by server */
    size_t max_early_data_size;
    /* Call back function and context */
    // picoquic_stream_data_cb_fn callback_fn;
    // void* callback_ctx;

    /* connection state, ID, etc. Todo: allow for multiple cnxid */
    picoquic_state_enum cnx_state;
    quic_connection_id_t initial_cnxid;
    quic_connection_id_t original_cnxid; //retry token中携带的原始cid
    fsockaddr_t registered_icid_addr;
    picohash_item registered_icid_item;
    fsockaddr_t registered_secret_addr;
    uint8_t registered_reset_secret[PICOQUIC_RESET_SECRET_SIZE];
    picohash_item registered_reset_secret_item;

    uint64_t start_time;
    int64_t phase_delay;
    uint64_t application_error;
    uint64_t local_error;
    char const* local_error_reason;
    uint64_t remote_application_error;
    uint64_t remote_error;
    uint64_t offending_frame_type;
    uint16_t retry_token_length;
    uint8_t* retry_token;

    /* Next time sending data is expected */
    uint64_t next_wake_time;
    picosplay_node_t cnx_wake_node;
    /* TLS context, TLS Send Buffer, streams, epochs */
    void* tls_ctx;
    uint64_t crypto_epoch_length_max;
    uint64_t crypto_epoch_sequence;
    uint64_t crypto_rotation_time_guard;
    struct st_ptls_buffer_t* tls_sendbuf;
    uint16_t psk_cipher_suite_id;

    quic_stream_t tls_stream[PICOQUIC_NUMBER_OF_EPOCHS]; /* Separate input/output from each epoch */
    picoquic_crypto_context_t crypto_context[PICOQUIC_NUMBER_OF_EPOCHS]; /* Encryption and decryption objects */
    picoquic_crypto_context_t crypto_context_old; /* Old encryption and decryption context after key rotation */
    picoquic_crypto_context_t crypto_context_new; /* New encryption and decryption context just before key rotation */
    uint64_t crypto_failure_count;
    /* Liveness detection */
    uint64_t latest_progress_time; /* last local time at which the connection progressed */
    uint64_t latest_receive_time; /* last time something was received from the peer */
    /* Close connection management */
    uint64_t last_close_sent;
    /* Sequence and retransmission state */
    picoquic_packet_context_t pkt_ctx[picoquic_nb_packet_context];
    /* Acknowledgement state */
    picoquic_ack_context_t ack_ctx[picoquic_nb_packet_context];
    /* Sequence number of the next observed address frame */
    uint64_t observed_number;
    /* Statistics */
    uint64_t nb_bytes_queued;
    uint32_t nb_zero_rtt_sent;
    uint32_t nb_zero_rtt_acked;
    uint32_t nb_zero_rtt_received;
    size_t max_mtu_sent;
    size_t max_mtu_received;
    uint64_t nb_packets_received;
    uint64_t nb_trains_sent;
    uint64_t nb_trains_short;
    uint64_t nb_trains_blocked_cwin;
    uint64_t nb_trains_blocked_pacing;
    uint64_t nb_trains_blocked_others;
    uint64_t nb_packets_sent;
    uint64_t nb_packets_logged;
    uint64_t nb_retransmission_total;
    uint64_t nb_preemptive_repeat;
    uint64_t nb_spurious;
    uint64_t nb_crypto_key_rotations;
    uint64_t nb_packet_holes_inserted;
    uint64_t max_ack_delay_remote;
    uint64_t max_ack_gap_remote;
    uint64_t max_ack_delay_local;
    uint64_t max_ack_gap_local;
    uint64_t min_ack_delay_remote;
    uint64_t min_ack_delay_local;
    unsigned int cwin_blocked : 1;
    unsigned int flow_blocked : 1;
    unsigned int stream_blocked : 1;
    /* Congestion algorithm */
    congestion_algorithm_t cc_algo;
    /* Management of quality signalling updates */
    uint64_t rtt_update_delta;
    uint64_t pacing_rate_update_delta;
    uint64_t pacing_rate_signalled;
    uint64_t pacing_increase_threshold;
    uint64_t pacing_decrease_threshold;
    uint64_t pacing_change_threshold;

    /* Data accounting for limiting amplification attacks */
    uint64_t initial_data_received;
    uint64_t initial_data_sent;

    /* Flow control information */
    uint64_t data_sent;
    uint64_t data_received;
    uint64_t maxdata_local; /* Highest value sent to the peer */
    uint64_t maxdata_local_acked; /* Highest value acked by the peer */
    uint64_t maxdata_remote; /* Highest value received from the peer */
    uint64_t max_stream_data_local;
    uint64_t max_stream_data_remote;
    uint64_t max_stream_id_bidir_local; /* Highest value sent to the peer */
    uint64_t max_stream_id_bidir_rank_acked; /* Highest rank value acked by the peer */
    uint64_t max_stream_id_bidir_local_computed; /* Value computed from stream FIN but not yet sent */
    uint64_t max_stream_id_bidir_remote; /* Highest value received from the peer */
    uint64_t max_stream_id_unidir_local; /* Highest value sent to the peer */
    uint64_t max_stream_id_unidir_rank_acked; /* Highest rank value acked by the peer */
    uint64_t max_stream_id_unidir_local_computed; /* Value computed from stream FIN but not yet sent */
    uint64_t max_stream_id_unidir_remote; /* Highest value received from the peer */

    /* Queue for frames waiting to be sent */
    picoquic_misc_frame_header_t* first_misc_frame;
    picoquic_misc_frame_header_t* last_misc_frame;

    /* Management of streams */
    picosplay_tree_t stream_tree;
    // picosplay_tree_t output_stream_tree;
    quic_stream_t* first_output_stream;
    quic_stream_t* last_output_stream;
    // 暂存来自对端新创建的streams, 供应用层accept
    uint64_t high_priority_stream_id;
    uint64_t next_stream_id[4]; //存储下一个流ID, 0:双向流, 1:单向流, 2:双向流(服务器), 3:单向流(服务器)
    uint64_t priority_limit_for_bypass; /* Bypass CC if dtagram or stream priority lower than this, 0 means never */
    picoquic_pacing_t priority_bypass_pacing;

    /* 重传队列包含packets with data frames that should be
     * sent according to priority 当拥塞窗口可以发送时. */
    // picosplay_tree_t queue_data_repeat_tree;

    /* Management of datagram queue (see also active datagram flag)
     * The "conflict" count indicates how many datagrams have been sent while
     * stream data was also waiting. If this passes the max value
     * picoquic will try sending stream data before the next datagram.
     * This is provisional -- we need to consider managing datagram
     * priorities in a way similar to stream priorities.
     */
    picoquic_misc_frame_header_t* first_datagram;
    picoquic_misc_frame_header_t* last_datagram;
    uint64_t datagram_priority;
    int datagram_conflicts_count;
    int datagram_conflicts_max;

    /* If not `0`, the connection will send keep alive messages in the given interval. */
    uint64_t keep_alive_interval;

    /* Management of paths */
    picoquic_path_t** path;
    int nb_paths;
    int nb_path_alloc;
    int last_path_polled;
    uint64_t unique_path_id_next;
    picoquic_path_t* nominal_path_for_ack;
    uint64_t status_sequence_to_send_next;
    uint64_t max_path_id_local;
    uint64_t max_path_id_acknowledged;
    uint64_t max_path_id_remote;
    uint64_t paths_blocked_acknowledged;
    /* Management of the CNX-ID stash */
    picoquic_remote_cnxid_stash_t* first_remote_cnxid_stash;
    /* management of local CID stash.
     * the number of lists represents the number of list already created,
     * minus the number of lists deleted.
     * */
    uint64_t nb_local_cnxid_lists;
    uint64_t next_path_id_in_lists;
    picoquic_local_cnxid_list_t* first_local_cnxid_list;

    /* Management of ACK frequency */
    uint64_t ack_frequency_sequence_local;
    uint64_t ack_gap_local;
    uint64_t ack_frequency_delay_local;
    uint64_t ack_frequency_sequence_remote;
    uint64_t ack_gap_remote;
    uint64_t ack_delay_remote;
    uint64_t ack_reordering_threshold_remote;

    /* Copies of packets received too soon */
    picoquic_stateless_packet_t* first_sooner;
    picoquic_stateless_packet_t* last_sooner;

    /* Log handling */
    uint16_t log_unique;
    FILE* f_binlog;
    char* binlog_file_name;
    void (*memlog_call_back)(quic_cnx_t* cnx, picoquic_path_t* path, void* v_memlog, int op_code,
                             uint64_t current_time);
    void* memlog_ctx;
} quic_cnx_t;

typedef struct st_picoquic_packet_data_t
{
    uint64_t last_time_stamp_received;
    uint64_t last_ack_delay; /* ACK Delay in ACK frame */
    int nb_path_ack;

    struct
    {
        picoquic_path_t* acked_path; /* path for which ACK was received */
        uint64_t largest_sent_time; /* Send time of ACKed packet (largest number acked) */
        uint64_t delivered_prior; /* Amount delivered prior to that packet */
        uint64_t delivered_time_prior; /* Time last delivery before acked packet sent */
        uint64_t delivered_sent_prior; /* Time this last delivery packet was sent */
        uint64_t lost_prior; /* Value of nb_bytes_lost when packet was sent */
        uint64_t inflight_prior; /* Value of bytes_in_flight when packet was sent */
        unsigned int rs_is_path_limited; /* Whether the path was app limited when packet was sent */
        unsigned int rs_is_cwnd_limited;
        unsigned int is_set;
        uint64_t data_acked;
    } path_ack[PICOQUIC_NB_PATH_TARGET];
} picoquic_packet_data_t;

/* Data structure used to hold chunk of stream data queued by application */
typedef struct st_quic_stream_data_node_t
{
    picosplay_node_t node;
    quic_context_t* quic;
    struct rte_mbuf* mbuf;
    struct st_picoquic_stream_queue_node_t* next_stream_data;
    uint64_t offset; /* Stream offset of the first octet in "bytes" */
    size_t length; /* Number of octets in "bytes" */
} quic_stream_data_node_t;

#define get_quic_stream_data_node(m) (quic_stream_data_node_t *)rte_mbuf_to_priv(m);

#endif //QUIC_COMMON_H
