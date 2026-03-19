#ifndef FNP_SOCKET_H
#define FNP_SOCKET_H

#include "fnp_sockaddr.h"
#include "fnp_ring.h"

#define SOCKET_TX_BURST_NUM 16
#define RECV_BATCH_SIZE 32

typedef struct fsocket fsocket_t;

#define FSOCKET_FRONTEND_FLAG_EVENTFD 0x01u
#define FSOCKET_FRONTEND_FLAG_POLLING 0x02u

// 与应用层交互的接口
typedef struct fsocket
{
    fsocket_type_t type; // 前后端共享的socket类型
    char name[48]; // socket的名称, 用于调试和日志

    fnp_ring_t* rx; // 从fnp-daemon接收数据的队列
    fnp_ring_t* tx; // 向fnp-daemon发送数据的队列

    int rx_efd_in_frontend; // 前端监听rx是否有数据的eventfd
    int tx_efd_in_frontend; // 前端触发tx，通知后端有数据
    int rx_efd_in_backend; // 后端触发通知，通知前端有数据
    int tx_efd_in_backend; // master监听tx是否有数据，socket在后端的唯一标识

    int frontend_id; //frontend_id为0的socket是可以释放的, 因为frontend不会再使用了
    int polling_worker; // 负责轮询该socket的worker_id, polling_worker为-1表示还未加入轮询
    u64 polling_tsc; // 最后一次轮询到数据的时间戳
    u32 frontend_flags; // 前端共享状态位, 见FSOCKET_FRONTEND_FLAG_*
    u32 close_requested : 1; // 应用层请求关闭socket
    u32 is_ready : 1; // 连接已建立，后端设置
    u32 is_closed : 1; // 连接已关闭, 后端设置
} fsocket_t;

#define fsocket(sock) ((fsocket_t *)sock)

#define is_tcp_socket(socket)   ((socket)->type == fsocket_type_tcp)
#define is_udp_socket(socket)   ((socket)->type == fsocket_type_udp)
#define is_quic_socket(socket)   ((socket)->type == fsocket_type_quic)
#define is_raw_socket(socket)   ((socket)->type == fsocket_type_raw)

static inline u32 fsocket_frontend_flags_load(const fsocket_t* socket)
{
    return __atomic_load_n(&socket->frontend_flags, __ATOMIC_ACQUIRE);
}

static inline void fsocket_frontend_flags_set(fsocket_t* socket, u32 flags)
{
    __atomic_or_fetch(&socket->frontend_flags, flags, __ATOMIC_RELEASE);
}

static inline void fsocket_frontend_flags_clear(fsocket_t* socket, u32 flags)
{
    __atomic_and_fetch(&socket->frontend_flags, ~flags, __ATOMIC_RELEASE);
}

static inline bool fsocket_frontend_eventfd_enabled(const fsocket_t* socket)
{
    return (fsocket_frontend_flags_load(socket) & FSOCKET_FRONTEND_FLAG_EVENTFD) != 0;
}

static inline bool fsocket_frontend_polling_enabled(const fsocket_t* socket)
{
    return (fsocket_frontend_flags_load(socket) & FSOCKET_FRONTEND_FLAG_POLLING) != 0;
}

// quic stream与应用层交互的接口
typedef struct fnp_quic_stream
{
    u64 stream_id;
    fnp_ring_t* rx;
    fnp_ring_t* tx;
    u64 local_error;
    u64 remote_error;
    u64 local_stop_error;
    u64 remote_stop_error;
    u8 priority;
    u32 is_unidirectional : 1; // 是否单向流
    u32 is_local : 1; // 是否是本地创建的流
    u32 request_close : 1; //关闭本地发送端
    u32 request_fin : 1; //请求发送fin
    u32 receive_fin : 1; //收到对方的fin
    u32 request_stop_sending : 1; //请求对方停止发送数据
    u32 receive_stop_sending : 1; //收到停止发送帧
    u32 request_reset : 1; //本地请求立即停止发送
    u32 receive_reset : 1; //收到对方的请求发送
} fnp_quic_stream_t;

// 小于socket_request_connect的值表示有数据待读取
typedef enum fsocket_event
{
    fsocket_event_data = 0x01, // backend -> frontend, 有应用数据/新连接待处理
    fsocket_event_close = 0x0100000000, // backend -> frontend
    // fsocket_request_close = 0x0200000000, // frontend -> backend, 应用层请求关闭连接
    // fsocket_is_ready = 0x0400000000, // backend -> frontend
    // fsocket_is_closed = 0x0800000000, // backend -> frontend, 通知frontend连接已关闭
} fsocket_event_e;


// 最大256字节
// 参见picoquic_stateless_packet_t
typedef struct
{
    fsockaddr_t local;
    fsockaddr_t remote;
    u32 request_syn : 1; // 请求发送SYN标志
    u32 request_fin : 1; // 请求发送FIN标志
    u32 receive_fin : 1; // 接收FIN标志
} fmbuf_info_t;

#define get_fmbuf_info(m) ((fmbuf_info_t *)rte_mbuf_to_priv(m))

#endif // FNP_SOCKET_H
