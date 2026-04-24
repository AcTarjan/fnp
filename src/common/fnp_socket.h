#ifndef FNP_SOCKET_H
#define FNP_SOCKET_H

#include "fnp_sockaddr.h"
#include "fnp_ring.h"

#define SOCKET_TX_BURST_NUM 16
#define RECV_BATCH_SIZE 32

typedef struct fsocket fsocket_t;

#define FSOCKET_FRONTEND_FLAG_EVENTFD 0x01u
#define FSOCKET_FRONTEND_FLAG_POLLING 0x02u

typedef enum fsocket_lifecycle
{
    fsocket_lifecycle_active = 0,
    fsocket_lifecycle_close_pending,
    fsocket_lifecycle_closing,
    fsocket_lifecycle_closed,
} fsocket_lifecycle_t;

// 与应用层交互的接口
typedef struct fsocket
{
    fsocket_type_t type; // 前后端共享的socket类型
    char name[48];       // socket的名称, 用于调试和日志

    fnp_ring_t *rx; // 从fnp-daemon接收数据的队列
    fnp_ring_t *tx; // 向fnp-daemon发送数据的队列

    int rx_efd_in_frontend;        // 前端监听rx是否有数据的eventfd
    int tx_efd_in_frontend;        // 前端触发tx，通知后端有数据
    int rx_efd_in_backend;         // 后端触发通知，通知前端有数据
    int tx_efd_in_backend;         // master监听tx是否有数据，socket在后端的唯一标识
    int direct_rx_efd_in_frontend; // frontend 直连写对端rx eventfd的dup fd

    int frontend_id;               // frontend_id为0的socket是可以释放的, 因为frontend不会再使用了
    int owner_worker;              // socket 逻辑归属的worker，用于control command路由
    int polling_worker;            // 负责发送轮询该socket的worker_id, polling_worker为-1表示还未加入轮询
    int recv_worker_id;            // 最近学习到的接收worker_id, -1表示未绑定本地hash
    u64 polling_tsc;               // 最后一次轮询到数据的时间戳
    fsocket_t *direct_peer;        // GTP-U LDP 的对端共享socket
    fsocket_t *direct_notify_peer; // 当前 direct_rx_efd 对应的对端socket
    fsockaddr_t direct_local;      // LDP 投递给对端应用时的本地地址信息
    fsockaddr_t direct_remote;     // LDP 投递给对端应用时的远端地址信息
    u32 frontend_flags;            // 前端共享状态位, 见FSOCKET_FRONTEND_FLAG_*
    u32 ref_count;                 // 共享对象引用计数，保护frontend/LDP并发访问
    u32 lifecycle_state;           // 见fsocket_lifecycle_t
    u32 frontend_attached;         // frontend 当前是否持有该共享socket
    u32 master_registered;         // master epoll 当前是否持有该socket的后端eventfd
    u32 polling_cmd_pending;       // add-poll command 是否已经入队，避免重复调度
    u32 close_requested;           // 应用层请求关闭socket
    u32 is_ready;                  // 连接已建立，后端设置
    u32 is_closed;                 // 连接已关闭, 后端设置
} fsocket_t;

#define fsocket(sock) ((fsocket_t *)sock)

#define is_gtpu_socket(socket) ((socket)->type == fsocket_type_gtpu)

static inline u32 fsocket_frontend_flags_load(const fsocket_t *socket)
{
    return __atomic_load_n(&socket->frontend_flags, __ATOMIC_ACQUIRE);
}

static inline void fsocket_ref_init(fsocket_t *socket)
{
    __atomic_store_n(&socket->ref_count, 1, __ATOMIC_RELAXED);
}

static inline void fsocket_ref_get(fsocket_t *socket)
{
    __atomic_add_fetch(&socket->ref_count, 1, __ATOMIC_ACQ_REL);
}

static inline void fsocket_ref_put(fsocket_t *socket)
{
    __atomic_sub_fetch(&socket->ref_count, 1, __ATOMIC_ACQ_REL);
}

static inline u32 fsocket_ref_count(const fsocket_t *socket)
{
    return __atomic_load_n(&socket->ref_count, __ATOMIC_ACQUIRE);
}

static inline u32 fsocket_lifecycle_load(const fsocket_t *socket)
{
    return __atomic_load_n(&socket->lifecycle_state, __ATOMIC_ACQUIRE);
}

static inline bool fsocket_request_close(fsocket_t *socket)
{
    if (socket == NULL)
    {
        return false;
    }

    socket->close_requested = 1;
    u32 state = fsocket_lifecycle_load(socket);
    while (state < fsocket_lifecycle_close_pending)
    {
        if (__atomic_compare_exchange_n(&socket->lifecycle_state,
                                        &state,
                                        fsocket_lifecycle_close_pending,
                                        false,
                                        __ATOMIC_ACQ_REL,
                                        __ATOMIC_ACQUIRE))
        {
            return true;
        }
    }

    return state == fsocket_lifecycle_close_pending;
}

static inline bool fsocket_enter_closing(fsocket_t *socket)
{
    if (socket == NULL)
    {
        return false;
    }

    u32 state = fsocket_lifecycle_load(socket);
    while (state < fsocket_lifecycle_closing)
    {
        if (__atomic_compare_exchange_n(&socket->lifecycle_state,
                                        &state,
                                        fsocket_lifecycle_closing,
                                        false,
                                        __ATOMIC_ACQ_REL,
                                        __ATOMIC_ACQUIRE))
        {
            return true;
        }
    }

    return false;
}

static inline void fsocket_mark_closed(fsocket_t *socket)
{
    if (socket == NULL)
    {
        return;
    }

    socket->is_closed = 1;
    __atomic_store_n(&socket->lifecycle_state, fsocket_lifecycle_closed, __ATOMIC_RELEASE);
}

static inline bool fsocket_is_closing(const fsocket_t *socket)
{
    return socket != NULL && fsocket_lifecycle_load(socket) >= fsocket_lifecycle_close_pending;
}

static inline bool fsocket_polling_try_schedule(fsocket_t *socket)
{
    if (socket == NULL || fsocket_is_closing(socket))
    {
        return false;
    }

    if (__atomic_load_n(&socket->polling_worker, __ATOMIC_ACQUIRE) >= 0)
    {
        return false;
    }

    return __atomic_exchange_n(&socket->polling_cmd_pending, 1, __ATOMIC_ACQ_REL) == 0;
}

static inline void fsocket_polling_clear_scheduled(fsocket_t *socket)
{
    if (socket == NULL)
    {
        return;
    }

    __atomic_store_n(&socket->polling_cmd_pending, 0, __ATOMIC_RELEASE);
}

static inline bool fsocket_polling_active_or_scheduled(const fsocket_t *socket)
{
    return socket != NULL &&
           (__atomic_load_n(&socket->polling_worker, __ATOMIC_ACQUIRE) >= 0 ||
            __atomic_load_n(&socket->polling_cmd_pending, __ATOMIC_ACQUIRE) != 0);
}

static inline void fsocket_master_set_registered(fsocket_t *socket, bool registered)
{
    if (socket == NULL)
    {
        return;
    }

    __atomic_store_n(&socket->master_registered, registered ? 1u : 0u, __ATOMIC_RELEASE);
}

static inline bool fsocket_master_registered(const fsocket_t *socket)
{
    return socket != NULL && __atomic_load_n(&socket->master_registered, __ATOMIC_ACQUIRE) != 0;
}

static inline bool fsocket_master_take_registered(fsocket_t *socket)
{
    return socket != NULL && __atomic_exchange_n(&socket->master_registered, 0, __ATOMIC_ACQ_REL) != 0;
}

static inline void fsocket_set_owner_worker(fsocket_t *socket, int worker_id)
{
    __atomic_store_n(&socket->owner_worker, worker_id, __ATOMIC_RELEASE);
}

static inline int fsocket_get_owner_worker(const fsocket_t *socket)
{
    return socket == NULL ? -1 : __atomic_load_n(&socket->owner_worker, __ATOMIC_ACQUIRE);
}

static inline void fsocket_attach_frontend(fsocket_t *socket, int frontend_id)
{
    if (socket == NULL)
    {
        return;
    }

    socket->frontend_id = frontend_id;
    if (__atomic_exchange_n(&socket->frontend_attached, 1, __ATOMIC_ACQ_REL) == 0)
    {
        fsocket_ref_get(socket);
    }
}

static inline bool fsocket_detach_frontend(fsocket_t *socket)
{
    if (socket == NULL)
    {
        return false;
    }

    socket->frontend_id = 0;
    if (__atomic_exchange_n(&socket->frontend_attached, 0, __ATOMIC_ACQ_REL) != 0)
    {
        fsocket_ref_put(socket);
        return true;
    }

    return false;
}

static inline fsocket_t *fsocket_direct_peer_load(const fsocket_t *socket)
{
    return socket == NULL ? NULL : __atomic_load_n(&socket->direct_peer, __ATOMIC_ACQUIRE);
}

static inline fsocket_t *fsocket_acquire_active(fsocket_t *socket)
{
    if (socket == NULL)
    {
        return NULL;
    }

    while (1)
    {
        if (fsocket_lifecycle_load(socket) >= fsocket_lifecycle_close_pending || socket->rx == NULL)
        {
            return NULL;
        }

        fsocket_ref_get(socket);
        if (fsocket_lifecycle_load(socket) < fsocket_lifecycle_close_pending && socket->rx != NULL)
        {
            return socket;
        }

        fsocket_ref_put(socket);
    }
}

static inline void fsocket_direct_peer_store(fsocket_t *socket, fsocket_t *peer)
{
    if (socket == NULL)
    {
        return;
    }

    __atomic_store_n(&socket->direct_peer, peer, __ATOMIC_RELEASE);
}

static inline fsocket_t *fsocket_acquire_direct_peer(const fsocket_t *socket)
{
    if (socket == NULL)
    {
        return NULL;
    }

    while (1)
    {
        fsocket_t *peer = fsocket_direct_peer_load(socket);
        if (peer == NULL)
        {
            return NULL;
        }

        fsocket_ref_get(peer);
        if (fsocket_direct_peer_load(socket) == peer &&
            fsocket_lifecycle_load(peer) < fsocket_lifecycle_close_pending &&
            peer->rx != NULL)
        {
            return peer;
        }

        fsocket_ref_put(peer);
        if (fsocket_direct_peer_load(socket) == peer)
        {
            return NULL;
        }
    }
}

static inline void fsocket_frontend_flags_set(fsocket_t *socket, u32 flags)
{
    __atomic_or_fetch(&socket->frontend_flags, flags, __ATOMIC_RELEASE);
}

static inline void fsocket_frontend_flags_clear(fsocket_t *socket, u32 flags)
{
    __atomic_and_fetch(&socket->frontend_flags, ~flags, __ATOMIC_RELEASE);
}

static inline bool fsocket_frontend_eventfd_enabled(const fsocket_t *socket)
{
    return (fsocket_frontend_flags_load(socket) & FSOCKET_FRONTEND_FLAG_EVENTFD) != 0;
}

static inline bool fsocket_frontend_polling_enabled(const fsocket_t *socket)
{
    return (fsocket_frontend_flags_load(socket) & FSOCKET_FRONTEND_FLAG_POLLING) != 0;
}

static inline bool fsocket_has_direct_path(const fsocket_t *socket)
{
    fsocket_t *peer = fsocket_direct_peer_load(socket);
    return socket != NULL && peer != NULL && peer->rx != NULL;
}

static inline bool fsocket_direct_notify_ready(const fsocket_t *socket)
{
    return socket != NULL && socket->direct_rx_efd_in_frontend >= 0 && socket->direct_notify_peer == socket->direct_peer;
}

// 小于socket_request_connect的值表示有数据待读取
typedef enum fsocket_event
{
    fsocket_event_data = 0x01,          // backend -> frontend, 有应用数据/新连接待处理
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
} fmbuf_info_t;

#define get_fmbuf_info(m) ((fmbuf_info_t *)rte_mbuf_to_priv(m))

#endif // FNP_SOCKET_H
