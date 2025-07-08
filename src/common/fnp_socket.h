#ifndef FNP_SOCKET_H
#define FNP_SOCKET_H

#include "fnp_sockaddr.h"
#include "fnp_iface.h"
#include "fnp_list.h"
#include "fnp_pring.h"

#include <rte_ip.h>


#define SOCKET_TX_BURST_NUM 16

typedef struct fnp_socket fsocket_t;
typedef void (*socket_handler)(fsocket_t*);


// 与应用层交互的接口
typedef struct fnp_socket
{
    fnp_protocol_t proto; // 协议类型
    fsockaddr_t local;
    fsockaddr_t remote;
    char name[48]; // socket的名称, 用于调试和日志
    socket_handler handler; // TCP,UDP和QUIC协议实体处理来自应用层/网络层的数据
    fnp_list_node_t worker_node; // 用于worker使用链表管理socket
    fnp_list_node_t frontend_node; // 用于frontend使用链表管理socket
    union
    {
        struct
        {
            fnp_pring_t* rx; // 从fnp-daemon接收数据的队列
            fnp_pring_t* tx; // 向fnp-daemon发送数据的队列
        };

        fnp_pring_t* pending_cnxs; // QUIC/TCP服务端收到的暂存的TCP or QUIC cnx
        fnp_pring_t* pending_streams; // QUIC cnx收到的暂存的QUIC Stream
    };

    int frontend_id; //frontend_id为0的socket是可以释放的, 因为frontend不会再使用了
    int worker_id; //服务端socket不需要记录worker_id, 因为服务端socket不需要发送数据; 接收数据时，新连接(不同的5元组)可能位于不同的worker.
    struct rte_mempool* pool;
    u32 is_local_communication : 1; // 是否是本地通信, remote的IP地址是本地的IP地址
    u32 request_syn : 1; // 应用层请求建立连接
    u32 is_ready : 1; // 连接已建立
    u32 request_close : 1; // 应用层请求关闭socket
    u32 receive_fin : 1; // 收到对方的fin
    void* sock[]; //指向协议实体
} fsocket_t;

#define fsocket(sock) ((fsocket_t *)sock)
#define is_server_socket(socket)   ((socket)->remote.ip == 0)
#define is_tcp_socket(socket)   ((socket)->proto == fnp_protocol_tcp)
#define is_udp_socket(socket)   ((socket)->proto == fnp_protocol_udp)
#define is_quic_socket(socket)   ((socket)->proto == fnp_protocol_quic)
#define is_tcp_server_socket(socket)   (is_tcp_socket(socket) && is_server_socket(socket))
#define is_udp_server_socket(socket)   (is_udp_socket(socket) && is_server_socket(socket))
#define is_quic_server_socket(socket)   (is_quic_socket(socket) && is_server_socket(socket))

// 应用层收到一个mbuf
static inline bool fnp_socket_enqueue_for_app(fsocket_t* socket, void* data)
{
    return fnp_pring_enqueue(socket->rx, data);
}

// 应用层发送一个mbuf
static inline bool fnp_socket_enqueue_for_net(fsocket_t* socket, void* data)
{
    return fnp_pring_enqueue(socket->tx, data);
}

// quic stream与应用层交互的接口
typedef struct fnp_quic_stream
{
    u64 stream_id;
    fnp_pring_t* rx;
    fnp_pring_t* tx;
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


#endif // FNP_SOCKET_H
