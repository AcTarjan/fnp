#ifndef FNP_ERROR_H
#define FNP_ERROR_H

#define FNP_OK 0
#define FNP_ERR_GENERIC -1
#define FNP_ERR_CC_ALGO -2          //不支持的拥塞控制算法


// socket相关
#define FNP_ERR_CREATE_SOCKET -400     // 端口已被绑定
#define FNP_ERR_PORT_BIND -401     // 端口已被绑定
#define FNP_ERR_IFACE_NOT_FOUND -402 // 未找到ip对应的网卡
#define FNP_ERR_ALLOC_SOCKET -403    // socket内存分配失败
#define FNP_ERR_ALLOC_SOCKET_RX -404 // socket的rx ring分配失败
#define FNP_ERR_ALLOC_SOCKET_TX -405 // socket的tx ring分配失败
#define FNP_ERR_ADD_HASH -406        // 添加到hash表失败
#define FNP_ERR_NO_ARP_CACHE -407    // 未找到arp缓存
#define FNP_ERR_NO_FRONTEND -408    // 未找到前端
#define FNP_ERR_FRONTEND_REGISTERED -409    // 前端已注册
#define FNP_ERR_NO_SOCKET -410    // 未找到socket
#define FNP_ERR_NO_SOCKET_FD -411    // 未找到可用的socket fd

// RING相关
#define FNP_ERR_CREATE_RING -501
#define FNP_ERR_RING_FULL -502      // 环形队列已满
#define FNP_ERR_RING_EMPTY -503     // 环形队列为空


// DPDK相关
#define FNP_ERR_RTE_EAL_INIT -100
#define FNP_ERR_MALLOC -101
#define FNP_ERR_CREATE_MBUFPOOL -102
#define FNP_ERR_MBUF_ALLOC -103
#define FNP_ERR_MSG_TIMEOUT -104
#define FNP_ERR_MSG_PARAM_LEN -105
#define FNP_ERR_CREATE_HASH_TABLE -106
#define FNP_ERR_HASH_ADD -108

// MSG相关
#define FNP_ERR_MSG_REPLY_PID   -300
#define FNP_ERR_MSG_REPLY_EVENT   -301
#define FNP_ERR_MSG_REPLY_DATA_LEN   -302
#define FNP_ERR_CREATE_EPOLL   -303
#define FNP_ERR_CREATE_EVENTFD   -304
#define FNP_ERR_ADD_EVENTFD   -305
#define FNP_ERR_DEL_EVENTFD   -306

// QUIC相关
#define FNP_ERR_QUIC_PARSE_PACKET -200
#define FNP_ERR_QUIC_UNSUPPORTED_VERSION -201
#define FNP_ERR_QUIC_VERSION -202
#define FNP_ERR_QUIC_WRONG_PACKET_TYPE -203
#define FNP_ERR_QUIC_FIXED_BIT -204
#define FNP_ERR_QUIC_RESERVED_BIT -205
#define FNP_ERR_QUIC_FIND_CONN -206
#define FNP_ERR_QUIC_AEAD_NOT_READY -207
#define FNP_ERR_QUIC_DECRYPT_HEADER -208
#define FNP_ERR_QUIC_DECRYPT_PAYLOAD -209
#define FNP_ERR_QUIC_FIND_PATH -210
#define FNP_ERR_QUIC_STATELESS_RESET -211
#define FNP_ERR_QUIC_TOKEN -212


// ... existing code ...
#define CHECK_RET(ret)     \
    do                     \
    {                      \
        if (ret != FNP_OK) \
        {                  \
            return ret;    \
        }                  \
    } while (0)
// ... existing code ...

#endif // FNP_ERROR_H
