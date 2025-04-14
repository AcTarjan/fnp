#ifndef FNP_ERROR_H
#define FNP_ERROR_H

#define FNP_OK 0
#define FNP_ERR_GENERIC -1

// socket相关
#define FNP_ERR_PORT_BINDED -10     // 端口已被绑定
#define FNP_ERR_IFACE_NOT_FOUND -11 // 未找到ip对应的网卡
#define FNP_ERR_ALLOC_SOCKET -12    // socket内存分配失败
#define FNP_ERR_ALLOC_SOCKET_RX -13 // socket的rx ring分配失败
#define FNP_ERR_ALLOC_SOCKET_TX -14 // socket的tx ring分配失败
#define FNP_ERR_ADD_HASH -15        // 添加到hash表失败
#define FNP_ERR_NO_ARP_CACHE -16    // 未找到arp缓存

// DPDK相关
#define FNP_ERR_RTE_EAL_INIT -100
#define FNP_ERR_MALLOC -101
#define FNP_ERR_MBUF_ALLOC -102
#define FNP_ERR_MSG_TIMEOUT -103
#define FNP_ERR_MSG_PARAM_LEN -104
#define FNP_ERR_CREATE_HASH_TABLE -105
#define FNP_ERR_HASH_ADD -106

// ... existing code ...
#define CHECK_RET(ret)  \
    do                  \
    {                   \
        if (ret < 0)    \
        {               \
            return ret; \
        }               \
    } while (0)
// ... existing code ...

#endif // FNP_ERROR_H
