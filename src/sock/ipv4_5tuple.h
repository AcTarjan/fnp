#ifndef IP_5TUPLE_H
#define IP_5TUPLE_H

#include <rte_hash.h>

#define IPV6_ADDR_LEN 16

typedef struct ipv4_5tuple {
    uint32_t remote_ip;
    uint32_t local_ip;
    uint16_t remote_port;
    uint16_t local_port;
    uint8_t  proto;
} ipv4_5tuple_t __rte_packed;

typedef struct ipv6_5tuple {
    uint8_t  ip_dst[IPV6_ADDR_LEN];
    uint8_t  ip_src[IPV6_ADDR_LEN];
    uint16_t port_dst;
    uint16_t port_src;
    uint8_t  proto;
} ipv6_5tuple_t __rte_packed;


struct rte_hash* create_ipv4_5tuple_hash(int socket_id);

// 成功：=0       失败：<0
int ipv4_5tuple_add(struct rte_hash* hash, ipv4_5tuple_t *key, void* value);

int ipv4_5tuple_remove(struct rte_hash* hash, ipv4_5tuple_t *key);

bool ipv4_5tuple_lookup(struct rte_hash* hash, ipv4_5tuple_t *key);

// 成功：>=0       失败：<0
int ipv4_5tuple_get_value(struct rte_hash* hash, void *ipv4_hdr, void** value);



#endif //IP_5TUPLE_H
