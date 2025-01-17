#ifndef SOCK_H
#define SOCK_H

#include "ipv4_5tuple.h"
#include <rte_ip.h>

typedef struct fnp_sock {
   union
   {
      struct
      {
         uint32_t remote_ip;
         uint32_t local_ip;
         uint16_t remote_port;
         uint16_t local_port;
         uint8_t  proto;
      };
      ipv4_5tuple_t key;
   };
   char rx_name[64];
   char tx_name[64];
   struct rte_ring* rx;
   struct rte_ring* tx;
} sock_t;

sock_t* sock_create(uint8_t proto, uint32_t lip, uint16_t lport, uint32_t rip, uint16_t rport);

int add_sock_to_hash(sock_t* sock);

bool lookup_sock_from_hash(ipv4_5tuple_t* key);

//接收数据包时，根据数据包的5元组信息查找对应的sock
sock_t* get_sock_from_hash(struct rte_ipv4_hdr* hdr);

void sock_free(sock_t* sock);

void sock_output();

#endif //SOCK_H
