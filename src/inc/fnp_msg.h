#ifndef FNP_MSG_H
#define FNP_MSG_H

#include <stdint.h>

#define SOCKET_RING_NAME_LEN 32

#define FNP_BIND_SOCKET_MSG_NAME      "bind_socket_msg"


typedef struct bind_socket_req
{
    uint32_t lip;
    uint32_t rip;
    uint16_t lport;
    uint16_t rport;
    uint8_t proto;
} bind_socket_req_t;

typedef struct bind_socket_reply
{
    char rx_name[SOCKET_RING_NAME_LEN];
    char tx_name[SOCKET_RING_NAME_LEN];
} bind_socket_reply_t;

#endif //FNP_MSG_H
