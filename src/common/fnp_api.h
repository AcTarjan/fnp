#ifndef FNP_FNP_API_H
#define FNP_FNP_API_H

#include "fnp_sockaddr.h"

#define FAPI_REGISTER_ACTION_NAME "fapi_register"
#define FAPI_CREATE_FSOCKET_ACTION_NAME "fapi_create_fsocket"
#define FAPI_ACCEPT_FSOCKET_ACTION_NAME "fapi_accept_fsocket"
#define FAPI_CLOSE_FSOCKET_ACTION_NAME "fapi_close_fsocket"

typedef struct fapi_common_req
{
    void* ptr; //
} fapi_common_req_t;

typedef struct fapi_common_resp
{
    int code; // 0: success, -1: error
    void* ptr;
} fapi_common_resp_t;

typedef struct fapi_create_socket_req
{
    fnp_protocol_t proto;
    fsockaddr_t local;
    fsockaddr_t remote;
    void* conf;
} fapi_create_socket_req_t;

#endif //FNP_FNP_API_H
