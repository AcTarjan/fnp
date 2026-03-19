#ifndef FNP_FNP_API_H
#define FNP_FNP_API_H

#include "fnp_sockaddr.h"

#define FAPI_REGISTER_ACTION_NAME "fapi_register"
#define FAPI_CREATE_FSOCKET_ACTION_NAME "fapi_create_fsocket"
#define FAPI_ACCEPT_FSOCKET_ACTION_NAME "fapi_accept_fsocket"
#define FAPI_CLOSE_FSOCKET_ACTION_NAME "fapi_close_fsocket"
#define FAPI_SOCKET_CONF_MAX_LEN 128

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
    fsocket_type_t type;
    u16 conf_len;
    u16 reserved0;
    u8 conf[FAPI_SOCKET_CONF_MAX_LEN];
} fapi_create_socket_req_t;

#endif //FNP_FNP_API_H
