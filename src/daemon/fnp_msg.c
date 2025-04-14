#include "fnp_msg.h"
#include "fnp_common.h"
#include "fnp_error.h"
#include "fnp_frontend.h"
#include "fnp_socket.h"

#include <rte_errno.h>
#include <rte_eal.h>

static int handle_register_msg(const struct rte_mp_msg *msg, const void *peer)
{
    if (msg->len_param != sizeof(register_req_t))
    {
        return FNP_ERR_MSG_PARAM_LEN;
    }

    register_req_t *req = (register_req_t *)msg->param;

    int ret = register_frontend(req->pid);

    struct rte_mp_msg reply;
    memset(&reply, 0, sizeof(reply));
    strcpy(reply.name, FNP_MSG_NAME_REGISTER);
    reply.len_param = sizeof(register_reply_t);
    register_reply_t *r = reply.param;
    r->code = ret;

    // 返回结果
    if (rte_mp_reply(&reply, peer) < 0)
    {
        FNP_WARN("error sending reply\n");
        return -2;
    }

    return FNP_OK;
}

static int handle_keeplive_resp(const struct rte_mp_msg *msg, const void *peer)
{
    if (msg->len_param != 4)
    {
        return FNP_ERR_MSG_PARAM_LEN;
    }

    int *pid = (int *)msg->param;
    update_frontend_alive(*pid);

    return FNP_OK;
}

static int create_socket_msg(const struct rte_mp_msg *msg, const void *peer)
{
    if (msg->len_param != sizeof(create_socket_req_t))
    {
        FNP_ERR("invalid create_socket_req_t!");
        return -1;
    }

    create_socket_req_t *req = (create_socket_req_t *)msg->param;

    struct rte_mp_msg reply;
    memset(&reply, 0, sizeof(reply));
    strcpy(reply.name, FNP_MSG_NAME_CREATE_SOCKET);
    reply.len_param = sizeof(create_socket_reply_t);
    create_socket_reply_t *r = reply.param;

    r->socket = create_socket(&req->addr, req->opt);
    FNP_INFO("create socket : %p\n", r->socket);
    r->code = FNP_OK;

    // 返回结果
    if (rte_mp_reply(&reply, peer) < 0)
    {
        FNP_WARN("error sending reply\n");
        return -2;
    }

    return 0;
}

static int socket_connect_msg(const struct rte_mp_msg *msg, const void *peer)
{
    if (msg->len_param != sizeof(socket_connect_req_t))
    {
        FNP_ERR("invalid msg!");
        return -1;
    }

    socket_connect_req_t *req = (socket_connect_req_t *)msg->param;
    int code = socket_connect(req->socket, req->rip, req->rport);

    // 构造响应
    struct rte_mp_msg reply;
    memset(&reply, 0, sizeof(reply));
    strcpy(reply.name, FNP_MSG_NAME_SOCKET_CONNECT);
    reply.len_param = sizeof(socket_connect_reply_t);
    socket_connect_reply_t *r = reply.param;
    r->code = code;

    // 返回结果
    if (rte_mp_reply(&reply, peer) < 0)
    {
        FNP_WARN("error sending reply\n");
        return -2;
    }

    return 0;
}

int init_msg_layer()
{
    int ret = rte_mp_action_register(FNP_MSG_NAME_REGISTER, handle_register_msg);
    if (ret && rte_errno != ENOTSUP)
        return -1;

    ret = rte_mp_action_register(FNP_MSG_NAME_KEEPALIVE_RESP, handle_keeplive_resp);
    if (ret && rte_errno != ENOTSUP)
        return -1;

    ret = rte_mp_action_register(FNP_MSG_NAME_CREATE_SOCKET, create_socket_msg);
    if (ret && rte_errno != ENOTSUP)
        return -1;

    ret = rte_mp_action_register(FNP_MSG_NAME_SOCKET_CONNECT, socket_connect_msg);
    if (ret && rte_errno != ENOTSUP)
        return -1;

    return 0;
}
