#include "fnp_msg.h"
#include "fnp_common.h"
#include "fnp_sock.h"

#include <rte_errno.h>
#include <rte_eal.h>

#include "../api/fnp_api.h"

static int bind_sock_msg(const struct rte_mp_msg *msg, const void *peer)
{
    if (msg->len_param != sizeof(bind_socket_req_t)) {
        FNP_ERR("invalid bind_sock_msg!");
        return -1;
    }

    bind_socket_req_t *req = (bind_socket_req_t *)msg->param;
    FNP_INFO("recv bind socket msg: proto %d\n", req->proto);
    FNP_INFO("recv bind socket msg: local ip[%s]\n", ipv4_ntos(req->lip));
    FNP_INFO("recv bind socket msg: local port[%d]\n", req->lport);
    FNP_INFO("recv bind socket msg: remote ip[%d]\n", req->rip);
    FNP_INFO("recv bind socket msg: remote port[%d]\n", req->rport);

    sock_t* sock = sock_create(req->proto, req->lip, req->lport,
        req->rip, req->rport);
    if (sock == NULL)
    {
        FNP_ERR("create sock failed");
        return -2;
    }

    //不动态申请也可以？在前端释放的是什么？dpdk内部做了一次copy？
    struct rte_mp_msg reply;
    memset(&reply, 0, sizeof(reply));
    strcpy(reply.name, FNP_BIND_SOCKET_MSG_NAME);
    reply.len_param = sizeof(bind_socket_reply_t);
    bind_socket_reply_t* r = reply.param;
    sprintf(r->rx_name, sock->rx_name);
    sprintf(r->tx_name, sock->tx_name);

    if (rte_mp_reply(&reply, peer) < 0)
    {
        printf("error sending reply\n");
        return -3;
    }

    return 0;
}


int msg_init()
{
    int ret = rte_mp_action_register(FNP_BIND_SOCKET_MSG_NAME, bind_sock_msg);
    if (ret && rte_errno != ENOTSUP)
        return -1;

    return 0;
}

