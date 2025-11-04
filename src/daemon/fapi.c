#include "fapi.h"
#include "fnp_api.h"
#include "fnp_error.h"
#include "fnp_frontend.h"
#include "fnp_master.h"
#include "fsocket.h"

int register_frontend_action(const struct rte_mp_msg* msg, const void* peer)
{
    int code = FNP_OK;

    if (unlikely(msg->len_param != sizeof(fapi_common_req_t)))
    {
        printf("invalid param length of fapi_register_req_t:  %d\n", msg->len_param);
        code = FNP_ERR_PARAM;
    }
    else
    {
        fapi_common_req_t* req = (fapi_common_req_t*)msg->param;
        fnp_frontend_t* frontend = req->ptr;
        if (frontend == NULL)
        {
            code = FNP_ERR_NO_FRONTEND;
        }
        else
        {
            FNP_INFO("start to register frontend: %d\n", frontend->pid);
            if (fnp_list_find(&master.frontend_list, frontend))
            {
                code = FNP_ERR_FRONTEND_REGISTERED;
            }
            else
            {
                //为前端分配mbuf pool
                char pool_name[32];
                // 1024 * 128 * 2048 = 256MB
                snprintf(pool_name, sizeof(pool_name), "fe_pool_%d", frontend->pid);
                frontend->pool = rte_pktmbuf_pool_create(pool_name, 1024 * 128 - 1, 0, FNP_MBUFPOOL_PRIV_SIZE,
                                                         RTE_MBUF_DEFAULT_BUF_SIZE - FNP_MBUFPOOL_PRIV_SIZE,
                                                         rte_socket_id());
                if (frontend->pool == NULL)
                {
                    FNP_ERR("fail to create %s", pool_name);
                    code = FNP_ERR_CREATE_MBUFPOOL;
                }
                else
                {
                    // 注册前端
                    fnp_list_insert_head(&master.frontend_list, &frontend->master_node, frontend);
                    FNP_INFO("register frontend %d successfully\n", frontend->pid);
                }
            }
        }
    }

    //不动态申请也可以？在前端释放的是什么？dpdk内部做了一次copy？
    struct rte_mp_msg reply = {0};
    strcpy(reply.name, FAPI_REGISTER_ACTION_NAME);
    reply.len_param = sizeof(fapi_common_resp_t);
    fapi_common_resp_t* resp = reply.param;
    resp->code = code;

    if (rte_mp_reply(&reply, peer) < 0)
    {
        printf("error sending reply\n");
        return -3;
    }

    return FNP_OK;
}

int create_fsocket_action(const struct rte_mp_msg* msg, const void* peer)
{
    int code = FNP_OK;
    struct rte_mp_msg reply = {0};
    strcpy(reply.name, FAPI_CREATE_FSOCKET_ACTION_NAME);
    reply.len_param = sizeof(fapi_common_resp_t);
    fapi_common_resp_t* resp = reply.param;
    if (unlikely(msg->len_param != sizeof(fapi_create_socket_req_t)))
    {
        printf("invalid param length of fapi_register_req_t:  %d\n", msg->len_param);
        code = FNP_ERR_PARAM;
    }
    else
    {
        fapi_create_socket_req_t* param = (fapi_create_socket_req_t*)msg->param;
        fsocket_t* socket = create_fsocket(param->proto, &param->local, &param->remote, param->conf, -1);
        if (likely(socket != NULL))
        {
            reply.num_fds = 2;
            reply.fds[0] = socket->rx_efd_in_backend; //将eventfd传递回去
            reply.fds[1] = socket->tx_efd_in_backend; //将eventfd传递回去
            resp->ptr = socket;
            printf("create fsocket successfully: %s\n", socket->name);
        }
        else
        {
            code = FNP_ERR_CREATE_SOCKET;
        }
    }

    //不动态申请也可以？在前端释放的是什么？dpdk内部做了一次copy？
    resp->code = code;
    if (rte_mp_reply(&reply, peer) < 0)
    {
        printf("error sending reply\n");
        return -3;
    }

    return FNP_OK;
}

int accept_fsocket_action(const struct rte_mp_msg* msg, const void* peer)
{
    int code = FNP_OK;
    struct rte_mp_msg reply = {0};
    strcpy(reply.name, FAPI_ACCEPT_FSOCKET_ACTION_NAME);
    reply.len_param = sizeof(fapi_common_resp_t);
    fapi_common_resp_t* resp = reply.param;
    if (unlikely(msg->len_param != sizeof(fapi_common_req_t)))
    {
        printf("invalid param length of fapi_register_req_t:  %d\n", msg->len_param);
        code = FNP_ERR_PARAM;
    }
    else
    {
        fapi_common_req_t* req = (fapi_common_req_t*)msg->param;
        fsocket_t* socket = req->ptr;

        fsocket_t* new_socket = NULL;
        if (likely(fnp_ring_dequeue(socket->rx, (void**)&new_socket)))
        {
            reply.num_fds = 2;
            reply.fds[0] = new_socket->rx_efd_in_backend; //将eventfd传递回去
            reply.fds[1] = new_socket->tx_efd_in_backend; //将eventfd传递回去
            resp->ptr = new_socket;
        }
        else
        {
            code = FNP_ERR_RING_EMPTY;
        }
    }

    //不动态申请也可以？在前端释放的是什么？dpdk内部做了一次copy？
    resp->code = code;
    if (rte_mp_reply(&reply, peer) < 0)
    {
        printf("error sending reply\n");
        return -3;
    }

    return FNP_OK;
}

int close_fsocket_action(const struct rte_mp_msg* msg, const void* peer)
{
    if (unlikely(msg->len_param != sizeof(fapi_common_req_t)))
    {
        printf("invalid param length of connect_fsocket_action:  %d\n", msg->len_param);
        return -1;
    }

    fapi_common_req_t* req = (fapi_common_req_t*)msg->param;
    close_fsocket(req->ptr);

    return FNP_OK;
}
