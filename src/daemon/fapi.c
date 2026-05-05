#include "fapi.h"
#include "fnp_api.h"
#include "fnp_context.h"
#include "fnp_error.h"
#include "fnp_frontend.h"
#include "fnp_master.h"
#include "fsocket.h"
#include "gtpu.h"
#include "fnp_ifaddr.h"
#include "fnp_worker.h"

static u16 frontend_pool_next_worker = 0;

static void frontend_detach_worker_pool(fnp_frontend_t *frontend)
{
    if (frontend == NULL)
    {
        return;
    }

    frontend->pool = NULL;
    frontend->pool_worker_id = (u16)-1;
}

static int frontend_assign_worker_pool(fnp_frontend_t *frontend)
{
    if (frontend == NULL)
    {
        return FNP_ERR_PARAM;
    }

    const int worker_count = get_fnp_worker_count();
    if (worker_count <= 0)
    {
        FNP_ERR("no worker pool available for frontend %d\n", frontend->pid);
        return FNP_ERR_NOT_FOUND;
    }

    const u16 worker_id = frontend_pool_next_worker++ % (u16)worker_count;
    fnp_worker_t *worker = get_fnp_worker(worker_id);
    if (worker == NULL || worker->pool == NULL)
    {
        FNP_ERR("worker %u has no mbuf pool for frontend %d\n",
                worker_id,
                frontend->pid);
        return FNP_ERR_NOT_FOUND;
    }

    frontend->pool = worker->pool;
    frontend->pool_worker_id = worker_id;
    FNP_INFO("frontend %d uses worker mbuf pool=%s worker=%u\n",
             frontend->pid,
             worker->pool->name,
             worker_id);
    return FNP_OK;
}

int register_frontend_action(const struct rte_mp_msg *msg, const void *peer)
{
    int code = FNP_OK;

    if (unlikely(msg->len_param != sizeof(fapi_register_req_t)))
    {
        printf("invalid param length of fapi_register_req_t:  %d\n", msg->len_param);
        code = FNP_ERR_PARAM;
    }
    else
    {
        fapi_register_req_t *req = (fapi_register_req_t *)msg->param;
        fnp_frontend_t *frontend = req->frontend;
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
                code = frontend_assign_worker_pool(frontend);
                if (code == FNP_OK)
                {
                    code = export_fnp_ifaddrs(frontend->ifaddrs,
                                              (u16)RTE_DIM(frontend->ifaddrs),
                                              &frontend->ifaddr_count);
                    if (code != FNP_OK)
                    {
                        frontend_detach_worker_pool(frontend);
                    }
                }

                if (code == FNP_OK)
                {
                    // 注册前端
                    fnp_list_insert_head(&master.frontend_list, &frontend->master_node, frontend);
                    FNP_INFO("register frontend %d successfully\n", frontend->pid);
                }
            }
        }
    }

    // 不动态申请也可以？在前端释放的是什么？dpdk内部做了一次copy？
    struct rte_mp_msg reply = {0};
    strcpy(reply.name, FAPI_REGISTER_ACTION_NAME);
    reply.len_param = sizeof(fapi_common_resp_t);
    fapi_common_resp_t *resp = (fapi_common_resp_t *)reply.param;
    resp->code = code;

    if (rte_mp_reply(&reply, peer) < 0)
    {
        printf("error sending reply\n");
        return -3;
    }

    return FNP_OK;
}

int create_fsocket_action(const struct rte_mp_msg *msg, const void *peer)
{
    int code = FNP_OK;
    struct rte_mp_msg reply = {0};
    strcpy(reply.name, FAPI_CREATE_FSOCKET_ACTION_NAME);
    reply.len_param = sizeof(fapi_create_socket_resp_t);
    fapi_create_socket_resp_t *resp = (fapi_create_socket_resp_t *)reply.param;
    if (unlikely(msg->len_param != sizeof(fapi_create_socket_req_t)))
    {
        printf("invalid param length of fapi_register_req_t:  %d\n", msg->len_param);
        code = FNP_ERR_PARAM;
    }
    else
    {
        fapi_create_socket_req_t *param = (fapi_create_socket_req_t *)msg->param;
        void *conf = param->conf_len == 0 ? NULL : param->conf;
        fsocket_t *socket = create_fsocket(param->type, conf, param->frontend);
        if (likely(socket != NULL))
        {
            if (socket->tx_efd_in_backend >= 0)
            {
                reply.num_fds = 1;
                reply.fds[0] = socket->tx_efd_in_backend; // 前端发包时通知后端master
            }
            resp->ptr = socket;
            printf("create fsocket successfully: %s\n", socket->name);
        }
        else
        {
            code = FNP_ERR_CREATE_SOCKET;
        }
    }

    // 不动态申请也可以？在前端释放的是什么？dpdk内部做了一次copy？
    resp->code = code;
    if (rte_mp_reply(&reply, peer) < 0)
    {
        printf("error sending reply\n");
        return -3;
    }

    return FNP_OK;
}

int accept_fsocket_action(const struct rte_mp_msg *msg, const void *peer)
{
    int code = FNP_OK;
    struct rte_mp_msg reply = {0};
    strcpy(reply.name, FAPI_ACCEPT_FSOCKET_ACTION_NAME);
    reply.len_param = sizeof(fapi_common_resp_t);
    fapi_common_resp_t *resp = (fapi_common_resp_t *)reply.param;
    if (unlikely(msg->len_param != sizeof(fapi_common_req_t)))
    {
        printf("invalid param length of fapi_register_req_t:  %d\n", msg->len_param);
        code = FNP_ERR_PARAM;
    }
    else
    {
        fapi_common_req_t *req = (fapi_common_req_t *)msg->param;
        fsocket_t *socket = req->ptr;

        fsocket_t *new_socket = NULL;
        if (likely(fnp_ring_dequeue(socket->rx, (void **)&new_socket)))
        {
            if (new_socket->tx_efd_in_backend >= 0)
            {
                reply.num_fds = 1;
                reply.fds[0] = new_socket->tx_efd_in_backend; // 前端发包时通知后端master
            }
            resp->ptr = new_socket;
        }
        else
        {
            code = FNP_ERR_RING_EMPTY;
        }
    }

    // 不动态申请也可以？在前端释放的是什么？dpdk内部做了一次copy？
    resp->code = code;
    if (rte_mp_reply(&reply, peer) < 0)
    {
        printf("error sending reply\n");
        return -3;
    }

    return FNP_OK;
}

int close_fsocket_action(const struct rte_mp_msg *msg, const void *peer)
{
    (void)peer;
    if (unlikely(msg->len_param != sizeof(fapi_common_req_t)))
    {
        printf("invalid param length of connect_fsocket_action:  %d\n", msg->len_param);
        return -1;
    }

    fapi_common_req_t *req = (fapi_common_req_t *)msg->param;
    close_fsocket(req->ptr);

    return FNP_OK;
}
