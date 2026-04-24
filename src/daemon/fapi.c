#include "fapi.h"
#include "fnp_api.h"
#include "fnp_error.h"
#include "fnp_frontend.h"
#include "fnp_master.h"
#include "fsocket.h"
#include "gtpu.h"
#include "network/fnp_network.h"
#include "fnp_worker.h"

static u32 frontend_pool_round_robin = 0;

static fnp_worker_t *pick_frontend_pool_worker(void)
{
    int worker_count = get_fnp_worker_count();
    if (worker_count <= 0)
    {
        return NULL;
    }

    u32 index = __atomic_fetch_add(&frontend_pool_round_robin, 1, __ATOMIC_RELAXED);
    return get_fnp_worker((int)(index % (u32)worker_count));
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
                fnp_worker_t *worker = pick_frontend_pool_worker();
                frontend->pool = worker == NULL ? NULL : worker->pool;
                frontend->pool_worker_id = worker == NULL ? (u16)-1 : (u16)worker->id;
                if (frontend->pool == NULL)
                {
                    FNP_ERR("fail to bind shared frontend pool");
                    code = FNP_ERR_CREATE_MBUFPOOL;
                }
                else
                {
                    code = export_network_ifaddrs(frontend->ifaddrs,
                                                  (u16)RTE_DIM(frontend->ifaddrs),
                                                  &frontend->ifaddr_count);
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
            u16 conf_len = sizeof(resp->conf);
            int export_ret = export_fsocket_conf(socket, resp->conf, &conf_len);
            if (export_ret != FNP_OK)
            {
                code = export_ret;
                close_fsocket(socket);
            }
            else
            {
                reply.num_fds = 2;
                reply.fds[0] = socket->rx_efd_in_backend; // 将eventfd传递回去
                reply.fds[1] = socket->tx_efd_in_backend; // 将eventfd传递回去
                resp->ptr = socket;
                resp->conf_len = conf_len;
                printf("create fsocket successfully: %s\n", socket->name);
            }
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
            reply.num_fds = 2;
            reply.fds[0] = new_socket->rx_efd_in_backend; // 将eventfd传递回去
            reply.fds[1] = new_socket->tx_efd_in_backend; // 将eventfd传递回去
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

int gtpu_ldp_attach_action(const struct rte_mp_msg *msg, const void *peer)
{
    int code = FNP_OK;
    struct rte_mp_msg reply = {0};
    strcpy(reply.name, FAPI_GTPU_LDP_ATTACH_ACTION_NAME);
    reply.len_param = sizeof(fapi_common_resp_t);
    fapi_common_resp_t *resp = (fapi_common_resp_t *)reply.param;

    if (unlikely(msg->len_param != sizeof(fapi_common_req_t)))
    {
        code = FNP_ERR_PARAM;
    }
    else
    {
        fapi_common_req_t *req = (fapi_common_req_t *)msg->param;
        fsocket_t *socket = req->ptr;
        fsocket_t *peer_socket = socket == NULL ? NULL : fsocket_acquire_direct_peer(socket);
        if (socket == NULL || socket->type != fsocket_type_gtpu || peer_socket == NULL ||
            peer_socket->rx_efd_in_backend < 0)
        {
            code = FNP_ERR_NOT_FOUND;
        }
        else
        {
            reply.num_fds = 1;
            reply.fds[0] = peer_socket->rx_efd_in_backend;
            resp->ptr = peer_socket;
        }
    }

    resp->code = code;
    if (rte_mp_reply(&reply, peer) < 0)
    {
        if (code == FNP_OK)
        {
            fsocket_ref_put((fsocket_t *)resp->ptr);
        }
        printf("error sending reply\n");
        return -3;
    }

    if (code == FNP_OK)
    {
        fsocket_ref_put((fsocket_t *)resp->ptr);
    }

    return FNP_OK;
}
