#include "fnp.h"

#include "fnp_api.h"
#include "fnp_common.h"
#include "fnp_error.h"
#include "fnp_internal.h"

#include <rte_eal.h>
#include <rte_errno.h>
#include <string.h>
#include <unistd.h>

static int socket_conf_size(fsocket_type_t type)
{
    switch (type)
    {
        case fsocket_type_udp:
            return (int)sizeof(fnp_udp_socket_conf_t);
        case fsocket_type_tcp:
            return (int)sizeof(fnp_tcp_socket_conf_t);
        case fsocket_type_raw:
            return (int)sizeof(fnp_raw_socket_conf_t);
        default:
            return -1;
    }
}

static void request_close_shared_socket(fsocket_t* shared_socket)
{
    if (shared_socket == NULL)
    {
        return;
    }

    struct rte_mp_msg msg = {0};
    sprintf(msg.name, FAPI_CLOSE_FSOCKET_ACTION_NAME);
    msg.len_param = sizeof(fapi_common_req_t);
    ((fapi_common_req_t*)msg.param)->ptr = shared_socket;

    if (rte_mp_sendmsg(&msg) < 0)
    {
        FNP_WARN("fail to send close msg to fnp-daemon: %s", rte_strerror(rte_errno));
    }
}

static const fnp_udp_socket_conf_t* fnp_socket_udp_conf(const fnp_socket_t* socket)
{
    if (socket == NULL || socket->shared == NULL || socket->shared->type != fsocket_type_udp)
    {
        return NULL;
    }

    if (socket->conf_len < sizeof(fnp_udp_socket_conf_t))
    {
        return NULL;
    }

    return (const fnp_udp_socket_conf_t*)socket->conf;
}

int fnp_socket_create(fsocket_type_t type, const void* conf, fnp_socket_t** out)
{
    if (out == NULL)
    {
        return FNP_ERR_PARAM;
    }
    *out = NULL;

    int conf_size = socket_conf_size(type);
    if (unlikely(conf_size < 0))
    {
        return FNP_ERR_NOT_SUPPORTED;
    }
    if (unlikely(conf == NULL))
    {
        return FNP_ERR_PARAM;
    }
    if (unlikely(conf_size > FAPI_SOCKET_CONF_MAX_LEN))
    {
        return FNP_ERR_PARAM;
    }

    struct rte_mp_msg msg = {0};
    struct rte_mp_reply reply = {0};
    struct timespec ts = {.tv_sec = 5, .tv_nsec = 0};
    sprintf(msg.name, FAPI_CREATE_FSOCKET_ACTION_NAME);
    msg.len_param = sizeof(fapi_create_socket_req_t);

    fapi_create_socket_req_t* req = (fapi_create_socket_req_t*)msg.param;
    req->type = type;
    req->conf_len = (u16)conf_size;
    memset(req->conf, 0, sizeof(req->conf));
    memcpy(req->conf, conf, conf_size);

    if (!(rte_mp_request_sync(&msg, &reply, &ts) == 0 && reply.nb_received == 1))
    {
        return FNP_ERR_TIMEOUT;
    }

    struct rte_mp_msg* reply_msg = &reply.msgs[0];
    fapi_common_resp_t* resp = (fapi_common_resp_t*)reply_msg->param;
    if (resp->code != FNP_OK)
    {
        free(reply.msgs);
        return resp->code;
    }

    if (unlikely(reply_msg->num_fds != 2))
    {
        free(reply.msgs);
        return FNP_ERR_PARAM;
    }

    fsocket_t* shared_socket = resp->ptr;
    shared_socket->rx_efd_in_frontend = reply_msg->fds[0];
    shared_socket->tx_efd_in_frontend = reply_msg->fds[1];

    fnp_socket_t* socket = frontend_add_fsocket(shared_socket, conf, (u16)conf_size);
    free(reply.msgs);
    if (socket == NULL)
    {
        if (shared_socket->rx_efd_in_frontend >= 0)
        {
            close(shared_socket->rx_efd_in_frontend);
            shared_socket->rx_efd_in_frontend = -1;
        }
        if (shared_socket->tx_efd_in_frontend >= 0)
        {
            close(shared_socket->tx_efd_in_frontend);
            shared_socket->tx_efd_in_frontend = -1;
        }
        request_close_shared_socket(shared_socket);
        return FNP_ERR_MALLOC;
    }

    *out = socket;
    return FNP_OK;
}

int fnp_socket_close(fnp_socket_t* socket)
{
    if (socket == NULL || socket->shared == NULL)
    {
        return FNP_ERR_PARAM;
    }

    fsocket_t* shared_socket = socket->shared;
    frontend_remove_fsocket(socket);
    shared_socket->close_requested = 1;
    request_close_shared_socket(shared_socket);
    return FNP_OK;
}

int fnp_socket_sendto(fnp_socket_t* socket, fnp_mbuf_t* m, const fsockaddr_t* peer)
{
    if (socket == NULL || socket->shared == NULL || m == NULL || peer == NULL)
    {
        return FNP_ERR_PARAM;
    }

    if (!is_udp_socket(socket->shared))
    {
        return FNP_ERR_NOT_SUPPORTED;
    }

    const fnp_udp_socket_conf_t* udp_conf = fnp_socket_udp_conf(socket);
    if (udp_conf == NULL)
    {
        return FNP_ERR_PARAM;
    }

    fmbuf_info_t* info = get_fmbuf_info(m);
    fsockaddr_copy(&info->local, &udp_conf->local);
    fsockaddr_copy(&info->remote, peer);

    if (unlikely(fnp_ring_enqueue(socket->shared->tx, m) == 0))
    {
        return FNP_ERR_FULL;
    }

    if (unlikely(socket->shared->polling_worker < 0))
    {
        fsocket_notify_backend(socket->shared);
    }

    return FNP_OK;
}

int fnp_socket_send(fnp_socket_t* socket, fnp_mbuf_t* m)
{
    if (socket == NULL || socket->shared == NULL || m == NULL)
    {
        return FNP_ERR_PARAM;
    }

    if (is_udp_socket(socket->shared))
    {
        const fnp_udp_socket_conf_t* udp_conf = fnp_socket_udp_conf(socket);
        if (udp_conf == NULL || udp_conf->remote.ip == 0)
        {
            return FNP_ERR_PARAM;
        }

        return fnp_socket_sendto(socket, m, &udp_conf->remote);
    }

    if (!is_raw_socket(socket->shared))
    {
        return FNP_ERR_NOT_SUPPORTED;
    }

    if (unlikely(fnp_ring_enqueue(socket->shared->tx, m) == 0))
    {
        return FNP_ERR_FULL;
    }

    if (unlikely(socket->shared->polling_worker < 0))
    {
        fsocket_notify_backend(socket->shared);
    }

    return FNP_OK;
}

int fnp_socket_recvfrom(fnp_socket_t* socket, uint8_t* buf, int buf_len, fsockaddr_t* peer)
{
    if (socket == NULL || socket->shared == NULL || buf == NULL || buf_len < 0)
    {
        return FNP_ERR_PARAM;
    }

    struct rte_mbuf* m = NULL;
    while (frontend_try_dequeue_mbuf(socket, &m) == FNP_ERR_EMPTY)
    {
    }

    u8* data = rte_pktmbuf_mtod(m, u8*);
    int data_len = rte_pktmbuf_data_len(m);
    if (unlikely(data_len > buf_len))
    {
        data_len = buf_len;
    }

    memcpy(buf, data, data_len);
    if (peer != NULL)
    {
        fmbuf_info_t* info = get_fmbuf_info(m);
        fsockaddr_copy(peer, &info->remote);
    }

    fnp_free_mbuf(m);
    return data_len;
}

int fnp_socket_recv(fnp_socket_t* socket, uint8_t* buf, int buf_len)
{
    return fnp_socket_recvfrom(socket, buf, buf_len, NULL);
}
