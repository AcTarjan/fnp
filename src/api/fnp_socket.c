#include "fnp.h"

#include "fnp_api.h"
#include "fnp_common.h"
#include "fnp_error.h"
#include "fnp_internal.h"

#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_pause.h>
#include <string.h>
#include <unistd.h>

static int socket_conf_size(fsocket_type_t type)
{
    switch (type)
    {
    case fsocket_type_gtpu:
        return (int)sizeof(fnp_gtpu_socket_conf_t);
    default:
        return -1;
    }
}

static void request_close_shared_socket(fsocket_t *shared_socket)
{
    if (shared_socket == NULL)
    {
        return;
    }

    struct rte_mp_msg msg = {0};
    sprintf(msg.name, FAPI_CLOSE_FSOCKET_ACTION_NAME);
    msg.len_param = sizeof(fapi_common_req_t);
    ((fapi_common_req_t *)msg.param)->ptr = shared_socket;

    if (rte_mp_sendmsg(&msg) < 0)
    {
        FNP_WARN("fail to send close msg to fnp-daemon: %s", rte_strerror(rte_errno));
    }
}

static const fnp_gtpu_socket_conf_t *fnp_socket_gtpu_conf(const fnp_socket_t *socket)
{
    if (socket == NULL || socket->shared == NULL || socket->shared->type != fsocket_type_gtpu)
    {
        return NULL;
    }

    if (socket->conf_len < sizeof(fnp_gtpu_socket_conf_t))
    {
        return NULL;
    }

    return (const fnp_gtpu_socket_conf_t *)socket->conf;
}

int fnp_socket_create(fsocket_type_t type, const void *conf, fnp_socket_t **out)
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

    fapi_create_socket_req_t *req = (fapi_create_socket_req_t *)msg.param;
    req->frontend = frontend;
    req->type = type;
    req->conf_len = (u16)conf_size;
    memset(req->conf, 0, sizeof(req->conf));
    memcpy(req->conf, conf, conf_size);

    if (!(rte_mp_request_sync(&msg, &reply, &ts) == 0 && reply.nb_received == 1))
    {
        return FNP_ERR_TIMEOUT;
    }

    struct rte_mp_msg *reply_msg = &reply.msgs[0];
    fapi_create_socket_resp_t *resp = (fapi_create_socket_resp_t *)reply_msg->param;
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

    fsocket_t *shared_socket = resp->ptr;
    shared_socket->rx_efd_in_frontend = reply_msg->fds[0];
    shared_socket->tx_efd_in_frontend = reply_msg->fds[1];

    u16 resolved_conf_len = resp->conf_len;
    if (resolved_conf_len == 0)
    {
        resolved_conf_len = (u16)conf_size;
    }
    if (unlikely(resolved_conf_len > FAPI_SOCKET_CONF_MAX_LEN))
    {
        free(reply.msgs);
        return FNP_ERR_PARAM;
    }

    const void *resolved_conf = resolved_conf_len == 0 ? NULL : resp->conf;
    fnp_socket_t *socket = frontend_add_fsocket(shared_socket,
                                                resolved_conf == NULL ? conf : resolved_conf,
                                                resolved_conf_len);
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

int fnp_socket_get_conf(const fnp_socket_t *socket, void *conf, u16 *conf_len)
{
    if (socket == NULL || conf_len == NULL)
    {
        return FNP_ERR_PARAM;
    }

    if (*conf_len < socket->conf_len)
    {
        *conf_len = socket->conf_len;
        return FNP_ERR_FULL;
    }

    if (conf != NULL && socket->conf_len > 0)
    {
        memcpy(conf, socket->conf, socket->conf_len);
    }

    *conf_len = socket->conf_len;
    return FNP_OK;
}

int fnp_socket_close(fnp_socket_t *socket)
{
    if (socket == NULL || socket->shared == NULL)
    {
        return FNP_ERR_PARAM;
    }

    fsocket_t *shared_socket = socket->shared;
    frontend_remove_fsocket(socket);
    if (fsocket_request_close(shared_socket))
    {
        request_close_shared_socket(shared_socket);
    }
    return FNP_OK;
}

int fnp_socket_sendto(fnp_socket_t *socket, fnp_mbuf_t *m, const fsockaddr_t *peer)
{
    (void)socket;
    (void)m;
    (void)peer;
    return FNP_ERR_NOT_SUPPORTED;
}

static int fnp_socket_send_direct_gtpu(fnp_socket_t *socket, fnp_mbuf_t *m)
{
    fsocket_t *shared_socket = socket->shared;
    fsocket_t *peer = fsocket_acquire_direct_peer(shared_socket);
    if (unlikely(peer == NULL))
    {
        return FNP_ERR_NOT_FOUND;
    }

    fmbuf_info_t *info = get_fmbuf_info(m);
    fsockaddr_copy(&info->local, &shared_socket->direct_local);
    fsockaddr_copy(&info->remote, &shared_socket->direct_remote);

    if (unlikely(fnp_ring_enqueue(peer->rx, m) == 0))
    {
        fsocket_ref_put(peer);
        return FNP_ERR_FULL;
    }

    if (!fsocket_frontend_eventfd_enabled(peer) || fsocket_frontend_polling_enabled(peer))
    {
        fsocket_ref_put(peer);
        return FNP_OK;
    }

    if (!fsocket_direct_notify_ready(shared_socket))
    {
        (void)frontend_prepare_direct_notify_fd(shared_socket);
    }

    if (fsocket_direct_notify_ready(shared_socket))
    {
        eventfd_write(shared_socket->direct_rx_efd_in_frontend, 1);
    }

    fsocket_ref_put(peer);

    return FNP_OK;
}

int fnp_socket_send(fnp_socket_t *socket, fnp_mbuf_t *m)
{
    if (unlikely(socket == NULL || socket->shared == NULL || m == NULL))
    {
        return FNP_ERR_PARAM;
    }

    fsocket_t *shared_socket = socket->shared;
    if (unlikely(!is_gtpu_socket(shared_socket)))
    {
        return FNP_ERR_NOT_SUPPORTED;
    }

    bool has_direct_path = fsocket_direct_peer_load(shared_socket) != NULL;
    if (unlikely(!has_direct_path && shared_socket->direct_notify_peer != NULL))
    {
        frontend_release_direct_notify_fd(shared_socket);
    }

    if (likely(has_direct_path))
    {
        int ret = fnp_socket_send_direct_gtpu(socket, m);
        if (likely(ret != FNP_ERR_NOT_FOUND))
        {
            return ret;
        }

        if (shared_socket->direct_notify_peer != NULL)
        {
            frontend_release_direct_notify_fd(shared_socket);
        }
    }

    if (unlikely(fnp_ring_enqueue(shared_socket->tx, m) == 0))
    {
        return FNP_ERR_FULL;
    }

    if (likely(fsocket_polling_active_or_scheduled(shared_socket)))
    {
        return FNP_OK;
    }

    fsocket_notify_backend(shared_socket);
    return FNP_OK;
}

int fnp_socket_recvfrom(fnp_socket_t *socket, uint8_t *buf, int buf_len, fsockaddr_t *peer)
{
    if (socket == NULL || socket->shared == NULL || buf == NULL || buf_len < 0)
    {
        return FNP_ERR_PARAM;
    }

    struct rte_mbuf *m = NULL;
    while (frontend_try_dequeue_mbuf(socket, &m) == FNP_ERR_EMPTY)
    {
        if (socket->shared->is_closed && (socket->shared->rx == NULL || fnp_ring_count(socket->shared->rx) == 0))
        {
            return FNP_ERR_EOF;
        }

        rte_pause();
    }

    u8 *data = rte_pktmbuf_mtod(m, u8 *);
    int data_len = rte_pktmbuf_data_len(m);
    if (unlikely(data_len > buf_len))
    {
        data_len = buf_len;
    }

    memcpy(buf, data, data_len);
    if (peer != NULL)
    {
        fmbuf_info_t *info = get_fmbuf_info(m);
        fsockaddr_copy(peer, &info->remote);
    }

    fnp_free_mbuf(m);
    return data_len;
}

int fnp_socket_recv(fnp_socket_t *socket, uint8_t *buf, int buf_len)
{
    return fnp_socket_recvfrom(socket, buf, buf_len, NULL);
}
