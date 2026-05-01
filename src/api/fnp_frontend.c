#define _GNU_SOURCE
#include "fnp_internal.h"

#include "fnp_api.h"
#include "fnp_error.h"
#include "fnp_mbuf.h"

#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_mempool.h>

#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <pthread.h>
#include <sched.h>
#include <unistd.h>

fnp_frontend_t *frontend = NULL;
fnp_frontend_local_t frontend_local = {0};

static int frontend_apply_init_conf(fnp_frontend_t *shared_frontend, const fnp_init_conf_t *conf)
{
    if (shared_frontend == NULL || conf == NULL)
    {
        return FNP_ERR_PARAM;
    }

    shared_frontend->id = conf->id;
    snprintf(shared_frontend->name, sizeof(shared_frontend->name), "%s", conf->name);
    return FNP_OK;
}

static int frontend_reserve_tables(u32 min_capacity)
{
    u32 old_capacity = frontend->socket_capacity;
    u32 new_capacity = old_capacity == 0 ? FNP_FRONTEND_INITIAL_FDS : old_capacity;
    while (new_capacity < min_capacity)
    {
        new_capacity <<= 1;
    }

    if (new_capacity == old_capacity)
    {
        return FNP_OK;
    }

    fsocket_t **new_shared_sockets = fnp_zmalloc(sizeof(*new_shared_sockets) * new_capacity);
    fnp_socket_t **new_local_sockets = calloc(new_capacity, sizeof(*new_local_sockets));
    if (new_shared_sockets == NULL || new_local_sockets == NULL)
    {
        fnp_free(new_shared_sockets);
        free(new_local_sockets);
        return FNP_ERR_MALLOC;
    }

    if (old_capacity > 0)
    {
        memcpy(new_shared_sockets, frontend->sockets, sizeof(*new_shared_sockets) * old_capacity);
        memcpy(new_local_sockets, frontend_local.sockets, sizeof(*new_local_sockets) * old_capacity);
    }

    fnp_free(frontend->sockets);
    free(frontend_local.sockets);

    frontend->sockets = new_shared_sockets;
    frontend->socket_capacity = new_capacity;
    frontend_local.sockets = new_local_sockets;
    frontend_local.capacity = new_capacity;
    return FNP_OK;
}

int frontend_init_tables(u32 initial_capacity)
{
    return frontend_reserve_tables(initial_capacity);
}

void frontend_cleanup_local_state(void)
{
    if (frontend_local.sockets != NULL)
    {
        for (u32 i = 0; i < frontend_local.capacity; ++i)
        {
            free(frontend_local.sockets[i]);
        }
    }

    free(frontend_local.sockets);
    memset(&frontend_local, 0, sizeof(frontend_local));
}

fnp_socket_t *frontend_add_fsocket(fsocket_t *shared_socket, const void *conf, u16 conf_len)
{
    if (shared_socket == NULL || conf_len > FAPI_SOCKET_CONF_MAX_LEN)
    {
        return NULL;
    }

    fnp_socket_t *socket = calloc(1, sizeof(*socket));
    if (socket == NULL)
    {
        return NULL;
    }

    socket->shared = shared_socket;
    socket->wait_epfd = -1;
    socket->conf_len = conf_len;
    if (conf_len > 0 && conf != NULL)
    {
        memcpy(socket->conf, conf, conf_len);
    }

    rte_spinlock_lock(&frontend->lock);
    if ((u32)frontend->socket_num >= frontend->socket_capacity)
    {
        int ret = frontend_reserve_tables(frontend->socket_capacity == 0 ? FNP_FRONTEND_INITIAL_FDS : frontend->socket_capacity + 1);
        if (ret != FNP_OK)
        {
            rte_spinlock_unlock(&frontend->lock);
            free(socket);
            return NULL;
        }
    }

    u32 slot_index = frontend->socket_capacity;
    for (u32 i = 0; i < frontend->socket_capacity; ++i)
    {
        if (frontend->sockets[i] == NULL)
        {
            slot_index = i;
            break;
        }
    }

    if (slot_index >= frontend->socket_capacity)
    {
        rte_spinlock_unlock(&frontend->lock);
        free(socket);
        return NULL;
    }

    socket->slot_index = slot_index;
    fsocket_attach_frontend(shared_socket, frontend->pid);
    frontend->sockets[slot_index] = shared_socket;
    frontend_local.sockets[slot_index] = socket;
    frontend->socket_num++;
    rte_spinlock_unlock(&frontend->lock);

    return socket;
}

void frontend_remove_fsocket(fnp_socket_t *socket)
{
    if (socket == NULL || socket->shared == NULL)
    {
        return;
    }

    fsocket_t *shared_socket = socket->shared;
    if (shared_socket->tx_efd_in_frontend >= 0)
    {
        close(shared_socket->tx_efd_in_frontend);
        shared_socket->tx_efd_in_frontend = -1;
    }

    rte_spinlock_lock(&frontend->lock);
    if (socket->slot_index < frontend->socket_capacity &&
        frontend_local.sockets[socket->slot_index] == socket)
    {
        frontend_local.sockets[socket->slot_index] = NULL;
        frontend->sockets[socket->slot_index] = NULL;
        frontend->socket_num--;
    }
    rte_spinlock_unlock(&frontend->lock);

    fsocket_detach_frontend(shared_socket);

    free(socket);
}

fnp_socket_t *frontend_get_fsocket(u32 slot_index)
{
    if (frontend == NULL || slot_index >= frontend_local.capacity)
    {
        return NULL;
    }

    return frontend_local.sockets[slot_index];
}


fnp_mbuf_t *fnp_alloc_mbuf()
{
    if (unlikely(frontend == NULL || frontend->pool == NULL))
    {
        return NULL;
    }

    return rte_pktmbuf_alloc(frontend->pool);
}

void fnp_free_mbuf(fnp_mbuf_t *m)
{
    rte_pktmbuf_free(m);
}

void fnp_free_mbuf_bulk(fnp_mbuf_t **m, u32 count)
{
    rte_pktmbuf_free_bulk(m, count);
}

const fnp_ifaddr_info_t *fnp_get_ifaddrs(u16 *ifaddr_count)
{
    if (ifaddr_count != NULL)
    {
        *ifaddr_count = frontend == NULL ? 0 : frontend->ifaddr_count;
    }

    if (frontend == NULL || frontend->ifaddr_count == 0)
    {
        return NULL;
    }

    return frontend->ifaddrs;
}

static void *keepalive_task(void *arg)
{
    (void)arg;

    while (1)
    {
        fnp_sleep(5000 * 1000);
        frontend->alive = 1;
    }
}

static fnp_frontend_t *create_frontend(void)
{
    fnp_frontend_t *shared_frontend = fnp_zmalloc(sizeof(*shared_frontend));
    if (shared_frontend == NULL)
    {
        return NULL;
    }

    shared_frontend->pid = getpid();
    shared_frontend->alive = 1;
    shared_frontend->fail_cnt = 0;
    shared_frontend->socket_num = 0;
    shared_frontend->socket_capacity = 0;
    shared_frontend->sockets = NULL;
    shared_frontend->pool_worker_id = (u16)-1;
    rte_spinlock_init(&shared_frontend->lock);
    return shared_frontend;
}

static int register_frontend_to_daemon(fnp_init_conf_t *conf)
{
    frontend = create_frontend();
    if (frontend == NULL)
    {
        return FNP_ERR_MALLOC;
    }

    if (frontend_init_tables(FNP_FRONTEND_INITIAL_FDS) != FNP_OK)
    {
        frontend_free(frontend);
        frontend = NULL;
        return FNP_ERR_MALLOC;
    }

    int ret = frontend_apply_init_conf(frontend, conf);
    if (ret != FNP_OK)
    {
        frontend_cleanup_local_state();
        frontend_free(frontend);
        frontend = NULL;
        return ret;
    }

    struct rte_mp_msg msg = {0};
    struct rte_mp_reply reply = {0};
    struct timespec ts = {.tv_sec = 5, .tv_nsec = 0};
    sprintf(msg.name, FAPI_REGISTER_ACTION_NAME);
    msg.num_fds = 0;
    msg.len_param = sizeof(fapi_register_req_t);
    ((fapi_register_req_t *)msg.param)->frontend = frontend;

    if (rte_mp_request_sync(&msg, &reply, &ts) == 0 && reply.nb_received == 1)
    {
        struct rte_mp_msg *reply_msg = &reply.msgs[0];
        fapi_common_resp_t *resp = (fapi_common_resp_t *)reply_msg->param;
        if (resp->code != FNP_OK)
        {
            frontend_cleanup_local_state();
            frontend_free(frontend);
            frontend = NULL;
            free(reply.msgs);
            return resp->code;
        }

        if (frontend->pool == NULL)
        {
            frontend_cleanup_local_state();
            frontend_free(frontend);
            frontend = NULL;
            free(reply.msgs);
            return FNP_ERR_CREATE_MBUFPOOL;
        }

        pthread_t ctrl_thread;
        ret = rte_ctrl_thread_create(&ctrl_thread, "fnp_keepalive_task", NULL,
                                     keepalive_task, NULL);
        if (ret != 0)
        {
            frontend_cleanup_local_state();
            frontend_free(frontend);
            frontend = NULL;
            free(reply.msgs);
            return ret;
        }

        free(reply.msgs);
        return FNP_OK;
    }

    frontend_cleanup_local_state();
    frontend_free(frontend);
    frontend = NULL;
    return FNP_ERR_TIMEOUT;
}

int fnp_init(fnp_init_conf_t *conf)
{
    if (conf == NULL || conf->main_lcore < 0 || conf->num_lcores < 0)
    {
        return FNP_ERR_PARAM;
    }

    if (conf->num_lcores > 0 && conf->lcores == NULL)
    {
        return FNP_ERR_PARAM;
    }

    char main_lcore_argv[32];
    snprintf(main_lcore_argv, sizeof(main_lcore_argv), "--main-lcore=%d", conf->main_lcore);

    const char *app_id = getenv("FNP_APP_ID");
    if (app_id == NULL || app_id[0] == 0)
    {
        app_id = "fnp";
    }

    char file_prefix_argv[64];
    snprintf(file_prefix_argv, sizeof(file_prefix_argv), "--file-prefix=%s", app_id);

    int argc = 6;
    char *argv[20] = {
        "fnp-api",
        "--proc-type=secondary",
        file_prefix_argv,
        "--iova-mode=pa",
        "--no-pci",
        main_lcore_argv,
    };

    u32 lcore_mask = 0;
    lcore_mask |= (1U << conf->main_lcore);
    for (int i = 0; i < conf->num_lcores; ++i)
    {
        lcore_mask |= (1U << conf->lcores[i]);
    }

    char lcore_argv[16];
    sprintf(lcore_argv, "-c %#x", lcore_mask);
    argv[argc++] = lcore_argv;

    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
    {
        return FNP_ERR_RTE_EAL_INIT;
    }

    ret = register_frontend_to_daemon(conf);
    CHECK_RET(ret);

    return FNP_OK;
}

int fnp_lcore_launch(unsigned lcore_id, fnp_lcore_func_t func, void *arg)
{
    if (func == NULL || lcore_id >= RTE_MAX_LCORE)
    {
        return FNP_ERR_PARAM;
    }

    return rte_eal_remote_launch(func, arg, lcore_id);
}

int fnp_lcore_wait(unsigned lcore_id)
{
    if (lcore_id >= RTE_MAX_LCORE)
    {
        return FNP_ERR_PARAM;
    }

    return rte_eal_wait_lcore(lcore_id);
}

unsigned fnp_lcore_id(void)
{
    return rte_lcore_id();
}
