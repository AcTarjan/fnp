#include "fnp_worker.h"
#include "fnp_msg.h"
#include "fnp_context.h"
#include "fnp_network.h"
#include "fnp_ring.h"

#include <sys/epoll.h>
#include <sys/eventfd.h>

#include <rte_per_lcore.h>
#include <unistd.h>

#include "arp.h"

// 每个lcore线程会拥有一个id实例
RTE_DEFINE_PER_LCORE(int, worker_id);
RTE_DEFINE_PER_LCORE(uint64_t, tsc_cycles);

#define MBUF_BURST_SIZE 64
#define FNP_WORKER_CONTROL_RING_SIZE 1024

int get_fnp_worker_count(void)
{
    return fnp.worker.count;
}

fnp_worker_t *get_local_worker(void)
{
    return get_fnp_worker(fnp_worker_id);
}

fnp_worker_t *get_fnp_worker(int id)
{
    if (unlikely(id < 0 || id >= fnp.worker.count))
    {
        return NULL;
    }

    return &fnp.worker.workers[id];
}

static void recv_data_from_nic()
{
    fnp_worker_t *worker = get_local_worker();

    for (int dev_index = 0; dev_index < get_fnp_device_count(); ++dev_index)
    {
        fnp_device_t *dev = get_fnp_device(dev_index);
        if (dev == NULL || dev->ops == NULL || dev->ops->recv == NULL)
        {
            continue;
        }

        dev->ops->recv(dev, worker->queue_id, MBUF_BURST_SIZE);
    }
}

static void send_data_to_net()
{
    fnp_worker_t *worker = get_local_worker();
    for (int dev_index = 0; dev_index < get_fnp_device_count(); ++dev_index)
    {
        fnp_device_t *dev = get_fnp_device(dev_index);
        if (unlikely(dev == NULL || !is_ethernet_device(dev)))
        {
            continue;
        }

        fnp_device_flush_tx(dev, worker->queue_id, MBUF_BURST_SIZE);
    }
}

static int fnp_worker_load(const fnp_worker_t *worker)
{
    return worker == NULL ? INT32_MAX : (int)(worker->recv_socket_count + worker->send_socket_count);
}

static fnp_worker_t *select_send_worker(void)
{
    fnp_worker_t *best = NULL;
    int best_load = INT32_MAX;
    for (int id = 0; id < get_fnp_worker_count(); ++id)
    {
        fnp_worker_t *worker = get_fnp_worker(id);
        int load = fnp_worker_load(worker);
        if (load < best_load)
        {
            best = worker;
            best_load = load;
        }
    }

    return best;
}

static fnp_worker_t *select_command_worker(const fsocket_t *socket)
{
    if (socket != NULL)
    {
        if (socket->polling_worker >= 0)
        {
            fnp_worker_t *worker = get_fnp_worker(socket->polling_worker);
            if (worker != NULL)
            {
                return worker;
            }
        }

        int owner_worker = fsocket_get_owner_worker(socket);
        if (owner_worker >= 0)
        {
            fnp_worker_t *worker = get_fnp_worker(owner_worker);
            if (worker != NULL)
            {
                return worker;
            }
        }

        if (socket->recv_worker_id >= 0)
        {
            fnp_worker_t *worker = get_fnp_worker(socket->recv_worker_id);
            if (worker != NULL)
            {
                return worker;
            }
        }
    }

    return select_send_worker();
}

static int worker_enqueue_command(fnp_worker_t *worker, fnp_worker_cmd_type_t type, fsocket_t *socket)
{
    if (worker == NULL || worker->control_ring == NULL || socket == NULL)
    {
        return FNP_ERR_PARAM;
    }

    fnp_worker_cmd_t *cmd = fnp_malloc(sizeof(*cmd));
    if (cmd == NULL)
    {
        worker->control_drops++;
        return FNP_ERR_MALLOC;
    }

    cmd->type = type;
    cmd->socket = socket;
    if (fnp_ring_enqueue(worker->control_ring, cmd) == 0)
    {
        worker->control_drops++;
        fnp_free(cmd);
        return FNP_ERR_RING_FULL;
    }

    return FNP_OK;
}

static int worker_add_fsocket_local(fnp_worker_t *worker, fsocket_t *socket)
{
    if (socket == NULL || worker == NULL || fsocket_is_closing(socket))
    {
        return FNP_OK;
    }

    fsocket_polling_clear_scheduled(socket);
    if (socket->polling_worker >= 0)
    {
        return FNP_OK;
    }

    if (worker->polling_count >= (int)RTE_DIM(worker->polling_table))
    {
        fsocket_polling_clear_scheduled(socket);
        return FNP_ERR_FULL;
    }

    socket->polling_worker = worker->id;
    fsocket_set_owner_worker(socket, worker->id);
    worker->polling_table[worker->polling_count++] = socket;
    worker->send_socket_count++;
    FNP_DEBUG("worker_add_fsocket_local: worker=%d socket=%s type=%d polling_count=%d\n",
              worker->id, socket->name, socket->type, worker->polling_count);
    return FNP_OK;
}

static int worker_remove_fsocket_local(fnp_worker_t *worker, fsocket_t *socket)
{
    if (socket == NULL)
    {
        return FNP_ERR_PARAM;
    }

    fsocket_polling_clear_scheduled(socket);

    if (worker == NULL)
    {
        worker = get_fnp_worker(socket->polling_worker);
    }
    if (worker == NULL || socket->polling_worker != worker->id)
    {
        socket->polling_worker = -1;
        return FNP_OK;
    }

    for (int i = 0; i < worker->polling_count; ++i)
    {
        if (worker->polling_table[i] != socket)
        {
            continue;
        }

        worker->polling_count--;
        worker->polling_table[i] = worker->polling_table[worker->polling_count];
        worker->polling_table[worker->polling_count] = NULL;
        if (worker->send_socket_count > 0)
        {
            worker->send_socket_count--;
        }
        break;
    }

    socket->polling_worker = -1;
    return FNP_OK;
}

int fnp_worker_add_fsocket(fsocket_t *socket)
{
    if (socket == NULL)
    {
        return FNP_ERR_PARAM;
    }

    if (!fsocket_polling_try_schedule(socket))
    {
        return FNP_OK;
    }

    fnp_worker_t *worker = select_command_worker(socket);
    if (worker == NULL)
    {
        fsocket_polling_clear_scheduled(socket);
        return FNP_ERR_NOT_FOUND;
    }

    int ret = worker_enqueue_command(worker, fnp_worker_cmd_add_poll, socket);
    if (ret != FNP_OK)
    {
        fsocket_polling_clear_scheduled(socket);
    }

    return ret;
}

int fnp_worker_remove_fsocket(fsocket_t *socket)
{
    if (socket == NULL)
    {
        return FNP_ERR_PARAM;
    }

    fnp_worker_t *worker = select_command_worker(socket);
    if (worker == NULL)
    {
        socket->polling_worker = -1;
        return FNP_ERR_NOT_FOUND;
    }

    return worker_enqueue_command(worker, fnp_worker_cmd_remove_poll, socket);
}

int fnp_worker_close_fsocket(fsocket_t *socket)
{
    fnp_worker_t *worker = select_command_worker(socket);
    if (worker == NULL)
    {
        return FNP_ERR_NOT_FOUND;
    }

    return worker_enqueue_command(worker, fnp_worker_cmd_close_socket, socket);
}

void fnp_worker_process_control(fnp_worker_t *worker)
{
    fnp_worker_cmd_t *cmd = NULL;
    while (fnp_ring_dequeue(worker->control_ring, (void **)&cmd) != 0)
    {
        if (cmd == NULL || cmd->socket == NULL)
        {
            fnp_free(cmd);
            continue;
        }

        switch (cmd->type)
        {
        case fnp_worker_cmd_add_poll:
            worker_add_fsocket_local(worker, cmd->socket);
            break;
        case fnp_worker_cmd_remove_poll:
            worker_remove_fsocket_local(worker, cmd->socket);
            break;
        case fnp_worker_cmd_close_socket:
        {
            const fsocket_ops_t *ops = get_fsocket_ops(cmd->socket->type);
            if (fsocket_enter_closing(cmd->socket))
            {
                worker_remove_fsocket_local(worker, cmd->socket);
                if (ops != NULL && ops->close != NULL)
                {
                    ops->close(cmd->socket);
                }
            }
            break;
        }
        default:
            break;
        }

        fnp_free(cmd);
    }
}

void fnp_worker_handle_polling_once(fnp_worker_t *worker, u64 tsc)
{
    int size = worker->polling_count;
    for (int i = 0; i < size; i++)
    {
        fsocket_t *socket = worker->polling_table[i];
        const fsocket_ops_t *ops = get_fsocket_ops(socket->type);
        fsocket_send_func send = ops == NULL ? NULL : ops->send;
        if (likely(send != NULL))
        {
            u32 pending = socket->tx == NULL ? 0 : fnp_ring_count(socket->tx);
            if (pending > 0)
            {
                FNP_DEBUG("worker_handle_polling: worker=%d socket=%s type=%d pending_tx=%u\n",
                          worker->id, socket->name, socket->type, pending);
            }
            send(socket, tsc); // 执行发送轮询
        }
        if (unlikely(tsc - socket->polling_tsc > RTE_PER_LCORE(tsc_cycles))) // 长时间没有数据, 不再polling
        {
            printf("remove fsocket from worker\n");
            worker_remove_fsocket_local(worker, socket);
            if (!fsocket_is_closing(socket) && socket->tx != NULL && fnp_ring_count(socket->tx) > 0)
            {
                // 退场窗口里如果应用刚写入了 tx ring，重新调度 polling，避免数据滞留。
                fnp_worker_add_fsocket(socket);
            }
            size--; // 数量减少
            i--;
        }
    }
}

// 尽量避免遍历，选择epoll来处理事件通知
// 尽量不要将mbuf保存在ofo队列或者pending队列内部，避免mbuf池耗尽
int fnp_worker_loop(void *arg)
{
    int id = *(int *)arg;
    RTE_PER_LCORE(worker_id) = id; // 初始化线程变量
    fnp_worker_t *worker = get_local_worker();

    i32 socket_id = rte_socket_id();
    i32 lcore_id = rte_lcore_id();
    printf("fnp_worker %d is running: lcore %d in socket %d\n", fnp_worker_id, lcore_id, socket_id);
    u64 cur_tsc, prev_tsc = 0;
    u64 hz = fnp_get_tsc_hz();
    RTE_PER_LCORE(tsc_cycles) = hz;
    u64 timer_timeout = hz / 1000; // 1ms
    while (1)
    {
        cur_tsc = fnp_get_tsc();

        // 收取底层device上的报文，并在device接收入口内完成协议分发
        recv_data_from_nic();

        //  每1ms检查定时器状态
        if (unlikely(cur_tsc - prev_tsc > timer_timeout))
        {
            rte_timer_manage(); // 检查定时器，触发重传
            prev_tsc = cur_tsc;
        }

        // 处理控制消息
        fnp_worker_process_control(worker);

        // polling发包
        fnp_worker_handle_polling_once(worker, cur_tsc);

        // 从网卡向网络发送数据
        send_data_to_net();
    }
}

int init_fnp_worker(worker_config *conf)
{
    if (conf == NULL)
    {
        return FNP_ERR_PARAM;
    }
    if (conf->lcores_count < 1 || conf->lcores_count > FNP_MAX_WORKER_NUM)
    {
        printf("init_fnp_worker: lcores_count %d out of range [1, %d]\n",
               conf->lcores_count, FNP_MAX_WORKER_NUM);
        return FNP_ERR_PARAM;
    }

    fnp.worker.count = conf->lcores_count;
    printf("fnp_worker_count = %d\n", fnp.worker.count);
    for (int id = 0; id < fnp.worker.count; id++)
    {
        fnp_worker_t *worker = get_fnp_worker(id);
        worker->id = id;
        worker->queue_id = id;
        worker->lcore_id = conf->lcores[id];
        i32 socket_id = (i32)rte_lcore_to_socket_id(worker->lcore_id);

        worker->polling_count = 0;
        worker->recv_socket_count = 0;
        worker->send_socket_count = 0;
        worker->control_drops = 0;

        // 初始化arp pending table
        char arp_name[32] = {0};
        sprintf(arp_name, "worker%d_arp_tbl", id);
        worker->arp_table = hash_create(arp_name, 256, sizeof(arp_key_t));
        if (worker->arp_table == NULL)
        {
            return FNP_ERR_CREATE_HASH_TABLE;
        }

        worker->epoll_fd = fmsg_epoll_create();
        if (worker->epoll_fd < 0)
        {
            printf("create epoll fd failed!\n");
            return FNP_ERR_CREATE_EPOLL;
        }

        worker->control_ring = fnp_ring_create(FNP_WORKER_CONTROL_RING_SIZE, true, false);
        if (worker->control_ring == NULL)
        {
            return FNP_ERR_GENERIC;
        }

        worker->gtpu_rx_tbl = NULL;

        char pool_name[32] = {0};
        sprintf(pool_name, "worker%d_mbuf_pool", id);
        worker->pool = rte_pktmbuf_pool_create(pool_name, conf->mbuf_pool_size, 0,
                                               FNP_MBUFPOOL_PRIV_SIZE,
                                               RTE_MBUF_DEFAULT_BUF_SIZE - FNP_MBUFPOOL_PRIV_SIZE, socket_id);
        if (worker->pool == NULL)
        {
            printf("%d create gDirectPool failed! rte_errno=%d(%s), socket_id=%d, pool_size=%d\n",
                   id, rte_errno, rte_strerror(rte_errno), socket_id, conf->mbuf_pool_size);
            return FNP_ERR_CREATE_MBUFPOOL;
        }

        char rx_pool_name[32] = {0};
        sprintf(rx_pool_name, "worker%d_rx_pool", id);
        worker->rx_pool = rte_pktmbuf_pool_create(rx_pool_name, conf->rx_pool_size, 0,
                                                  FNP_MBUFPOOL_PRIV_SIZE,
                                                  RTE_MBUF_DEFAULT_BUF_SIZE - FNP_MBUFPOOL_PRIV_SIZE, socket_id);
        if (worker->rx_pool == NULL)
        {
            printf("create rx pool failed! rte_errno=%d(%s), socket_id=%d, pool_size=%d\n",
                   rte_errno, rte_strerror(rte_errno), socket_id, conf->rx_pool_size);
            return FNP_ERR_CREATE_MBUFPOOL;
        }

        char clone_pool_name[32] = {0};
        sprintf(clone_pool_name, "worker%d_clone_pool", id);
        worker->clone_pool = rte_pktmbuf_pool_create(clone_pool_name, conf->clone_pool_size, 0,
                                                     FNP_MBUFPOOL_PRIV_SIZE,
                                                     RTE_MBUF_DEFAULT_BUF_SIZE - FNP_MBUFPOOL_PRIV_SIZE, socket_id);
        if (worker->clone_pool == NULL)
        {
            printf("create clone pool failed! rte_errno=%d(%s), socket_id=%d, pool_size=%d\n",
                   rte_errno, rte_strerror(rte_errno), socket_id, conf->clone_pool_size);
            return FNP_ERR_CREATE_MBUFPOOL;
        }
    }

    FNP_INFO("fnp_worker init successfully\n");
    return FNP_OK;
}

int start_fnp_worker()
{
    for (int id = 0; id < fnp.worker.count; id++)
    {
        fnp_worker_t *worker = get_fnp_worker(id);
        if (rte_eal_remote_launch(fnp_worker_loop, &worker->id, worker->lcore_id) != 0)
        {
            printf("launch %d error!\n", worker->lcore_id);
            return -1;
        }
    }

    return 0;
}
