#include "fnp_internal.h"
#include "fnp_api.h"
#include "fnp_mbuf.h"
#include <unistd.h>


fnp_frontend_t* frontend = NULL; //该前端上下文

fnp_mbuf_t* fnp_alloc_mbuf()
{
    // 批量申请，提高效率，如果一次申请太多，时延会变大
#define ALLOC_BATCH_SIZE 8
    static struct rte_mbuf* alloc_mbufs[ALLOC_BATCH_SIZE];
    static int alloc_idx = ALLOC_BATCH_SIZE;

    if (unlikely(alloc_idx == ALLOC_BATCH_SIZE))
    {
        int ret = rte_pktmbuf_alloc_bulk(frontend->pool, alloc_mbufs, ALLOC_BATCH_SIZE);
        if (unlikely(ret != 0))
        {
            return NULL;
        }
        alloc_idx = 0;
    }

    return alloc_mbufs[alloc_idx++];
}


void fnp_free_mbuf(fnp_mbuf_t* m)
{
    // 批量释放
#define FREE_BATCH_SIZE 8
    static struct rte_mbuf* free_mbufs[FREE_BATCH_SIZE];
    static int free_index = 0;

    free_mbufs[free_index++] = m;

    if (unlikely(free_index == FREE_BATCH_SIZE))
    {
        free_index = 0;
        rte_pktmbuf_free_bulk(free_mbufs, FREE_BATCH_SIZE);
    }
}


// 保活线程
static void* keepalive_task(void* arg)
{
    while (1)
    {
        fnp_sleep(5000 * 1000); // 5s
        frontend->alive = 1; //共享内存，直接修改
    }
}

static fnp_frontend_t* create_frontend()
{
    fnp_frontend_t* frontend = fnp_zmalloc(sizeof(fnp_frontend_t));
    if (frontend == NULL)
    {
        return NULL;
    }

    frontend->pid = getpid();
    frontend->alive = 1;
    frontend->fail_cnt = 0;
    frontend->socket_num = 0;

    rte_spinlock_init(&frontend->lock);
    return frontend;
}

static int register_frontend_to_daemon()
{
    frontend = create_frontend();
    if (frontend == NULL)
    {
        return FNP_ERR_MALLOC;
    }
    printf("pid is %d\n", frontend->pid);

    struct rte_mp_msg msg = {0};
    struct rte_mp_reply reply = {0};
    struct timespec ts = {.tv_sec = 5, .tv_nsec = 0};
    sprintf(msg.name, FAPI_REGISTER_ACTION_NAME);
    msg.num_fds = 0;
    fapi_common_req_t* req = msg.param;
    msg.len_param = sizeof(fapi_common_req_t);
    req->ptr = frontend;

    //等待master返回响应
    if (rte_mp_request_sync(&msg, &reply, &ts) == 0 &&
        reply.nb_received == 1)
    {
        struct rte_mp_msg* reply_msg = &reply.msgs[0];
        fapi_common_resp_t* resp = (fapi_common_resp_t*)reply_msg->param;
        if (resp->code != FNP_OK)
        {
            frontend_free(frontend);
            return resp->code;
        }

        // 启动保活任务
        pthread_t ctrl_thread;
        int ret = rte_ctrl_thread_create(&ctrl_thread, "fnp_keepalive_task", NULL,
                                         keepalive_task, NULL);
        if (ret != 0)
        {
            RTE_LOG(ERR, EAL, "Failed to create control thread\n");
            return ret;
        }

        free(reply.msgs);
        return FNP_OK;
    }

    frontend_free(frontend);
    FNP_ERR("can't get reply from fnp-daemon");
    return -3;
}

int fnp_init(int main_lcore, int lcores[], int num_lcores)
{
    //初始化lcores
    char main_lcore_argv[16];
    sprintf(main_lcore_argv, "--main-lcore=%d", main_lcore);

    int argc = 5;
    char* argv[20] = {
        "fnp-api",
        "--proc-type=secondary",
        "--file-prefix=fnp",
        "--no-pci",
        main_lcore_argv,
    };

    u32 lcore_mask = 0;
    lcore_mask |= (1U << main_lcore); // 设置主lcore
    for (int i = 0; i < num_lcores; i++)
    {
        lcore_mask |= (1U << lcores[i]);
    }

    char lcore_argv[16];
    sprintf(lcore_argv, "-c %#x", lcore_mask);
    argv[argc++] = lcore_argv;

    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
    {
        printf("Error with EAL initialization\n");
        return -1;
    }

    // 向fnp-backend注册
    ret = register_frontend_to_daemon();
    CHECK_RET(ret);

    printf("fnp-frontend %d init successfully. main lcore: %d\n", frontend->pid, rte_lcore_id());
    return FNP_OK;
}
