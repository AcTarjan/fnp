#include "fnp_frontend.h"

#include <unistd.h>

#include "fnp_internal.h"
#include "fnp_msg.h"

fnp_frontend_t* frontend = NULL; //该前端上下文

static void keepalive_task()
{
    while (1)
    {
        rte_delay_us_sleep(5000 * 1000); // 5s
        frontend->alive = 1; //共享内存，直接修改
    }
}

static fnp_frontend_t* create_frontend()
{
    fnp_frontend_t* frontend = fnp_malloc(sizeof(fnp_frontend_t));
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

int register_frontend_to_daemon()
{
    frontend = create_frontend();
    if (frontend == NULL)
    {
        return FNP_ERR_MALLOC;
    }

    fnp_msg_t* msg = new_fmsg(frontend->pid, fmsg_type_register_frontend);
    msg->ptr = (void*)frontend;

    send_fmsg_with_reply(fnp_master_id, msg);
    if (msg->code != 0)
    {
        FNP_ERR("register frontend failed, code: %d\n", msg->code);
        fnp_free(msg);
        return -1;
    }
    fnp_free(msg);

    // 启动保活任务
    pthread_t ctrl_thread;
    int ret = rte_ctrl_thread_create(&ctrl_thread, "fnp_keepalive_task", NULL,
                                     keepalive_task, NULL);
    if (ret != 0)
    {
        RTE_LOG(ERR, EAL, "Failed to create control thread\n");
        return ret;
    }

    return FNP_OK;
}
