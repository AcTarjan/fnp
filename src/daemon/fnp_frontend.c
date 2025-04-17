#include "fnp_frontend.h"

#include "fnp_common.h"
#include "fnp_error.h"
#include "fnp_context.h"
#include "fnp_msg.h"
#include "hash.h"

#define FrontendTableSize 64

typedef struct frontend_info
{
    i32 pid;
    bool alive;   // 是否存活
    int fail_cnt; // 没有接收到心跳包的次数
} frontend_info_t;

int init_frontend_layer()
{
    fnp.frontendTbl = hash_create("FnpFrontendHashTable", FrontendTableSize, 4);
    if (fnp.frontendTbl == NULL)
    {
        return FNP_ERR_CREATE_HASH_TABLE;
    }

    return FNP_OK;
}

// 控制线程调用
int register_frontend(i32 pid)
{
    FNP_INFO("register new frontend: %d\n", pid);
    frontend_info_t *info = fnp_malloc(sizeof(frontend_info_t));
    if (info == NULL)
    {
        return FNP_ERR_MALLOC;
    }
    info->pid = pid;
    info->alive = true;
    info->fail_cnt = 0;

    if (!hash_add(fnp.frontendTbl, &pid, info))
    {
        fnp_free(info);
        return FNP_ERR_HASH_ADD;
    }

    return FNP_OK;
}

// 在控制线程运行，修改
void update_frontend_alive(i32 pid)
{
    // FNP_INFO("recv keepalive from pid: %d\n", pid);
    frontend_info_t *info = NULL;
    if (hash_lookup(fnp.frontendTbl, &pid, (void **)&info))
    {
        info->alive = true;
    }
}

static check_all_frontend()
{
    u32 next = 0;
    frontend_info_t *info = NULL;
    i32 *pid = 0;
    // 遍历所有的frontend
    while (hash_iterate(fnp.frontendTbl, (void **)&pid, (void **)&info, &next))
    {
        
        if (info->alive)
        {
            info->alive = false; // 重新发送
            info->fail_cnt = 0;
        }
        else
        {
            FNP_WARN("frontend %d lost keepalive\n", *pid, info->alive);
            info->fail_cnt++;
            // 超过3次，删除该frontend
            if (info->fail_cnt >= 3)
            {

                FNP_WARN("frontend %d fail to keepalive, start to delete!!!\n", *pid);
                hash_del(fnp.frontendTbl, pid);
                // TODO: 释放该前端所有的socket
                fnp_free(info);
            }
        }
    }
}

// main lcore调用，检查fnp-frontend是否正常
// 遍历 + 删除
void check_frontend_alive()
{
    FNP_INFO("start to check frontend alive!\n");
    while (1)
    {
        check_all_frontend();

        // 发送心跳包
        struct rte_mp_msg msg;
        msg.num_fds = 0;
        msg.len_param = 0;
        sprintf(msg.name, FNP_MSG_NAME_KEEPALIVE_REQ);
        rte_mp_sendmsg(&msg);
        sleep(10);
    }
}