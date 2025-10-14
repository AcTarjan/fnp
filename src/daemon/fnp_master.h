#ifndef FNP_MASTER_H
#define FNP_MASTER_H
#include "fnp_msg.h"
#include "fnp_list.h"

typedef struct fmaster_context
{
    fchannel_t* chan;
    fnp_list_t frontend_list;
    int epoll_fd;
} fmaster_context_t;

extern fmaster_context_t master;

int init_fnp_master();

void fnp_master_loop();

#endif //FNP_MASTER_H
