#ifndef FNP_MASTER_H
#define FNP_MASTER_H
#include "fnp_list.h"
#include "fnp_socket.h"

typedef struct fmaster_context
{
    fnp_list_t frontend_list;
    int epoll_fd;
} fmaster_context_t;

extern fmaster_context_t master;

int init_fnp_master();

int fnp_master_add_fsocket(fsocket_t* socket);

void fnp_master_loop();

#endif //FNP_MASTER_H
