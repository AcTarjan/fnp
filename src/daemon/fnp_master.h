#ifndef FNP_MASTER_H
#define FNP_MASTER_H
#include "fnp_list.h"
#include "fnp_msg.h"
#include "fnp_socket.h"

typedef void (*fsocket_release_func_t)(fsocket_t *socket);

typedef enum
{
    master_ev_kind_timer,
    master_ev_kind_retire,
} master_ev_kind_t;

typedef struct
{
    master_ev_kind_t kind;
    int fd;
} master_ev_tag_t;

typedef struct fmaster_context
{
    fnp_list_t frontend_list;
    int epoll_fd;
    fchannel_t *retire_chan;
    master_ev_tag_t timer_tag;
    master_ev_tag_t retire_tag;
} fmaster_context_t;

extern fmaster_context_t master;

int init_fnp_master();

int fnp_master_add_fsocket(fsocket_t *socket);

int fnp_master_remove_fsocket(fsocket_t *socket);

int fnp_master_retire_fsocket(fsocket_t *socket, fsocket_release_func_t release);

void fnp_master_loop();

#endif // FNP_MASTER_H
