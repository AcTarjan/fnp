
#ifndef FNP_FRONTEND_H
#define FNP_FRONTEND_H

#include "fnp_common.h"

int init_frontend_layer();

int register_frontend(i32 pid);

void update_frontend_alive(i32 pid);

void check_frontend_alive();

#endif // FNP_FRONTEND_H