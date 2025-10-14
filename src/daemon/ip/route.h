#ifndef FNP_ROUTE_H
#define FNP_ROUTE_H

#include "fnp_iface.h"

typedef struct route_entry
{
    u32 ip;
    u32 mask;
    u32 next_hop; //下一跳路由
    fnp_iface_t* iface; //出口
} route_entry_t;

typedef struct route_table
{
} route_table_t;

#endif //FNP_ROUTE_H
