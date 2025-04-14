#include "fnp_iface.h"
#include "fnp_context.h"

fnp_iface_t *lookup_iface(u32 ip)
{
    for (i32 i = 0; i < fnp.iface_num; ++i)
    {
        if (fnp.ifaces[i].ip == ip)
        {
            return &fnp.ifaces[i];
        }
    }

    return NULL;
}

fnp_iface_t *find_iface_for_outlet(u32 rip)
{
    for (i32 i = 0; i < fnp.iface_num; ++i)
    {
        fnp_iface_t *iface = &fnp.ifaces[i];
        if (iface->ip & iface->mask == rip & iface->mask)
        {
            return &fnp.ifaces[i];
        }
    }

    return &fnp.ifaces[0];
}

u32 find_next_hop(fnp_iface_t *iface, u32 rip)
{
    if ((iface->ip & iface->mask) != (rip & iface->mask))
    {
        return iface->gateway;
    }

    return rip;
}

// u32 find_next_hop(u32 rip)
// {
//     for (i32 i = 0; i < fnp.iface_num; ++i)
//     {
//         fnp_iface_t *iface = &fnp.ifaces[i];
//         if (iface->ip & iface->mask == rip & iface->mask)
//         {
//             return rip;
//         }
//     }

//     return fnp.ifaces[0].ip;
// }