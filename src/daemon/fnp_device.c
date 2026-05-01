#include "fnp_device.h"

#include "fnp_context.h"

#include <string.h>

#define device_context (get_fnp_context()->device)

fnp_device_type_t parse_device_type(const char *type)
{
    if (type == NULL || type[0] == '\0' || strcmp(type, "ethernet") == 0)
    {
        return fnp_device_type_ethernet;
    }

    return 0;
}

fnp_device_driver_t parse_device_driver(const char *driver)
{
    if (driver == NULL || driver[0] == '\0')
    {
        return fnp_device_driver_none;
    }

    if (strcmp(driver, "physical") == 0)
    {
        return fnp_device_driver_physical;
    }

    if (strcmp(driver, "dpdk_tap") == 0)
    {
        return fnp_device_driver_dpdk_tap;
    }

    return 0;
}

bool validate_device_type_driver(fnp_device_type_t type, fnp_device_driver_t driver)
{
    switch (type)
    {
    case fnp_device_type_ethernet:
        return driver == fnp_device_driver_physical || driver == fnp_device_driver_dpdk_tap;
    default:
        return false;
    }
}

int get_fnp_device_count(void)
{
    return device_context.count;
}

fnp_device_t *get_fnp_device(int index)
{
    if (unlikely(index < 0 || index >= device_context.count))
    {
        return NULL;
    }

    return &device_context.devices[index];
}

fnp_device_t *lookup_device_by_id(u16 device_id)
{
    for (int i = 0; i < device_context.count; ++i)
    {
        if (device_context.devices[i].id == device_id)
        {
            return &device_context.devices[i];
        }
    }

    return NULL;
}

fnp_device_t *lookup_device_by_name(const char *name)
{
    if (unlikely(name == NULL))
    {
        return NULL;
    }

    for (int i = 0; i < device_context.count; ++i)
    {
        if (strcmp(device_context.devices[i].name, name) == 0)
        {
            return &device_context.devices[i];
        }
    }

    return NULL;
}

fnp_device_t *lookup_device_by_port(u16 port_id)
{
    for (int i = 0; i < device_context.count; ++i)
    {
        if (device_context.devices[i].port_id == port_id)
        {
            return &device_context.devices[i];
        }
    }

    return NULL;
}

const struct rte_ether_addr *get_device_mac(const fnp_device_t *dev)
{
    return &dev->mac;
}
