#ifndef FNP_TAP_H
#define FNP_TAP_H

#include "fnp_network.h"

#include <rte_mbuf.h>

int tap_module_init(void);

// Ether 层把完整以太网帧发往 tap device 时，从这里递交给绑定的 tap socket。
void tap_device_output(struct rte_mbuf* m, fnp_device_t* dev);

#endif // FNP_TAP_H
