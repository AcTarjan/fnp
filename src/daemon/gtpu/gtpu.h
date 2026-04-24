#ifndef FNP_GTPU_H
#define FNP_GTPU_H

#include "fnp.h"
#include "fnp_socket.h"
#include <rte_mbuf.h>

#define FNP_GTPU_UDP_PORT 2152

int gtpu_module_init(void);

void gtpu_udp_input(struct rte_mbuf *m);

int gtpu_export_socket_conf(const fsocket_t *socket, fnp_gtpu_socket_conf_t *conf);

#endif // FNP_GTPU_H