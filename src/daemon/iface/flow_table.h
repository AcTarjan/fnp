#ifndef FLOW_TABLE_H
#define FLOW_TABLE_H

#include <rte_flow.h>

int init_flow_table(uint16_t port_id);

struct rte_flow* add_udp_flow_rule(uint16_t port_id, uint16_t queue_id,
                                   uint32_t lip, uint16_t lport, uint32_t rip, uint16_t rport);

struct rte_flow* add_tcp_flow_rule(uint16_t port_id, uint16_t queue_id,
                                   uint32_t lip, uint16_t lport, uint32_t rip, uint16_t rport);

int delete_flow_rule(uint16_t port_id, struct rte_flow* flow);

#endif //FLOW_TABLE_H
