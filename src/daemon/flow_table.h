#ifndef FLOW_TABLE_H
#define FLOW_TABLE_H

#include <rte_flow.h>

int create_base_flow_rules(uint16_t port_id);

struct rte_flow* add_flow_rule(uint16_t port_id, uint8_t proto, uint32_t dst_ip, uint16_t dst_port, uint16_t queue_id);

int delete_flow_rule(uint16_t port_id, struct rte_flow* flow);

#endif //FLOW_TABLE_H
