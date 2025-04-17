#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_flow.h>
#include <rte_table_action.h>
#include <rte_mbuf.h>
#include <rte_hash.h>


// 创建基础规则（ARP和ICMP到队列0）
int create_base_flow_rules(uint16_t port_id)
{
    struct rte_flow_error error;
    struct rte_flow_attr attr = {
        .ingress = 1,
        .priority = 100, // 高优先级
    };

    // 规则1：ARP流量到队列0
    struct rte_flow_item_eth eth_spec_arp = {
        .type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP),
    };
    struct rte_flow_item_eth eth_mask_arp = {
        .type = 0xFFFF,
    };


    struct rte_flow_item pattern_arp[] = {
        {.type = RTE_FLOW_ITEM_TYPE_ETH, .spec = &eth_spec_arp, .mask = &eth_mask_arp},
        {.type = RTE_FLOW_ITEM_TYPE_END},
    };

    struct rte_flow_action_queue queue_arp = {.index = 0};
    struct rte_flow_action actions_arp[] = {
        {.type = RTE_FLOW_ACTION_TYPE_QUEUE, .conf = &queue_arp},
        {.type = RTE_FLOW_ACTION_TYPE_END},
    };

    // 规则2：ICMP流量到队列0
    struct rte_flow_item_eth eth_spec_icmp = {
        .type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)
    };
    struct rte_flow_item_eth eth_mask_icmp = {
        .type = 0xFFFF
    };

    struct rte_flow_item_ipv4 ip_spec_icmp = {
        .hdr.next_proto_id = IPPROTO_ICMP
    };
    struct rte_flow_item_ipv4 ip_mask_icmp = {
        .hdr.next_proto_id = 0xFF
    };

    struct rte_flow_item_icmp icmp_spec = {0};
    struct rte_flow_item_icmp icmp_mask = {0};

    struct rte_flow_item pattern_icmp[] = {
        {.type = RTE_FLOW_ITEM_TYPE_ETH, .spec = &eth_spec_icmp, .mask = &eth_mask_icmp},
        {.type = RTE_FLOW_ITEM_TYPE_IPV4, .spec = &ip_spec_icmp, .mask = &ip_mask_icmp},
        {.type = RTE_FLOW_ITEM_TYPE_ICMP, .spec = &icmp_spec, .mask = &icmp_mask},
        {.type = RTE_FLOW_ITEM_TYPE_END},
    };

    struct rte_flow_action_queue queue_icmp = {.index = 0};
    struct rte_flow_action actions_icmp[] = {
        {.type = RTE_FLOW_ACTION_TYPE_QUEUE, .conf = &queue_icmp},
        {.type = RTE_FLOW_ACTION_TYPE_END},
    };

    // 规则3：默认丢弃其他流量
    struct rte_flow_item pattern_drop[] = {
        {.type = RTE_FLOW_ITEM_TYPE_END},
    };

    struct rte_flow_action actions_drop[] = {
        {.type = RTE_FLOW_ACTION_TYPE_DROP,},
        {.type = RTE_FLOW_ACTION_TYPE_END},
    };

    // 创建规则
    if (!rte_flow_create(port_id, &attr, pattern_arp, actions_arp, &error) ||
        !rte_flow_create(port_id, &attr, pattern_icmp, actions_icmp, &error) ||
        !rte_flow_create(port_id, &(struct rte_flow_attr){.ingress = 1, .priority = 1000},
                         pattern_drop, actions_drop, &error))
    {
        printf("Base rule creation failed: %s\n", error.message);
        return -1;
    }

    return 0;
}

// 动态添加TCP/UDP规则
struct rte_flow* add_flow_rule(uint16_t port_id, uint8_t proto, uint32_t dst_ip, uint16_t dst_port, uint16_t queue_id)
{
    struct rte_flow_error error;
    struct rte_flow_attr attr = {
        .ingress = 1,
        .priority = 150, // 高于默认规则，低于ARP/ICMP
    };

    // 通用头部
    struct rte_flow_item_eth eth_spec = {
        .type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)
    };
    struct rte_flow_item_eth eth_mask = {
        .type = 0xFFFF
    };


    struct rte_flow_item_ipv4 ip_spec = {
        .hdr.dst_addr = dst_ip,
        .hdr.next_proto_id = proto,
    };
    struct rte_flow_item_ipv4 ip_mask = {
        .hdr.dst_addr = 0xFFFFFFFF,
        .hdr.next_proto_id = 0xFF,
    };

    // TCP/UDP特定部分
    struct rte_flow_item pattern[4];
    struct rte_flow_action actions[2];

    if (proto == IPPROTO_TCP)
    {
        struct rte_flow_item_tcp tcp_spec = {
            .hdr.dst_port = dst_port
        };
        struct rte_flow_item_tcp tcp_mask = {
            .hdr.dst_port = 0xFFFF
        };

        pattern[0] = (struct rte_flow_item){.type = RTE_FLOW_ITEM_TYPE_ETH, .spec = &eth_spec, .mask = &eth_mask};
        pattern[1] = (struct rte_flow_item){.type = RTE_FLOW_ITEM_TYPE_IPV4, .spec = &ip_spec, .mask = &ip_mask};
        pattern[2] = (struct rte_flow_item){.type = RTE_FLOW_ITEM_TYPE_TCP, .spec = &tcp_spec, .mask = &tcp_mask};
        pattern[3] = (struct rte_flow_item){.type = RTE_FLOW_ITEM_TYPE_END};
    }
    else if (proto == IPPROTO_UDP)
    {
        struct rte_flow_item_udp udp_spec = {
            .hdr.dst_port = dst_port
        };
        struct rte_flow_item_udp udp_mask = {
            .hdr.dst_port = 0xFFFF
        };

        pattern[0] = (struct rte_flow_item){.type = RTE_FLOW_ITEM_TYPE_ETH, .spec = &eth_spec, .mask = &eth_mask};
        pattern[1] = (struct rte_flow_item){.type = RTE_FLOW_ITEM_TYPE_IPV4, .spec = &ip_spec, .mask = &ip_mask};
        pattern[2] = (struct rte_flow_item){.type = RTE_FLOW_ITEM_TYPE_UDP, .spec = &udp_spec, .mask = &udp_mask};
        pattern[3] = (struct rte_flow_item){.type = RTE_FLOW_ITEM_TYPE_END};
    }
    else
    {
        printf("Unsupported protocol: %u\n", proto);
        return NULL;
    }

    // 动作：转发到指定队列
    struct rte_flow_action_queue queue = {.index = queue_id};
    actions[0] = (struct rte_flow_action){.type = RTE_FLOW_ACTION_TYPE_QUEUE, .conf = &queue};
    actions[1] = (struct rte_flow_action){.type = RTE_FLOW_ACTION_TYPE_END};

    // 创建规则
    struct rte_flow* flow = rte_flow_create(port_id, &attr, pattern, actions, &error);
    if (!flow)
    {
        printf("Failed to create flow rule: %s\n", error.message);
        return NULL;
    }

    printf("Rule added: %s %u.%u.%u.%u:%u → Queue %u\n",
           proto == IPPROTO_TCP ? "TCP" : "UDP",
           (dst_ip >> 24) & 0xFF, (dst_ip >> 16) & 0xFF,
           (dst_ip >> 8) & 0xFF, dst_ip & 0xFF, dst_port, queue_id);

    return flow;
}

// 动态删除TCP/UDP规则
int delete_flow_rule(uint16_t port_id, struct rte_flow* flow)
{
    struct rte_flow_error error;

    // 删除规则
    if (rte_flow_destroy(port_id, flow, &error) < 0)
    {
        printf("Failed to destroy flow rule: %s\n", error.message);
        return -1;
    }

    printf("delete flow rule successfully\n");

    return 0;
}
