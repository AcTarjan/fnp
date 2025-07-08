#include <stdio.h>
#include <stdint.h>
#include <rte_ethdev.h>
#include <rte_flow.h>
#include <rte_mbuf.h>

#include "fnp_error.h"


// 动态添加TCP/UDP规则
struct rte_flow* add_tcp_flow_rule(uint16_t port_id, uint16_t queue_id,
                                   uint32_t lip, uint16_t lport, uint32_t rip, uint16_t rport)
{
    struct rte_flow_error error;
    struct rte_flow_attr attr = {
        .ingress = 1,
        .priority = 10,
    };

    struct rte_flow_item_ipv4 ip_spec = {0};
    struct rte_flow_item_ipv4 ip_mask = {0};

    ip_spec.hdr.dst_addr = lip;
    ip_mask.hdr.dst_addr = 0xFFFFFFFF;
    if (rip != 0)
    {
        ip_spec.hdr.src_addr = rip;
        ip_mask.hdr.src_addr = 0xFFFFFFFF;
        attr.priority = 0; //对于确定的4元组，优先级更高，先匹配4元组，再匹配2元组
    }

    struct rte_flow_item_tcp tcp_spec = {0};
    struct rte_flow_item_tcp tcp_mask = {0};
    tcp_spec.hdr.dst_port = lport;
    tcp_mask.hdr.dst_port = 0xFFFF;
    if (rport != 0)
    {
        tcp_spec.hdr.src_port = rport;
        tcp_mask.hdr.src_port = 0xFFFF;
    }

    struct rte_flow_item patterns[] = {
        {.type = RTE_FLOW_ITEM_TYPE_ETH, .spec = NULL, .mask = NULL},
        {.type = RTE_FLOW_ITEM_TYPE_IPV4, .spec = &ip_spec, .mask = &ip_mask},
        {.type = RTE_FLOW_ITEM_TYPE_TCP, .spec = &tcp_spec, .mask = &tcp_mask},
        {.type = RTE_FLOW_ITEM_TYPE_END},
    };


    // 动作：转发到指定队列
    struct rte_flow_action_queue queue = {.index = queue_id};
    struct rte_flow_action actions[] = {
        {.type = RTE_FLOW_ACTION_TYPE_QUEUE, .conf = &queue},
        {.type = RTE_FLOW_ACTION_TYPE_END},
    };

    // 创建规则
    struct rte_flow* flow = rte_flow_create(port_id, &attr, patterns, actions, &error);
    if (flow == NULL)
    {
        printf("Failed to create flow rule: %s\n", error.message);
        return NULL;
    }

    return flow;
}

struct rte_flow* add_udp_flow_rule(uint16_t port_id, uint16_t queue_id,
                                   uint32_t lip, uint16_t lport, uint32_t rip, uint16_t rport)
{
    struct rte_flow_error error;
    struct rte_flow_attr attr = {
        .ingress = 1,
        .priority = 10,
    };

    struct rte_flow_item_ipv4 ip_spec = {0};
    struct rte_flow_item_ipv4 ip_mask = {0};

    ip_spec.hdr.dst_addr = lip;
    ip_mask.hdr.dst_addr = 0xFFFFFFFF;
    if (rip != 0)
    {
        ip_spec.hdr.src_addr = rip;
        ip_mask.hdr.src_addr = 0xFFFFFFFF;
        attr.priority = 0;
    }

    struct rte_flow_item_udp udp_spec = {0};
    struct rte_flow_item_udp udp_mask = {0};
    udp_spec.hdr.dst_port = lport;
    udp_spec.hdr.dst_port = 0xFFFF;
    if (rport != 0)
    {
        udp_spec.hdr.src_port = rport;
        udp_spec.hdr.src_port = 0xFFFF;
    }

    struct rte_flow_item patterns[] = {
        {.type = RTE_FLOW_ITEM_TYPE_ETH, .spec = NULL, .mask = NULL},
        {.type = RTE_FLOW_ITEM_TYPE_IPV4, .spec = &ip_spec, .mask = &ip_mask},
        {.type = RTE_FLOW_ITEM_TYPE_UDP, .spec = &udp_spec, .mask = &udp_mask},
        {.type = RTE_FLOW_ITEM_TYPE_END},
    };


    // 动作：转发到指定队列
    struct rte_flow_action_queue queue = {.index = queue_id};
    struct rte_flow_action actions[] = {
        {.type = RTE_FLOW_ACTION_TYPE_QUEUE, .conf = &queue},
        {.type = RTE_FLOW_ACTION_TYPE_END},
    };

    // 创建规则
    struct rte_flow* flow = rte_flow_create(port_id, &attr, patterns, actions, &error);
    if (flow == NULL)
    {
        printf("Failed to create flow rule: %s\n", error.message);
        return NULL;
    }

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

static int create_arp_rule(uint16_t port_id)
{
    struct rte_flow_error error;
    struct rte_flow_attr attr = {
        .ingress = 1,
        .priority = 0,
    };

    // ARP规则，将ARP包转发到队列0
    struct rte_flow_action_queue queue = {.index = 0};
    struct rte_flow_action actions[] = {
        {.type = RTE_FLOW_ACTION_TYPE_QUEUE, .conf = &queue,},
        {.type = RTE_FLOW_ACTION_TYPE_END},
    };

    struct rte_flow_item patterns[] = {
        {.type = RTE_FLOW_ITEM_TYPE_ETH, .spec = NULL, .mask = NULL},
        {.type = RTE_FLOW_ITEM_TYPE_ARP_ETH_IPV4, .spec = NULL, .mask = NULL},
        {.type = RTE_FLOW_ITEM_TYPE_END},
    };

    if (rte_flow_validate(port_id, &attr, patterns, actions, &error) != 0)
    {
        printf("ARP rule validate failed: %s\n", error.message);
        return -1;
    }

    if (rte_flow_create(port_id, &attr, patterns, actions, &error) == NULL)
    {
        printf("ARP rule create failed: %s\n", error.message);
        return -1;
    }

    printf("create arp rule successfully\n");
    return FNP_OK;
}

static int create_icmp_rule(uint16_t port_id)
{
    struct rte_flow_error error;
    struct rte_flow_attr attr = {
        .ingress = 1,
        .priority = 0, //值越小，优先级越高
    };

    struct rte_flow_item patterns[] = {
        {.type = RTE_FLOW_ITEM_TYPE_ETH, .spec = NULL, .mask = NULL}, // 以太网层：不指定spec/mask, 匹配任意MAC
        {.type = RTE_FLOW_ITEM_TYPE_IPV4, .spec = NULL, .mask = NULL}, // IPv4层：匹配任意源/目的IP
        {.type = RTE_FLOW_ITEM_TYPE_ICMP, .spec = NULL, .mask = NULL}, // ICMP层：关键！显式指定ICMP类型, 匹配所有ICMP类型
        {.type = RTE_FLOW_ITEM_TYPE_END} // 结束标记
    };

    struct rte_flow_action_queue queue_action = {.index = 0};
    struct rte_flow_action actions[] = {
        {.type = RTE_FLOW_ACTION_TYPE_QUEUE, .conf = &queue_action},
        {.type = RTE_FLOW_ACTION_TYPE_END},
    };

    if (rte_flow_validate(port_id, &attr, patterns, actions, &error) < 0)
    {
        printf("ICMP rule validate failed: %s\n", error.message);
        return -1;
    }

    if (!rte_flow_create(port_id, &attr, patterns, actions, &error))
    {
        printf("ICMP rule create failed: %s\n", error.message);
        return -1;
    }

    printf("create ICMP rule successfully\n");
    return FNP_OK;
}

// 丢弃不匹配的流量
int create_default_drop_rule(uint16_t port_id)
{
    struct rte_flow_error error;
    struct rte_flow_attr attr = {
        .ingress = 1,
        .priority = 100,
    };

    struct rte_flow_item pattern[] = {
        {.type = RTE_FLOW_ITEM_TYPE_END},
    };
    struct rte_flow_action actions[] = {
        {.type = RTE_FLOW_ACTION_TYPE_DROP,},
        {.type = RTE_FLOW_ACTION_TYPE_END},
    };
    if (rte_flow_validate(port_id, &attr, pattern, actions, &error) < 0)
    {
        printf("DROP rule validate failed: %s\n", error.message);
        return -1;
    }
    if (!rte_flow_create(port_id, &attr, pattern, actions, &error))
    {
        printf("DROP rule create failed: %s\n", error.message);
        return -1;
    }

    printf("create default DROP rule successfully\n");
    return FNP_OK;
}

int init_flow_table(uint16_t port_id)
{
    int ret = create_arp_rule(port_id);
    CHECK_RET(ret);

    ret = create_icmp_rule(port_id);
    CHECK_RET(ret);

    // ret = create_default_drop_rule(port_id);
    // CHECK_RET(ret);

    printf("create basic rules for port %u successfully\n", port_id);
    return FNP_OK;
}
