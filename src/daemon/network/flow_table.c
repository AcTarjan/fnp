#include <stdio.h>
#include <stdint.h>
#include <rte_ethdev.h>
#include <rte_flow.h>
#include <rte_mbuf.h>

#include "fnp_error.h"


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
