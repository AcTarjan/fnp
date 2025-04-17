#include "fnp_list.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

// 默认比较函数, 插入第一个
static int default_compare(const void* a, const void* b)
{
    return 0;
}

void fnp_init_list(fnp_list_t* list, fnp_list_node_compare_func compare)
{
    list->head = NULL;
    if (compare != NULL)
        list->compare = compare;
    else
        list->compare = default_compare;
}

void fnp_list_insert(fnp_list_t* list, fnp_list_node_t* node, void* value)
{
    // 空链表直接插入
    node->value = value;
    node->next = NULL;
    if (list->head == NULL)
    {
        list->head = node;
        return;
    }

    // 根据比较函数找到插入位置
    fnp_list_node_t* prev = NULL;
    fnp_list_node_t* cur = list->head;
    while (cur && list->compare(value, cur->value) > 0)
    {
        prev = cur;
        cur = cur->next;
    }

    // 插入头部/中间/尾部
    if (prev == NULL)
    {
        node->next = list->head;
        list->head = node;
    }
    else
    {
        prev->next = node;
        node->next = cur;
    }
}

bool fnp_list_find(fnp_list_t* list, void* value)
{
    fnp_list_node_t* cur = list->head;
    while (cur)
    {
        if (list->compare(value, cur->value) == 0)
            return true; // 找到匹配的节点
        cur = cur->next;
    }
    return false; // 未找到
}

void fnp_list_delete(fnp_list_t* list, fnp_list_node_t* node)
{
    if (!list->head || !node)
        return;

    // 删除头节点
    if (node == list->head)
    {
        list->head = node->next;
    }
    else
    {
        // 找到targetNode的前驱节点
        fnp_list_node_t* prev = list->head;
        while (prev->next != node) prev = prev->next;
        prev->next = node->next;
    }
}
