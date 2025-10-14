#include "fnp_list.h"

#include <rte_branch_prediction.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

// 默认比较函数, 插入第一个
static int default_compare(void* a, void* b)
{
    return 0;
}

void fnp_init_list(fnp_list_t* list, fnp_list_node_compare_func compare)
{
    list->head = list->tail = NULL;
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
        list->tail = node;
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
    if (likely(prev == NULL))
    {
        node->next = list->head;
        list->head = node; // 更新头节点
    }
    else
    {
        prev->next = node;
        node->next = cur;
        if (unlikely(cur == NULL))
        {
            list->tail = node; // 更新尾节点
        }
    }
}

void fnp_list_insert_head(fnp_list_t* list, fnp_list_node_t* node, void* value)
{
    node->value = value;
    node->next = NULL;

    fnp_list_node_t* head = list->head;
    if (likely(head != NULL))
    {
        node->next = head;
        list->head = node;
    }
    else
    {
        list->head = list->tail = node;
    }
}

void fnp_list_insert_tail(fnp_list_t* list, fnp_list_node_t* node, void* value)
{
    node->value = value;
    node->next = NULL;

    fnp_list_node_t* tail = list->tail;
    if (likely(tail != NULL))
    {
        tail->next = node;
        list->tail = node;
    }
    else
    {
        list->head = list->tail = node;
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
    if (list->head == NULL || node == NULL)
        return;

    // 删除头节点
    if (node == list->head)
    {
        list->head = node->next;
        if (list->head == NULL) //只有一个节点
            list->tail = NULL;
    }
    else
    {
        // 找到targetNode的前驱节点
        fnp_list_node_t* prev = list->head;
        while (likely(prev != NULL) && prev->next != node) prev = prev->next;
        if (unlikely(prev == NULL))
            return;
        prev->next = node->next;
        if (prev->next == NULL)
        {
            list->tail = prev;
        }
    }
}
