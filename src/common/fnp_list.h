#ifndef FNP_LIST_H
#define FNP_LIST_H
#include <stdbool.h>
#include <stddef.h>

// 链表节点（嵌套外部数据）
typedef struct fnp_list_node
{
    struct fnp_list_node* next;
    void* value; // 指向外部数据的指针
} fnp_list_node_t;

typedef fnp_list_node_t* (*fnp_list_node_get_func)(void*); // 根据值来创建一个list node
typedef void* (*fnp_list_node_get_value_func)(fnp_list_node_t*); // 根据list node来获取一个值
typedef int (*fnp_list_node_compare_func)(void*, void*); // 大于0继续比较, 表示插入值，大于

// 链表控制结构（封装操作函数）
typedef struct fnp_list
{
    fnp_list_node_t* head;
    fnp_list_node_compare_func compare;
} fnp_list_t;

void fnp_init_list(fnp_list_t* list, fnp_list_node_compare_func compare);

void fnp_list_insert(fnp_list_t* list, fnp_list_node_t* node, void* value);

// 必须配置compare函数
bool fnp_list_find(fnp_list_t* list, void* value);

void fnp_list_delete(fnp_list_t* list, fnp_list_node_t* node);

static inline fnp_list_node_t* fnp_list_first(fnp_list_t* list)
{
    return list->head;
}

static inline fnp_list_node_t* fnp_list_get_next(fnp_list_node_t* node)
{
    return node == NULL ? NULL : node->next;
}

#endif //FNP_LIST_H
