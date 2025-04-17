/* This code is copied and adapted from https://github.com/lrem/splay */

#ifndef FNP_SPLAY_H
#define FNP_SPLAY_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_picosplay_node_t
{
    struct st_picosplay_node_t *parent, *left, *right;
} picosplay_node_t;

typedef int64_t (*picosplay_comparator)(void* left, void* right);
typedef picosplay_node_t* (*picosplay_create)(void* value);
typedef void (*picosplay_delete_node)(void* tree, picosplay_node_t* node);
typedef void* (*picosplay_node_value)(picosplay_node_t* node);

typedef struct st_picosplay_tree_t
{
    picosplay_node_t* root;
    picosplay_comparator comp;
    picosplay_create create;
    picosplay_delete_node delete_node;
    picosplay_node_value node_value;
    int size;
} picosplay_tree_t;


void picosplay_init_tree(picosplay_tree_t* tree, picosplay_comparator comp, picosplay_create create,
                         picosplay_delete_node delete_node, picosplay_node_value node_value);
picosplay_tree_t* picosplay_new_tree(picosplay_comparator comp, picosplay_create create,
                                     picosplay_delete_node delete_node, picosplay_node_value node_value);
picosplay_node_t* picosplay_insert(picosplay_tree_t* tree, void* value);
picosplay_node_t* picosplay_find(picosplay_tree_t* tree, void* value);
picosplay_node_t* picosplay_find_previous(picosplay_tree_t* tree, void* value);
picosplay_node_t* picosplay_first(picosplay_tree_t* tree);
picosplay_node_t* picosplay_previous(picosplay_node_t* node);
picosplay_node_t* picosplay_next(picosplay_node_t* node);
picosplay_node_t* picosplay_last(picosplay_tree_t* tree);

void picosplay_delete(picosplay_tree_t* tree, void* value);
void picosplay_delete_hint(picosplay_tree_t* tree, picosplay_node_t* node);
void picosplay_empty_tree(picosplay_tree_t* tree);

#ifdef __cplusplus
}
#endif

#endif /* FNP_SPLAY_H */
