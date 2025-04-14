#ifndef RED_BLACK_TREE_H
#define RED_BLACK_TREE_H



typedef unsigned int u32;
typedef unsigned char u8;



typedef struct rb_node
{
    unsigned long parent_and_color;       //后2位表示color, 前30/62位表示parent
    struct rb_node*    left;
    struct rb_node*    right;
} rb_node;

#define rb_color(rb)       (((rb)->parent_and_color) & 1)


typedef struct rb_tree
{
    /* data */
    rb_node* root;

    //可选
    rb_node* max;   //最大值, 最右
}rb_tree;


static inline void rb_link_node(rb_node *node, rb_node *parent,
                                rb_node **rb_link)
{
    node->parent_and_color = (unsigned long)parent;
    node->left = node->right = NULL;

    *rb_link = node;
}

rb_node* rb_prev(const rb_node *node);
rb_node* rb_next(const rb_node *node);
rb_node *rb_first(const struct rb_tree *rbt);

void rbtree_insert(rb_tree* rbt, rb_node* node);
void rb_erase(rb_tree *rbt, rb_node *node);


#endif