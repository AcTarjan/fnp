#include <stdio.h>
#include "rbtree.h"

#define	RB_RED		0
#define	RB_BLACK	1

#define rb_parent(r)   ((rb_node *)((r)->parent_and_color & ~3))
#define rb_is_black(rb)    (rb_color(rb))
#define rb_is_red(rb)      (!rb_is_black(rb))

/* 'empty' nodes are nodes that are known not to be inserted in an rbtree */
#define RB_EMPTY_NODE(node)  \
	((node)->parent_and_color == (unsigned long)(node))
#define RB_CLEAR_NODE(node)  \
	((node)->parent_and_color = (unsigned long)(node))

static inline void rb_set_parent(rb_node *rb, rb_node *p)
{
    rb->parent_and_color = (unsigned long)p | rb_color(rb);
}

static inline void rb_set_red(rb_node *rb)
{
    rb->parent_and_color &= (~1);
}

static inline void rb_set_black(rb_node *rb)
{
    rb->parent_and_color |= 1;
}

static inline void rb_set_parent_color(rb_node *rb, rb_node *p, int color)
{
    rb->parent_and_color = (unsigned long)p | color;
}

/* change parent's child from old to new */
static inline void __rb_change_child(rb_tree *rbt, rb_node *parent, rb_node *old, rb_node *new)
{
    if (parent) {
        if (parent->left == old)
            parent->left = new;
        else
            parent->right = new;
    } else
        rbt->root = new;
}

rb_node *rb_prev(const rb_node *node)
{
    rb_node *parent;

    if (RB_EMPTY_NODE(node))
        return NULL;

    /*
     * If we have a left-hand child, go down and then right as far
     * as we can.
     */
    if (node->left) {
        node = node->left;
        while (node->right)
            node = node->right;
        return (rb_node *)node;
    }

    /*
     * No left-hand children. Go up till we find an ancestor which
     * is a right-hand child of its parent.
     */
    while ((parent = rb_parent(node)) && node == parent->left)
        node = parent;

    return parent;
}

rb_node* rb_next(const rb_node *node)
{
    rb_node *parent;

    if (RB_EMPTY_NODE(node))
        return NULL;

    /*
     * If we have a right-hand child, go down and then left as far
     * as we can.
     */
    if (node->right) {
        node = node->right;
        while (node->left)
            node = node->left;
        return (rb_node*)node;
    }

    /*
     * No right-hand children. Everything down and left is smaller than us,
     * so any 'next' node must be in the general direction of our parent.
     * Go up the tree; any time the ancestor is a right-hand child of its
     * parent, keep going up. First time it's a left-hand child of its
     * parent, said parent is our 'next' node.
     */
    while ((parent = rb_parent(node)) && node == parent->right)
        node = parent;

    return parent;
}

rb_node *rb_first(const struct rb_tree *rbt)
{
    rb_node* n = rbt->root;
    if (!n)
        return NULL;
    while (n->left)
        n = n->left;
    return n;
}

/*
 * 左旋操作
 *
 *      p                p
 *     / \              / \
 *   old   U   -->    new  U
 *     \              / \
 *     new          old  R
 *     /  \           \
 *    L    R           L
 *
 */
static inline void __rb_left_rotate(rb_tree* rbt, rb_node* old)
{
    rb_node* new = old->right;

    // 将新轴的左孩子变为旧轴的右孩子
    old->right = new->left;
    if(new->left)  //如果新轴的右孩子不为空, 修改其父节点
        rb_set_parent(new->left, old);

    // 修改新轴的父节点
    rb_node* parent = rb_parent(old);   //旧轴的父节点变成新轴的父节点
    rb_set_parent(new, parent);
    if(!parent)     //parent为空, 说明旧轴是根节点
        rbt->root = new;
    else if(old == parent->right)
        parent->right = new;
    else
        parent->left = new;

    // 修改新轴的左孩子为旧轴
    new->left = old;
    rb_set_parent(old, new);
}


/*
 * 右旋操作
 *
 *        p                p
 *       / \              / \
 *     old  U   -->     new  U
 *     /                / \
 *   new               L  old
 *   /  \                 /
 *  L    R               R
 *
 */
static inline void __rb_right_rotate(rb_tree* rbt, rb_node* old)
{
    rb_node *new = old->left;

    // 将新轴的右孩子变为旧轴的左孩子
    old->left = new->right;
    if(new->right)  //如果新轴的右孩子不为空, 修改其父节点
        rb_set_parent(new->right, old);

    // 修改新轴的父节点
    rb_node* parent = rb_parent(old);   //旧轴的父节点变成新轴的父节点
    rb_set_parent(new, parent);
    if(!parent)
        rbt->root = new;
    else if(old == parent->right)
        parent->right = new;
    else
        parent->left = new;

    // 修改新轴的右孩子为旧轴
    new->right = old;
    rb_set_parent(old, new);
}

void rbtree_insert(rb_tree* rbt, rb_node* node)
{
    rb_node *parent = rb_parent(node), *gparent, *tmp;

    while (1) {
        /*
         * 循环的隐藏条件: 当前节点是红色
         */
        if (!parent) {
            /*
             * The inserted node is root. Either this is the
             * first node, or we recursed at Case 1 below and
             * are no longer violating 4).
             */
            rb_set_parent_color(node, NULL, RB_BLACK);
            break;
        }

        /*
         * 当前节点是红色, 父节点是黑色, 不违反规则4, 不再需要调整了
         * 相当于插入一个红色节点, 不影响黑高
         */
        if(rb_is_black(parent))
            break;

        gparent = rb_parent(parent);

        tmp = gparent->right;
        if (parent != tmp) {	/* 父节点是祖父节点的左孩子 */
            if (tmp && rb_is_red(tmp)) {  //叔节点是红色
                /*
                 * Case 1: 当前节点是红色, 父节点和叔节点都是红色
                 * 注: 大写表示黑色, 小写表示红色
                 *       G            g
                 *      / \          / \
                 *     p   u  -->   P   U
                 *    /            /
                 *   n            n
                 *
                 * 调整: 父节点和叔节点变黑, 祖父节点变红
                 * 结果: g的父节点可能是红色, 需要以g为当前节点继续调整
                 *
                 */
                rb_set_black(tmp);      //叔节点变黑
                rb_set_black(parent);   //父节点变黑

                node = gparent;         //将祖父节点变红, 以祖父节点为当前节点继续调整
                parent = rb_parent(node);
                rb_set_red(node);
                continue;
            }

            tmp = parent->right;
            if (node == tmp) {
                /*
                 * Case 2: 叔节点是黑色, 且当前节点是父节点的右孩子
                 * 调整: 以父节点为轴左旋
                 * 结果: 仍然违反规则4, 但是可以通过Case 3修正
                 *
                 *      G             G
                 *     / \           / \
                 *    p   U  -->    n   U
                 *     \           /
                 *      n         p
                 *
                 */

                __rb_left_rotate(rbt, parent);
                parent = node;      //修改parent指向当前节点
            }

            /*
             * Case 3: 节点的叔节点是黑色, 且当前节点是父节点的左孩子
             * 操作: 以祖父节点为轴右旋, 并交换父节点和祖父节点的颜色
             *
             *        G           P
             *       / \         / \
             *      p   U  -->  n   g
             *     / \             / \
             *    n  TMP         TMP  U
             *
             * 结果: 调整结束
             */
            __rb_right_rotate(rbt, gparent);

            rb_set_black(parent);
            rb_set_red(gparent);
            break;
        } else { /* 父节点是祖父节点的右孩子 */
            tmp = gparent->left;
            if (tmp && rb_is_red(tmp)) {
                /* Case 1的镜像 */
                rb_set_black(tmp);      //叔节点变黑
                rb_set_black(parent);   //父节点变黑

                node = gparent;         //将祖父节点变红, 以祖父节点为当前节点继续调整
                parent = rb_parent(node);
                rb_set_red(node);
                continue;
            }

            tmp = parent->left;
            if (node == tmp) {
                /* Case 2的镜像: 以父节点为轴右旋 */
                __rb_right_rotate(rbt, parent);
                parent = node;
            }

            /* Case 3的镜像: 以祖父节点为轴左旋, 并交换父节点和祖父节点的颜色 */
            __rb_left_rotate(rbt, gparent);

            rb_set_black(parent);
            rb_set_red(gparent);
            break;
        }
    }
}



/**********************红黑树删除 start***************************/
static __always_inline rb_node* __rb_erase(rb_tree *rbt, rb_node *node)
{
    rb_node *right_child = node->right;
    rb_node *left_child = node->left;
    rb_node *parent = rb_parent(node);
    rb_node* rebalance = NULL;

    if (!left_child) {
        /*
         * Case 1: 没有左孩子, 只有右孩子或者没有孩子
         * 如果只有右孩子, 那么这个孩子必须是红色, 且孩子没有子树, 否则违反规则5(相同的黑高); 且该节点必是黑色, 否则违反规则4 (不能连续的红色), 直接用孩子替换自己即可
         * 如果没有孩子; 且该节点是红色, 直接删除即可; 若是黑色, 需要进行平衡
         *
         * Note that if there is one right_child it must be red due to 5)
         * and node must be black due to 4). We adjust colors locally
         * so as to bypass __rb_erase_rebalance() later on.
         */
        __rb_change_child(rbt, parent, node, right_child);
        if (right_child) {    //如果有右孩子, 替换node
            right_child->parent_and_color = node->parent_and_color;
            rebalance = NULL;
        } else  //无孩子
            rebalance = rb_is_black(node) ? parent : NULL;
    } else if (!right_child) {
        /* 还是Case 1: 只有一个左孩子 */
        left_child->parent_and_color = node->parent_and_color;
        __rb_change_child(rbt, parent, node, left_child);
        rebalance = NULL;
    } else {    //左右孩子都有, 则寻找后继节点来替换当前节点
        rb_node *successor = right_child;
        rb_node *child2;        //后继节点的右孩子

        rb_node* tmp = right_child->left;
        if (!tmp) {
            /*
             * Case 2: node的右孩子没有左孩子, 后继节点是node的右孩子,
             *
             *    (n)          (s)
             *    / \          / \
             *  (x) (s)  ->  (x) (c)
             *        \
             *        (c)
             */
            parent = successor;
            child2 = successor->right;
        } else {
            /*
             * Case 3: node的后继节点是它的右孩子最远的左孩子, 且这个后继节点没有左孩子
             *
             *    (n)          (s)
             *    / \          / \
             *  (x) (y)  ->  (x) (y)
             *      /            /
             *    (p)          (p)
             *    /            /
             *  (s)          (c)
             *    \
             *    (c)
             */
            do {
                parent = successor;     //此时后继节点的父节点就是自己
                successor = tmp;
                tmp = tmp->left;
            } while (tmp);
            child2 = successor->right;

            parent->left = child2;  //此时不能修改child2的父节点, 因为child2可能是nil

            //修改后继节点的右孩子为node的右孩子
            successor->right = right_child;
            rb_set_parent(right_child, successor);
        }
        //此时parent是后继节点的父节点, 不是node的父节点

        //修改后继节点的左孩子为node的左孩子
        successor->left = left_child;
        rb_set_parent(left_child, successor);

        //修改node的parent的孩子指向successor
        __rb_change_child(rbt, rb_parent(node), node,successor);

        if (child2) {   //后继节点有右孩子
            successor->parent_and_color = node->parent_and_color;
            rb_set_parent_color(child2, parent, RB_BLACK);
            rebalance = NULL;
        } else {    // 后继节点没有右孩子, 看看后继节点是不是黑色
            rebalance = rb_is_black(successor) ? parent : NULL;
            successor->parent_and_color = node->parent_and_color;
        }
    }

    return rebalance;
}

static __always_inline void
__rb_erase_rebalance(rb_tree *rbt, rb_node *parent)
{
    struct rb_node *node = NULL, *sibling, *tmp1, *tmp2;

    while (1)
    {
        /*
         * Loop invariants:
         * - node is black (or NULL on first iteration)
         * - node is not the root (parent is not NULL)
         * - 所有从parent的黑高, 走node的路径的黑高都少1
         */
        sibling = parent->right;
        if (node != sibling) {	/* node == parent->left */
            if (rb_is_red(sibling)) {
                /*
                 * Case 1: 兄弟节点s是红色的, 父节点P是黑色的, 节点N所在的路径少1个黑色节点
                 * 操作: 以父节点为轴左旋, 并交换父节点和兄弟节点的颜色
                 * 结果: parent不变, sibling变成sibling的左孩子，节点N所在路径的黑高还是少1, 但是可以通过Case 2, 3, 4修正
                 *
                 *     P               S
                 *    / \             / \
                 *   N   s    -->    p   Sr
                 *      / \         / \
                 *     Sl  Sr      N   Sl
                 */
                tmp1 = sibling->left;
                __rb_left_rotate(rbt, parent);
                rb_set_red(parent);
                rb_set_black(sibling);
                sibling = tmp1;
            }
            tmp1 = sibling->right;
            if (!tmp1 || rb_is_black(tmp1)) {
                tmp2 = sibling->left;
                if (!tmp2 || rb_is_black(tmp2)) {
                    /*
                     * Case 2: 兄弟节点为黑，其左右孩子均为黑, parent的颜色任意
                     * 操作: 将兄弟节点变红。如果父节点是红色，将父节点变黑, N的黑高加1，S的黑高不变，调整结束;
                     * 如果父节点是黑色，将父节点作为新的node，继续调整，此时p的各条路径的黑高相等，但是p的parent的黑高减1了。
                     *    (p)           (p)
                     *    / \           / \
                     *   N   S    -->  N   s
                     *      / \           / \
                     *     Sl  Sr        Sl  Sr
                     *
                     */
                    rb_set_red(sibling);
                    if (rb_is_red(parent)) {
                        rb_set_black(parent);
                    } else {
                        node = parent;
                        parent = rb_parent(node);
                        if (parent)
                            continue;
                    }
                    break;
                }
                /*
                 * Case 3: 兄弟节点S为黑，, 右孩子是黑色, 其左孩子sl是红色 parent的颜色任意
                 * 操作: 以兄弟节点S为轴右旋
                 * 结果: 经过Case4的操作后，N的黑高加1，S的黑高不变
                 *
                 *   (p)           (p)
                 *   / \           / \
                 *  N   S    -->  N   sl
                 *     / \             \
                 *    sl  Sr            S
                 *                       \
                 *                        Sr
                 *
                 * Note: p might be red, and then both
                 * p and sl are red after rotation(which
                 * breaks property 4). This is fixed in
                 * Case 4 (in __rb_rotate_set_parents()
                 *         which set sl the color of p
                 *         and set p RB_BLACK)
                 *
                 *   (p)            (sl)
                 *   / \            /  \
                 *  N   sl   -->   P    S
                 *       \        /      \
                 *        S      N        Sr
                 *         \
                 *          Sr
                 */
                __rb_right_rotate(rbt, sibling);

                tmp1 = sibling;
                sibling = tmp2;
            }
            /*
             * Case 4: 兄弟节点S为黑，右孩子sr是红色, 左孩子和parent的颜色任意;
             * 还有Case3操作后的情况, 需要Case4操作来修正
             * 操作: 以父节点p为轴左旋, 兄弟节点S获得p的颜色, p变黑，右孩子sr变黑
             * (p and sl could be either color here.
             *  After rotation, p becomes black, s acquires
             *  p's color, and sl keeps its color)
             *
             *      (p)             (s)
             *      / \             / \
             *     N   S     -->   P   Sr
             *        / \         / \
             *      (sl) sr      N  (sl)
             */

            __rb_left_rotate(rbt, parent);
            rb_set_parent_color(sibling, rb_parent(sibling),rb_color(parent));
            rb_set_black(tmp1);
            rb_set_black(parent);
            break;
        } else {
            sibling = parent->left;
            if (rb_is_red(sibling)) {
                /* Case 1 - right rotate at parent */
                tmp1 = sibling->right;
                __rb_right_rotate(rbt, parent);
                rb_set_red(parent);
                rb_set_black(sibling);
                sibling = tmp1;
            }
            tmp1 = sibling->left;
            if (!tmp1 || rb_is_black(tmp1)) {
                tmp2 = sibling->right;
                if (!tmp2 || rb_is_black(tmp2)) {
                    /* Case 2 - sibling color flip */
                    rb_set_red(sibling);
                    if (rb_is_red(parent))
                        rb_set_black(parent);
                    else {
                        node = parent;
                        parent = rb_parent(node);
                        if (parent)
                            continue;
                    }
                    break;
                }
                /* Case 3 - left rotate at sibling */
                __rb_left_rotate(rbt, sibling);
                tmp1 = sibling;
                sibling = tmp2;
            }
            /* Case 4 - right rotate at parent + color flips */
            __rb_right_rotate(rbt, parent);
            rb_set_parent_color(sibling, rb_parent(sibling),rb_color(parent));
            rb_set_black(tmp1);
            rb_set_black(parent);
            break;
        }
    }
}

void rb_erase(rb_tree *rbt, rb_node *node)
{
    rb_node *rebalance;      // 用于记录需要重新平衡的节点, 即删除节点的父节点
    rebalance = __rb_erase(rbt, node);
//    若出现了失衡点（parent），则失衡点有且仅有一个子节点。该子节点即为 sibling（而 node 为 NULL）。
    if (rebalance) // 需要重新平衡
        __rb_erase_rebalance(rbt, rebalance);
}
/**********************红黑树删除 end***************************/
