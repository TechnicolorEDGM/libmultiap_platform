/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

#include "kwaytree.h"
#include <stdlib.h>

k_tree_node* ktree_node(uint32_t key, uint32_t* value) {
    k_tree_node* node = (k_tree_node*) calloc(1, sizeof(k_tree_node));
    if (node != NULL) {
        node->key = key;
        node->value = value;
        node->height = 1;
        node->color = -1;
    }
    return node;
}

array_list_t* ktree_elements_at_depth(k_tree_node* root, int height, int color) {
    array_list_t* q = new_array_list(eListTypeDefault);
    if(root == NULL) {
        return 0;
    }
    push_object(q, root);
    list_iterator_t * it = NULL;
    array_list_t* list = new_array_list(eListTypeDefault);
    while(list_get_size(q) != 0) {
        int n = list_get_size(q);
         while(n > 0) {
            k_tree_node *tmp = first_object(q);
            if(tmp->height == height) {
                if((color == -1) || (color == tmp->color)){
                    push_object(list, tmp);
                }
            }
            if(tmp != NULL) {
                pop_object(q);
            }
            if(it == NULL) {
                it = new_list_iterator(tmp->children);
            }else {
                bind_list_iterator(it, tmp->children);
            }
            tmp = get_next_list_object(it);
            while(tmp != NULL) {
                push_object(q, tmp);
                tmp = get_next_list_object(it);
            }
            n--;
        }
    }
    free_list_iterator(it);
    delete_array_list(q);
    return list;
}

int ktree_max_height(k_tree_node* root) {
    array_list_t* q = new_array_list(eListTypeDefault);
    if(root == NULL) {
        return 0;
    }
    int depth = 0;
    push_object(q, root);
    list_iterator_t * it = NULL;
    while(list_get_size(q) != 0) {
        int n = list_get_size(q);
        depth++;
        while(n > 0) {
            k_tree_node *tmp = first_object(q);
            if(tmp != NULL) {
                pop_object(q);
            }
            if(it == NULL) {
                it = new_list_iterator(tmp->children);
            }else {
                bind_list_iterator(it, tmp->children);
            }
            tmp = get_next_list_object(it);
            while(tmp != NULL) {
                push_object(q, tmp);
                tmp = get_next_list_object(it);
            }
            n--;
        }
    }
    free_list_iterator(it);
    delete_array_list(q);
    return depth;
}

static int ktree_height_helper(k_tree_node* node) {
    int h = 0;
    while(node != NULL) {
        h++;
        node = node->parent;
    }
    return h;
}

int ktree_height(k_tree_node* node) {
    int h = 0;
    if(node != NULL) {
        h = node->height;
    }
    return h;
}

int ktree_color(k_tree_node* node) {
    int color = -1;
    if(node != NULL) {
        color = node->color;
    }
    return color;
}

int ktree_set_color(k_tree_node* node, int color) {
    int ret = -1;
    if(node != NULL) {
        node->color = color;
        ret = node->color;
    }
    return ret;
}

int ktree_add_node(k_tree_node* parent, k_tree_node* child) {
    int ret = -1;
    if(parent != NULL && child != NULL)
    {
        if(parent->children == NULL) {
            /* lazy instance of the children*/
            parent->children = new_array_list(eListTypeDefault);
        }
        child->self = push_object_ex(parent->children, child);
        child->parent = parent;
        child->height = ktree_height_helper(child);
        ret = 0;
    }
    return ret;
}
void ktree_remove_node(k_tree_node* child) {
    k_tree_node* parent = NULL;
    if(child != NULL && child->parent != NULL)
        parent = child->parent;
    if(parent && child->self) {
        remove_node(parent->children, child->self);
        child->self = NULL;
        child->parent = NULL;
        child->height = -1;
    }
}

k_tree_node* ktree_predecessor(k_tree_node* child) {
    k_tree_node* predecessor = NULL;
    if(child != NULL) {
        predecessor = child->parent;
    }
    return predecessor;
}

int ktree_is_leaf(k_tree_node* node) {
    if(node == NULL) {
        return -1;
    }
    if(node->children == NULL || list_get_size(node->children) == 0) {
        return 1;
    }
    else {
        return 0;
    }
}

void free_children_iter(list_iterator_t * iter)
{
	free(iter);
}

list_iterator_t* ktree_children_iter(k_tree_node * root)
{
	if(root == NULL) {
        return 0;
    }
   
    list_iterator_t * it = NULL;
    it = new_list_iterator(root->children);

	return it;
}

void ktree_free_node(k_tree_node* node)
{
    if(node)
    {
        free(node);
        node = NULL;
    }

    return;
}
