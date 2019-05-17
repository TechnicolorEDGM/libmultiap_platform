/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

#ifndef MULTIAP_TOPOLOGY_TREE_H
#define MULTIAP_TOPOLOGY_TREE_H

#include "map_data_model.h"
#include "kwaytree.h"

/*
 *   @brief Types of nodes in the topology tree, 
 *	  used for color coding the nodes 
 */
typedef enum TREE_NODE_TYPE
{
	AL_ENTITY = 1,
	STATION
}TREE_NODE_TYPE;

#define MAX_TYPE_STRING_LEN 15

/*
 *   @brief Get the tree node from ALE node
 *   
 *   @params Pointer to the structure map_ale_info_t* for which we need tree node.
 *   @return Pointer to k_tree_node*
 */
static inline k_tree_node* get_ktree_node(map_ale_info_t* ale_node) {
	k_tree_node* tree_node = ale_node ? ale_node->self_tree_node : NULL;
	return tree_node;
}

static inline map_ale_info_t* get_ale_from_tree(k_tree_node* tree_node)
{
	map_ale_info_t* ale_node = tree_node ? (map_ale_info_t*)tree_node->value : NULL;
	return ale_node;
}

static inline map_ale_info_t* map_get_next_ale_in_list(array_list_t* l)
{
    k_tree_node* tree_node = pop_object(l);
    if(tree_node)
        return get_ale_from_tree(tree_node);
    else
    {
        //The array list allocated for fetching the ale nodes
        //must be deleted once the list is empty
        delete_array_list(l);
        return NULL;
    }
}

/** @brief Get the root node of the topology tree
 *
 *  This will return the root tree node
 *
 *  @param none
 *  @return root tree node
 */
map_ale_info_t* get_root_ale_node();
#define CONTROLLER_ALE_NODE get_root_ale_node()

/*
 *   @brief Fetch the next list object and free iter at the end of list 
 *   
 *   @params Gets the list iterator of the childre array list
 *   @return one ale child from the list at a time
 */
map_ale_info_t* fetch_and_free_child_iter(list_iterator_t* iter);

/*
 *   @brief Iterate through all the child nodes for the given parent 
 */
#define foreach_child_in(parent, child) \
for (list_iterator_t* it = ktree_children_iter(get_ktree_node(parent)); (NULL != (child = fetch_and_free_child_iter(it))); )\

/*
 *   @brief Iterate through all the child + parent = neighbor nodes for the given ale node
 */
#define foreach_neighbors_of(ale, neighbor)\
list_iterator_t* it = NULL;\
for (it = ktree_children_iter(get_ktree_node(ale)), neighbor = get_parent_ale_node(ale); (neighbor != NULL) || (NULL != (neighbor = fetch_and_free_child_iter(it))); neighbor = NULL)\

/*
 *   @brief Iterate through all the child nodes for the given level
 */
#define foreach_child_in_level(level, child) \
array_list_t* l = NULL;\
for (l = ktree_elements_at_depth(get_ktree_node(CONTROLLER_ALE_NODE), level, -1);\
    (NULL != (child = map_get_next_ale_in_list(l)));)\

/*
** init_topology_tree
**
** This function is used to create a root parent node for the tree
**
** Returns +ve for succes -ve for failure case
**
*/
int8_t init_topology_tree(uint8_t *al_mac);

/** @brief Creates the node for topology tree
 *
 *  This will create a tree node for the given ale node 
 *	with the given type.
 *
 *  @param ale node and type
 *  @return new tree node
 */
int8_t create_topology_tree_node(map_ale_info_t* ale_node,TREE_NODE_TYPE type);

/** @brief Removes the node from the topology tree
 *
 *  This will free and remove the tree node for the given ale node
 *
 *  @param ale node
 *  @return none
 */
void remove_topology_tree_node(map_ale_info_t* ale_node);

/** @brief Insert the node in topology tree
 *
 *  This will insert or update the child node with the given ale parent 
 *	
 *  @param ale child and parent node
 *  @return +ve for success and -ve for failure
 */
int8_t topology_tree_insert(map_ale_info_t* parent, map_ale_info_t* child);

/** @brief Displays topology tree
 *
 *  This will display the entire topolgy tree
 *
 *  @param none
 *  @return none
 */
void dump_topology_tree();

/** @brief Displays topology tree over UBUS
 *
 *  This will display the topolgy tree nodes in ubus
 *  @param poineter to pointer for allocating jason buffer
 *  @return none
*/
void get_topo_tree_jason_buf(void **buf);

/** @brief Checks if both the given nodes are
*   associated with each other on the tree
*
*   @param 2 ale_nodes
*   @return 1- True 0 -False
*/
int8_t is_parent_of(map_ale_info_t * parent, map_ale_info_t * child);

#define IS_PARENT_OF(parent,child) is_parent_of(parent,child)
#define IS_CHILD_OF(parent,child) IS_PARENT_OF(parent,child)
#define IS_NEIGHBOUR_OF(A,B) (IS_PARENT_OF(A,B) || IS_PARENT_OF(B,A))
#define IS_ORPHANED(ale) ((get_parent_ale_node(ale)) ? (1) : (0) )

/** @brief Returns the parent ale node for the given ale node
 *
 *  This will return the parent node for the given ale node 
 *	
 *  @param child ale node 
 *  @return parent tree node
 */
map_ale_info_t* get_parent_ale_node(map_ale_info_t* child_ale);

/** @brief Dismantles the topology tree
 *
 *  This will disassmble the entire subtree with the root node 
 *	and will make all its child nodes as orphan nodes.
 *
 *  @param root node of the subtree to be disassembled
 *  @return none
 */
void disassemble_tree(map_ale_info_t* root_node);

/** @brief Dismantles the topology tree
 *
 *  This will disassmble the entire subtree with the root node 
 *	and will make all its child nodes as orphan nodes.
 *
 *  @param root node of the subtree to be disassembled
 *  @return none
 */
int32_t map_get_child_count(map_ale_info_t* root_node);

static inline void make_ale_orphaned(map_ale_info_t *ale) {
	if(ale)
		ktree_remove_node(ale->self_tree_node);
}

void display_topology_tree(k_tree_node* parent_node);

void dump_topology_tree_by_level(int level);


/** @brief Gets the height of the topology tree
 *
 *  This will fetch and return the height of the
 *  topology tree.
 *
 *  @param none
 *  @return height of the tree
 */
int32_t map_get_topology_tree_height();

/** @brief Gets the height of an ale node in the tree
 *
 *  This will fetch and return the height of the ale node
 *  in the topology tree.
 *
 *  @param ale_node
 *  @return height of the node in the tree
 */
int32_t map_get_height_of(map_ale_info_t* ale_node);

#endif //MULTIAP_TOPOLOGY_TREE_H

