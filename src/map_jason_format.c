/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

#include "map_topology_tree.h"
#include "platform_utils.h"
#include <string.h>
#include <syslog.h>
#include <stdlib.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>


void add_jason_buf_tree_node(map_ale_info_t* child, uint32_t height, struct blob_buf *buf)
{
    int8_t mac_str[MAX_MAC_STRING_LEN] = {0};

    get_mac_as_str(child->al_mac, mac_str, MAX_MAC_STRING_LEN);
    blobmsg_add_string(buf, "ALE MAC", (const char*)mac_str);
}

void build_jason_buf_topo_tree(k_tree_node* parent_node, struct blob_buf *buf)
{
    map_ale_info_t* parent;
    map_ale_info_t* child;
    k_tree_node* child_node;
    uint32_t height;
    uint32_t color;
    void *tbl = NULL;

    parent = get_ale_from_tree(parent_node);

    if(ktree_is_leaf(parent_node))
    {
        return;
    }
    else
    {
        tbl = blobmsg_open_table(buf, NULL);
        if(NULL == tbl) {
            blobmsg_add_string(buf, "Error", NULL);
            return;
        }
        foreach_child_in(parent,child)
        {
            child_node = get_ktree_node(child);
            height = ktree_height(child_node);
            color = ktree_color(child_node);
            add_jason_buf_tree_node(child,height,buf);
            build_jason_buf_topo_tree(child_node, buf);
        }
        blobmsg_close_table(buf, tbl);
    }
}

void get_topo_tree_jason_buf(void **buf)
{
    /* free this memory in monitor task context after sending message over ubus */
    void *tbl = NULL;
    map_ale_info_t* parent = NULL;
    uint32_t height = 0;

    *buf = (struct blob_buf *) calloc(1,sizeof(struct blob_buf));
    if(NULL == *buf) {
       return;
    }
    blob_buf_init(*buf, BLOBMSG_TYPE_TABLE);

    parent = get_root_ale_node();
    height = ktree_height(parent->self_tree_node);

    tbl = blobmsg_open_table(*buf, "TopologyTree");
    if(NULL == tbl) {
        blobmsg_add_string(*buf, "Error", NULL);
        return;
    }

    add_jason_buf_tree_node(parent, height, *buf);
    build_jason_buf_topo_tree(parent->self_tree_node, *buf);

    blobmsg_close_table(*buf, tbl);
}

