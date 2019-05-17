/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

#include "map_data_model.h"
#include "platform_map.h"
#include "platform_multiap_get_info.h"
#include "map_data_model_dumper.h"
#include "map_topology_tree.h"
#include "hashmap.h"
#include <string.h>

static hash_map_t* g_data_model =  NULL;

uint8_t is_valid_datamodel()
{
    if(g_data_model)
        return 1;

    platform_log(MAP_LIBRARY,LOG_ERR, "Hash not initalized yet\n");
    return 0;
}

static inline void get_agent_key(unsigned char* addr, char* string, int length) {
    if(addr == NULL && string== NULL) return;
    snprintf(string, length, "ALE:%02x:%02x:%02x:%02x:%02x:%02x",
             addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

static inline void get_radio_key(unsigned char* addr, char* string, int length) {
    if(addr == NULL && string== NULL) return;
    snprintf(string, length, "RAD:%02x:%02x:%02x:%02x:%02x:%02x",
             addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

static inline void get_bss_key(unsigned char* addr, char* string, int length) {
    if(addr == NULL && string== NULL) return;
    snprintf(string, length, "BSS:%02x:%02x:%02x:%02x:%02x:%02x",
             addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

static inline void get_sta_key(unsigned char* addr, char* string, int length) {
    if(addr == NULL && string== NULL) return;
    snprintf(string, length, "STA:%02x:%02x:%02x:%02x:%02x:%02x",
             addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

static int8_t get_index_of_sta(uint8_t *sta_mac,array_list_t *list)
{
    int8_t index = 0;
    uint8_t sta_mac_found = 0;
    list_iterator_t* it = new_list_iterator(list);
    if(!it)
        return -1;

    while(it->iter)
    {
        uint8_t* mac = (uint8_t*) get_next_list_object(it);
        if(mac && (memcmp(mac, sta_mac, MAC_ADDR_LEN) == 0))
        {
            sta_mac_found = 1;
            break;
        }
        index++;
    }

    free_list_iterator(it);

    if(sta_mac_found) return index; else return -1;
}

/* Retry timer cleanup of ALE, Radio, STA*/
static inline void cleanup_ale_retry_timers(map_ale_info_t *ale) {
    // cleanup retry timers
    char *ale_retry_ids[]     = { POLICY_CONFIG_RETRY_ID, AP_CAPS_QUERY_RETRY_ID,
        CHAN_PREF_QUERY_RETRY_ID, CHAN_SELEC_REQ_RETRY_ID, TOPOLOGY_QUERY_RETRY_ID };

    uint8_t retry_timer_count = sizeof(ale_retry_ids)/sizeof(char*);
    char retry_id[MAX_TIMER_ID_STRING_LENGTH];

    for (uint8_t i = 0; i < retry_timer_count; ++i) {
        GET_RETRY_ID(ale->al_mac, ale_retry_ids[i] , retry_id);
        if(is_timer_registered(retry_id)) {
            map_unregister_retry((const char*)retry_id);
        }
    }
}

static inline void cleanup_radio_retry_timers(map_radio_info_t *radio) {
    // cleanup retry timers
    char    *radio_retry_ids[]  = { POLICY_CONFIG_RETRY_ID};
    uint8_t retry_timer_count   = sizeof(radio_retry_ids)/sizeof(char*);
    char    retry_id[MAX_TIMER_ID_STRING_LENGTH];

    for (uint8_t i = 0; i < retry_timer_count; ++i) {
        GET_RETRY_ID(radio->radio_id, radio_retry_ids[i] , retry_id);
        if(is_timer_registered(retry_id)) {
            map_unregister_retry(retry_id);
        }
    }
}

static inline void cleanup_sta_retry_timers(map_sta_info_t *sta) {
    // cleanup retry timers
    char *sta_retry_ids[]     = {CLIENT_CAPS_QUERRY_RETRY_ID};
    uint8_t retry_timer_count = sizeof(sta_retry_ids)/sizeof(char*);
    char retry_id[MAX_TIMER_ID_STRING_LENGTH];

    for (uint8_t i = 0; i < retry_timer_count; ++i) {
        GET_RETRY_ID(sta->mac, sta_retry_ids[i] , retry_id);
        if(is_timer_registered(retry_id)) {
            map_unregister_retry((const char*)retry_id);
        }
    }
}

int8_t add_sta_to_list(uint8_t *sta_mac,array_list_t *list)
{
    // Check for ducplicates before adding.
    // if there is a valid index then there is a node already available
    if((!sta_mac)  || (list == NULL) || (get_index_of_sta(sta_mac,list) != -1) )
        return -1;

    uint8_t *mac = (uint8_t*) calloc(1, MAC_ADDR_LEN);
    if(!mac)
    {
        platform_log(MAP_LIBRARY,LOG_ERR,"%s Failed to allocate memory.\n", __func__);
        return -1;
    }

    memcpy(mac, sta_mac, MAC_ADDR_LEN);

    // Add it to the list
    if(push_object(list,(void*)mac) == -1) {
        platform_log(MAP_LIBRARY,LOG_ERR,"%s Failed adding agent to list\n",__func__);
        free(mac);
        return -1;
    }

    return 0;
}

int8_t remove_sta_from_list(uint8_t *sta_mac, array_list_t *list)
{
    int8_t status = -1;
    
    if((sta_mac)  || (list != NULL) ) {
        int8_t node_index = get_index_of_sta(sta_mac,list);

        if(node_index == -1)
            return 0;

        uint8_t* deleted_sta_mac = remove_object_at_index(list,node_index);

        // Just to ensure we deleted the right node
        if(deleted_sta_mac) {
            free(deleted_sta_mac);
            status = 0;
        }
    }
    return status;
}

void empty_array_list(array_list_t * arraylist)
{
    /* No need to check for NULL as its been taken care inside list implementation */
    uint32_t count = list_get_size(arraylist);
    uint32_t index = 0;

    for(index = 0; index < count; index++)
    {
        
        uint8_t* deleted_sta_mac = remove_last_object(arraylist);

        // Delete the right node
        if(deleted_sta_mac)
        {
            free(deleted_sta_mac);
        }
    }
}

int8_t get_index_of_neigh(map_neighbor_link_metric_t *object,array_list_t *list)
{
    int8_t index = 0;
    uint8_t obj_found = 0;
    list_iterator_t* it = new_list_iterator(list);
    if(!it)
        return -1;

    while(it->iter)
    {
        map_neighbor_link_metric_t *obj = (map_neighbor_link_metric_t*) get_next_list_object(it);
        if(obj == object)
        {
            obj_found = 1;
           break;
        }
        index++;
    }

    free_list_iterator(it);

    if(obj_found) return index; else return -1;
}

int8_t remove_neigh_from_list(map_neighbor_link_metric_t *object, array_list_t *list)
{
    int8_t status = -1;

    if((object)  || (list != NULL) )
    {
        int8_t node_index = get_index_of_neigh(object,list);

        if(node_index == -1)
            return 0;

        map_neighbor_link_metric_t *obj = remove_object_at_index(list,node_index);

        // Just to ensure we deleted the right node
        if(obj)
        {
            free(obj);
            status = 0;
        }
    }

    return status;
}

void get_mac_as_str(uint8_t* addr, int8_t* string, int length)
{
    if(addr == NULL && string== NULL) return;
    snprintf((char*)string, length, "%02x:%02x:%02x:%02x:%02x:%02x",
             addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

hash_map_t* get_map_datamodel()
{
    return g_data_model;
}


int8_t init_map_datamodel()
{
    g_data_model = new_hash_map(eHashMapDefault);
    if(!g_data_model)
    {
        platform_log(MAP_LIBRARY,LOG_ERR, " %s Failed to create onboarding agent list hashmap\n",__func__);
        return -1;
    }

    return 0;
}

map_ale_info_t* create_ale(uint8_t* al_mac) {
    if(al_mac == NULL) {
        platform_log(MAP_LIBRARY,LOG_ERR, " %s Empty AL MAC address.!\n", __func__);
        return NULL;
    }

    map_ale_info_t *node = NULL;

    char key[HASH_KEY_LEN] = {0};
    get_agent_key(al_mac, key, HASH_KEY_LEN);

    // If the node is created already return the existing ALE node
    node = get_value_for_key(g_data_model, key);
    if(node)
        return node;

    node = calloc(1, sizeof(map_ale_info_t));
    if(!node){
        platform_log(MAP_LIBRARY,LOG_ERR, "\n%s Failed to allocating memory\n", __func__);
        return node;
    }

    // Update the AL mac
    memcpy(node->al_mac, al_mac, MAC_ADDR_LEN);
    strcpy(node->iface_name, "all");

    if ( -1 == set_value_for_key(g_data_model, key, (void*) node))
    {
        platform_log(MAP_LIBRARY,LOG_ERR, " %s Failed to update agent node to hash table. \n", __func__);
        free(node);
        return NULL;
    }
    platform_log(MAP_LIBRARY,LOG_DEBUG, "-----------------------------------------------------\n");
    platform_log(MAP_LIBRARY,LOG_DEBUG, "| New MAP Agent %s ", key);
    platform_log(MAP_LIBRARY,LOG_DEBUG, "-----------------------------------------------------\n");


    //Create the neighbor link metrics
    node->eth_neigh_link_metric_list = new_array_list(eListTypeDefault);
    if(!node->eth_neigh_link_metric_list)
    {
        platform_log(MAP_LIBRARY,LOG_ERR, " %s Failed to create neighbor link metric list\n",__func__);
        return NULL;
    }

    /* create the arraylists for agent - local steering mac and btm steering mac disallowed list */
    node->agent_policy.btm_steering_macs_disallowed_list = new_array_list(eListTypeDefault);
    if(!node->agent_policy.btm_steering_macs_disallowed_list)
    {
        platform_log(MAP_LIBRARY,LOG_ERR, " %s Failed to create btm steering mac list\n",__func__);
        free(node);
        return NULL;
    }

    node->agent_policy.local_steering_macs_disallowed_list = new_array_list(eListTypeDefault);
    if(!node->agent_policy.local_steering_macs_disallowed_list)
    {
        platform_log(MAP_LIBRARY,LOG_ERR, " %s Failed to create local steering mac list\n",__func__);
        free(node);
        return NULL;
    }

	//Create new topology tree node for the al entity
	if(create_topology_tree_node(node,AL_ENTITY) < 0)
	{
		platform_log(MAP_LIBRARY,LOG_ERR, " %s Failed to create topology tree node\n",__func__);
		free(node);
		return NULL;
	}

    return node;
}

map_ale_info_t* get_ale(uint8_t* al_mac) {
    if(al_mac == NULL) {
        platform_log(MAP_LIBRARY,LOG_ERR, "Empty AL MAC address.!\n");
        return NULL;
    }

    map_ale_info_t *node = NULL;
    char key[HASH_KEY_LEN] = {0};
    get_agent_key(al_mac, key, HASH_KEY_LEN);

    node = get_value_for_key(g_data_model, key);
    return node;
}

int8_t remove_ale(uint8_t* al_mac) {
    if(al_mac == NULL) {
        platform_log(MAP_LIBRARY,LOG_ERR, " %s Empty AL MAC address.!\n", __func__);
        return -1;
    }

    map_ale_info_t *node = NULL;
    map_neighbor_link_metric_t *neigh_obj = NULL;

    char agent_key[HASH_KEY_LEN] = {0};
    get_agent_key(al_mac, agent_key, HASH_KEY_LEN);

    node = get_value_for_key(g_data_model, agent_key);
    if(node) {
        // Cleanup all the retry timers assocciated retry timers
        cleanup_ale_retry_timers(node);

        // Cleanup the radio nodes
        for (uint8_t i = 0; i < node->num_radios; ++i) {
            if(node->radio_list[i]) {
                if (-1 == remove_radio(node->radio_list[i]->radio_id)) {
                    platform_log(MAP_LIBRARY,LOG_ERR, "Failed Removing the radio\n");
                    // Procceed cleaning other resources Event if cleanup of one radio failed.
                }
            }
        }

        // Cleanup neighbor link metric references

        if(node->eth_neigh_link_metric_list != NULL) {
            while(list_get_size(node->eth_neigh_link_metric_list) > 0) {
                neigh_obj = remove_last_object(node->eth_neigh_link_metric_list);
                free(neigh_obj);
            }
            delete_array_list(node->eth_neigh_link_metric_list);
        }

        //Clean up agent steering mac disallowed list
        empty_array_list(node->agent_policy.btm_steering_macs_disallowed_list);
        empty_array_list(node->agent_policy.local_steering_macs_disallowed_list);
        delete_array_list(node->agent_policy.btm_steering_macs_disallowed_list);
        delete_array_list(node->agent_policy.local_steering_macs_disallowed_list);

        // Delete the entry from the hash table
        remove_key(g_data_model, agent_key);
        remove_topology_tree_node(node);
        if(node != NULL)
        {
            free(node);
            node = NULL;
        }
        platform_log(MAP_LIBRARY,LOG_DEBUG, "Agent Node with mac %s is removed\n", agent_key);
        return 0;
    }
    else {
        // Node does not exist. Nothing to do. return sucess
        return 0;
    }
}

void update_ale_radio_link(map_radio_info_t* radio, uint8_t* al_mac) {
    map_ale_info_t *ale = get_ale(al_mac);
    if(ale == NULL) {
        char key[HASH_KEY_LEN] = {0};
        get_agent_key(al_mac, key, HASH_KEY_LEN);
        platform_log(MAP_LIBRARY,LOG_DEBUG, "Agent Node with mac %s not found\n", key);
        return;
    }

    for (int i = 0; i < MAX_RADIOS_PER_AGENT; ++i)
    {
        // Store it when you see the first NULL
        if(ale->radio_list[i] == NULL) {
            // Make a circular reference between agent node and radio node
            ale->radio_list[i] = radio;
            ale->num_radios++;
            radio->ale = ale;
            break;
        }
    }
}

map_radio_info_t* create_radio(uint8_t* radio_id, uint8_t* al_mac) {

    if(radio_id == NULL) {
        platform_log(MAP_LIBRARY,LOG_ERR, " %s Empty AL MAC or Radio ID address.!\n", __func__);
        return NULL;
    }

    char radio_node_key[HASH_KEY_LEN] = {0};
    get_radio_key(radio_id, radio_node_key, HASH_KEY_LEN);

    map_radio_info_t* radio = NULL;
    radio = get_radio(radio_id);

    if(radio == NULL) {
        radio = calloc(1, sizeof(map_radio_info_t));
        if(radio == NULL){
            platform_log(MAP_LIBRARY,LOG_ERR, "\n%s Failed to allocating memory\n", __func__);
            return NULL;
        }

        // Update the RADIO ID mac
        memcpy(radio->radio_id, radio_id, MAC_ADDR_LEN);

        // Update the default to a invalid value
        radio->supported_freq = 0xFF;

        if ( -1 == set_value_for_key(g_data_model, radio_node_key, (void*) radio))
        {
            platform_log(MAP_LIBRARY,LOG_ERR, " %s Failed to update Radio node to hash table. \n", __func__);
            free(radio);
            return NULL;
        }
        platform_log(MAP_LIBRARY,LOG_DEBUG, "-----------------------------------------------------\n");
        platform_log(MAP_LIBRARY,LOG_DEBUG, "| New Radio %s ", radio_node_key);
        platform_log(MAP_LIBRARY,LOG_DEBUG, "-----------------------------------------------------\n");
    }

    if((al_mac !=NULL) && (radio->ale == NULL)) {
        update_ale_radio_link(radio, al_mac);
    }

    return radio;
}

map_radio_info_t* get_radio(uint8_t* radio_id) {
    if(radio_id == NULL) {
        platform_log(MAP_LIBRARY,LOG_ERR, "Empty Radio ID address.!\n");
        return NULL;
    }

    map_radio_info_t *node = NULL;
    char key[HASH_KEY_LEN] = {0};
    get_radio_key(radio_id, key, HASH_KEY_LEN);

    node = get_value_for_key(g_data_model, key);
    return node;
}

int8_t remove_radio(uint8_t* radio_id) {
    if(radio_id == NULL) {
        platform_log(MAP_LIBRARY,LOG_ERR, " %s Empty AL MAC address.!\n", __func__);
        return -1;
    }

    map_radio_info_t *radio = NULL;

    char radio_key[HASH_KEY_LEN] = {0};
    get_radio_key(radio_id, radio_key, HASH_KEY_LEN);

    radio = get_value_for_key(g_data_model, radio_key);
    if(radio) {

        // Cleanup all the retry timers associated with this radio
        cleanup_radio_retry_timers(radio);

        // Cleanup BSS nodes under the radio
        for (uint8_t i = 0; i < radio->num_bss; ++i) {
            if(radio->bss_list[i]) {
                if (-1 == remove_bss(radio->bss_list[i]->bssid)) {
                    platform_log(MAP_LIBRARY,LOG_ERR, "Failed Removing the BSS\n");
                    // Procceed cleaning other resources Event if cleanup of one BSS failed.
                }
            }
        }

        // Cleanup op_class_list
        if(radio->op_class_list)
            free(radio->op_class_list);

        if(radio->ht_caps)
            free(radio->ht_caps);

        if(radio->vht_caps)
            free(radio->vht_caps);

        if(radio->he_caps)
            free(radio->he_caps);

        // Cleanup agent info radio list
        if(radio->ale) {
            for (int i = 0; i < MAX_RADIOS_PER_AGENT; ++i) {
                if(radio->ale->radio_list[i] ==  radio) {
                    radio->ale->radio_list[i] = NULL;
                    break;
                }
            }
        }

        // Delete the entry from the hash tabel
        remove_key(g_data_model, radio_key);
        free(radio);

        platform_log(MAP_LIBRARY,LOG_DEBUG, "Radio Node with mac %s is removed\n", radio_key);
        return 0;
    }
    else {
        // Node does not exist. Nothing to do. return sucess
        return 0;
    }
}

static map_bss_info_t* _create_new_bss(uint8_t* bss_id, map_radio_info_t *radio) {

    map_bss_info_t *bss = NULL;

    do {
        if(bss_id == NULL || radio == NULL)
            break;

        bss = calloc(1, sizeof(map_bss_info_t));
        if(bss == NULL){
            platform_log(MAP_LIBRARY,LOG_ERR, "\n%s Failed to allocating memory\n", __func__);
            break;
        }

        // Update the BSS ID mac
        memcpy(bss->bssid, bss_id, MAC_ADDR_LEN);

        int8_t bss_node_key[HASH_KEY_LEN] = {0};
        get_bss_key(bss_id, (char*)bss_node_key, HASH_KEY_LEN);

        // Update the radio Node
        for (int i = 0; i < MAX_BSS_PER_RADIO; ++i)
        {
            // Store it when you see the first NULL
            if(radio->bss_list[i] == NULL) {
                // Make a circular reference between radio node and bss node
                radio->bss_list[i] = bss;
                bss->radio = radio;
                break;
            }
        }

        // Formation of circular refernce confirms the successfull update
        if(bss->radio == NULL) {
            platform_log(MAP_LIBRARY,LOG_ERR, " %s Already %d BSS configured.! \n", __func__, MAX_BSS_PER_RADIO);
            free(bss);
            bss = NULL;
            break;
        }

        //Create the station list
        bss->sta_list = new_array_list(eListTypeDefault);
        if(!bss->sta_list)
        {
            platform_log(MAP_LIBRARY,LOG_ERR, " %s Failed to create station list\n",__func__);
            free(bss);
            return NULL;
        }

        //Create the neighbor link metrics
        bss->neigh_link_metric_list = new_array_list(eListTypeDefault);
        if(!bss->neigh_link_metric_list)
        {
            platform_log(MAP_LIBRARY,LOG_ERR, " %s Failed to create neighbor link metric list\n",__func__);
            return NULL;
        }

        if ( -1 == set_value_for_key(g_data_model, (const char*)bss_node_key, (void*) bss))
        {
            platform_log(MAP_LIBRARY,LOG_ERR, " %s Failed to update BSS node to hash table. \n", __func__);
            break;
        }
        platform_log(MAP_LIBRARY,LOG_DEBUG, "-----------------------------------------------------\n");
        platform_log(MAP_LIBRARY,LOG_DEBUG, "| New BSS %s ", bss_node_key);
        platform_log(MAP_LIBRARY,LOG_DEBUG, "-----------------------------------------------------\n");
    }while(0);

    return bss;
}

map_bss_info_t* create_bss(uint8_t* bss_id, uint8_t* radio_id) {
    map_bss_info_t* bss = NULL;

    do {
        if(bss_id == NULL || radio_id == NULL) {
            platform_log(MAP_LIBRARY,LOG_ERR, " %s Empty BSS MAC or Radio ID address.!\n", __func__);
            break;
        }

        map_radio_info_t *radio = NULL;
        radio = get_radio(radio_id);
        if(radio == NULL) {
            platform_log(MAP_LIBRARY,LOG_DEBUG, "%s Radio Node not found\n", __func__);
            break;
        }

        bss = get_bss(bss_id);

        if(bss) {
            if(bss->radio && (memcmp(bss->radio->radio_id, radio_id, MAC_ADDR_LEN) != 0)) {
                platform_log(MAP_LIBRARY,LOG_ERR, "\n%s :BSS node already associated with different Radio!\n", __func__);
                break;
            }
        }
        else {
            bss = _create_new_bss(bss_id, radio);
            break;
        }
    } while(0);

    return bss;
}

map_bss_info_t* get_bss(uint8_t* bss_id) {
    if(bss_id == NULL) {
        platform_log(MAP_LIBRARY,LOG_ERR, "Empty BSS ID address.!\n");
        return NULL;
    }

    map_bss_info_t *node = NULL;
    char bss_key[HASH_KEY_LEN] = {0};
    get_bss_key(bss_id, bss_key, HASH_KEY_LEN);

    node = get_value_for_key(g_data_model, bss_key);
    return node;   
}

int8_t remove_bss(uint8_t* bss_id) {
    if(bss_id == NULL) {
        platform_log(MAP_LIBRARY,LOG_ERR, " %s Empty BSS MAC address.!\n", __func__);
        return -1;
    }

    map_bss_info_t *bss = NULL;
    map_neighbor_link_metric_t *neigh_obj = NULL;

    char bss_key[HASH_KEY_LEN] = {0};
    get_bss_key(bss_id, bss_key, HASH_KEY_LEN);

    bss = get_value_for_key(g_data_model, bss_key);
    if(bss) {
        if(bss->sta_list) {
            map_sta_info_t *sta = NULL;
            for(uint8_t* sta_mac_to_delete = NULL; (0 < list_get_size(bss->sta_list)); sta_mac_to_delete = NULL ){
                sta_mac_to_delete = last_object(bss->sta_list);
                if(sta_mac_to_delete == NULL)
                    break;

                sta = get_sta(sta_mac_to_delete);
                if(sta) {
                    // This removes the BSS -> STA reference and the STA themselves
                    remove_sta(sta_mac_to_delete, bss_id);
                }
                else {
                    platform_log(MAP_LIBRARY,LOG_ERR, "%s Dangling reference in BSS (%s) STA list", __func__, bss_key);
                    // This case should never happen, but added to avoid memory leak
                    remove_last_object(bss->sta_list);
                    free(sta_mac_to_delete);
                }
            }
            // Cleanup array list
            delete_array_list(bss->sta_list);
        }


        // Cleanup neighbor link metric references

        if(bss->neigh_link_metric_list != NULL) {
            while(list_get_size(bss->neigh_link_metric_list) > 0) {
                neigh_obj = remove_last_object(bss->neigh_link_metric_list);
                free(neigh_obj);
            }
            delete_array_list(bss->neigh_link_metric_list);
        }

        // Cleanup radio info bss list
        if(bss->radio) {
            for (int i = 0; i < MAX_BSS_PER_RADIO; ++i) {
                if(bss->radio->bss_list[i] ==  bss) {
                    bss->radio->bss_list[i] = NULL;
                    break;
                }
            }
        }

        // Delete the entry from the hash tabel
        remove_key(g_data_model, bss_key);
        free(bss);

        platform_log(MAP_LIBRARY,LOG_DEBUG, "BSS Node with mac %s is removed\n", bss_key);
        return 0;
    }
    else {
        // Node does not exist. Nothing to do. return success
        return 0;
    }
}

static map_sta_info_t* _create_new_sta(uint8_t* sta_mac) {
    map_sta_info_t* sta = NULL;

        sta = calloc(1, sizeof(map_sta_info_t));
        if(sta == NULL) {
            platform_log(MAP_LIBRARY,LOG_ERR, "\n%s Failed to allocating memory\n", __func__);
            return NULL;
        }
        // Update the station mac address
        memcpy(sta->mac, sta_mac, MAC_ADDR_LEN);

        char sta_key[HASH_KEY_LEN] = {0};
        get_sta_key(sta_mac, sta_key, HASH_KEY_LEN);
        if ( -1 == set_value_for_key(g_data_model, sta_key, (void*) sta))
        {
            platform_log(MAP_LIBRARY,LOG_ERR, " %s Failed to update BSS node to hash table. \n", __func__);
            free(sta);
            return NULL;
        }

        sta->metrics = new_array_list(eListTypeDefault);
        if(sta->metrics == NULL)
            platform_log(MAP_LIBRARY,LOG_ERR, "Failed Creating new STA metrics list. \n ");

        platform_log(MAP_LIBRARY,LOG_DEBUG, "-----------------------------------------------------\n");
        platform_log(MAP_LIBRARY,LOG_DEBUG, "| New STA %s ", sta_key);
        platform_log(MAP_LIBRARY,LOG_DEBUG, "-----------------------------------------------------\n");

    return sta;
}

map_sta_info_t* create_sta(uint8_t* sta_mac, uint8_t* bss_id) {
    if(sta_mac == NULL || bss_id == NULL) {
        platform_log(MAP_LIBRARY,LOG_ERR, " %s Empty STA MAC or BSS ID.!\n", __func__);
        return NULL;
    }

    map_bss_info_t *bss = NULL;
    bss = get_bss(bss_id);
    if(bss == NULL) {
        platform_log(MAP_LIBRARY,LOG_DEBUG, "%s BSS node not found\n", __func__);
        return NULL;
    }

    map_sta_info_t* sta = get_sta(sta_mac);
    if(sta == NULL) {
        sta = _create_new_sta(sta_mac);
        if(sta == NULL) {
            platform_log(MAP_LIBRARY,LOG_ERR, "%s Failed to create new STA node.", __func__);
            return NULL;
        }
    }

    // Associate or update the STA <=> BSS link
    update_sta_bss(sta_mac, bss_id);

    return sta;
}

map_sta_info_t* get_sta(uint8_t* sta_mac) {
    if(sta_mac == NULL) {
        platform_log(MAP_LIBRARY,LOG_ERR, "Empty STA mac address.!\n");
        return NULL;
    }

    map_sta_info_t *sta = NULL;
    char sta_key[HASH_KEY_LEN] = {0};
    get_sta_key(sta_mac, sta_key, HASH_KEY_LEN);

    sta = get_value_for_key(g_data_model, sta_key);
    return sta;
}

static inline int8_t cleanup_sta_resource(map_sta_info_t *sta) {
    char sta_key[HASH_KEY_LEN] = {0};
    get_sta_key(sta->mac, sta_key, HASH_KEY_LEN);
    void *obj = NULL;

    // Cleanup retry timers associated with STA
    cleanup_sta_retry_timers(sta);

    //This removes the metrics reference from sta
    if(sta->metrics != NULL) {
        while(list_get_size(sta->metrics) > 0) {
            obj = remove_last_object(sta->metrics);
            free(obj);
        }
        delete_array_list(sta->metrics);
    }

    // Cleanup Beacon metrics
    if(sta->beacon_metrics){
        free(sta->beacon_metrics);
        sta->beacon_metrics = NULL;
    }

    // Cleanup STA traffic stats
    if(sta->traffic_stats){
        free(sta->traffic_stats);
        sta->traffic_stats = NULL;
    }

    // Cleanup STA assoc frame
    if(sta->assoc_frame_len > 0) {
        free(sta->assoc_frame);
        sta->assoc_frame = NULL;
        sta->assoc_frame_len = 0;
    }

    // Delete the entry from hash tabel
    remove_key(g_data_model, sta_key);

    free(sta);
    return 0;
}

int8_t remove_sta(uint8_t* sta_mac, uint8_t* bss_id) {
    
    if(sta_mac == NULL) {
        platform_log(MAP_LIBRARY,LOG_ERR, "%s Empty STA mac address.!\n",__func__);
    }

    map_bss_info_t *remove_request_bss = get_bss(bss_id);
    map_sta_info_t *sta = get_sta(sta_mac);
    if(sta) {
        if(sta->bss == NULL) {
            return cleanup_sta_resource(sta);
        }
        // Remove STA if the request comes from associated BSS, else ignore
        else if(sta->bss == remove_request_bss) {
            if(remove_sta_from_list(sta_mac, remove_request_bss->sta_list) < 0)
                platform_log(MAP_LIBRARY,LOG_ERR, "Unable to remove station reference from BSS list");
            return cleanup_sta_resource(sta);
        }
        else {
            platform_log(MAP_LIBRARY,LOG_DEBUG, "%s STA<=>BSS and Remove request BSS are not same. Remove request declined!",__func__);
        }
    }
    return 0;
}

// This API should be used to create/update the STA <=> BSS reference link
int8_t update_sta_bss(uint8_t* sta_mac, uint8_t* bss_id) {

    if(sta_mac == NULL) {
        platform_log(MAP_LIBRARY,LOG_ERR, " %s Empty STA MAC.!\n", __func__);
        return -1;
    }

    char sta_key[HASH_KEY_LEN] = {0};
    get_sta_key(sta_mac, sta_key, HASH_KEY_LEN);

    map_sta_info_t *sta = get_sta(sta_mac);
    if(!sta) {
        platform_log(MAP_LIBRARY,LOG_ERR, "%s Unable to find the Station %s.", __func__, sta_key);
        return -1;        
    }

    if(bss_id) {
        map_bss_info_t *target_bss = get_bss(bss_id);
        if(target_bss) {
            if(sta->bss) {
                // If Current and requested BSS are not same, Remove the old STA <=> BSS reference
                if(0 != memcmp(sta->bss->bssid, bss_id, MAC_ADDR_LEN)) {
                    if(remove_sta_from_list(sta_mac, sta->bss->sta_list) < 0)
                        platform_log(MAP_LIBRARY,LOG_ERR, "Unable to remove station from bss sta list");
                }
                else {
                    // Old and requested STA <=> BSS link is same. Nothing to do
                    return 0;
                }
            }
            // Update new STA <=> BSS reference
            sta->bss = target_bss;
            if(add_sta_to_list(sta_mac, target_bss->sta_list) < 0) {
                platform_log(MAP_LIBRARY,LOG_ERR, "Unable to add station to bss sta list");
                remove_sta(sta_mac, bss_id);
                return -1;
            }        
        }
    }
    return 0;
}
