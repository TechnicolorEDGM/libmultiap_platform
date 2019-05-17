/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

#ifndef MULTIAP_CONTROLLER_DATA_MODEL_H
#define MULTIAP_CONTROLLER_DATA_MODEL_H

#include <stdio.h>
#include <sys/time.h>
#include "hashmap.h"
#include "arraylist.h"
#include "kwaytree.h"
#include "map_common_defines.h"
#include "map_timer_handler.h"
#include "map_retry_handler.h"
/*
 *   @brief This API Free the iterator on last node and return false, otherwise
 *           get next hash key and return true.
 */
static inline const char* free_on_exit(hash_iterator_t *it) {
    const char *key = get_next_hash_key(it);
    if(!key)
        free_hash_iterator(it);
    return key;
}

uint8_t is_valid_datamodel();
hash_map_t* get_map_datamodel();

/*
 *   @brief Iterate through all the nodes in the map data model 
 */
#define foreach_hash_node(key) \
for (hash_iterator_t *it = new_hash_iterator(get_map_datamodel()); (NULL != (key = free_on_exit(it))); )

/*
 *   @brief Agent/Radio/BSS/STA filters from data model nodes
 */
#define filter_ale(key, obj) (( (key[0]) == ('A') &&  (key[1]) == ('L') && (key[2]) == ('E') ) ? \
                                ({obj = get_value_for_key(get_map_datamodel(), key);}) : ({continue;}))

#define filter_radio(key, obj) (( (key[0]) == ('R') &&  (key[1]) == ('A') && (key[2]) == ('D') ) ? \
                                ({obj = get_value_for_key(get_map_datamodel(), key);}) : ({continue;}))

#define filter_bss(key, obj) (( (key[0]) == ('B') &&  (key[1]) == ('S') && (key[2]) == ('S') ) ? \
                                ({obj = get_value_for_key(get_map_datamodel(), key);}) : ({continue;}))

#define filter_sta(key, obj) (( (key[0]) == ('S') &&  (key[1]) == ('T') && (key[2]) == ('A') ) ? \
                                ({obj = get_value_for_key(get_map_datamodel(), key);}) : ({continue;}))



typedef struct map_ale_info_s               map_ale_info_t;
typedef struct map_radio_info_s             map_radio_info_t;
typedef struct map_bss_info_s               map_bss_info_t;
typedef struct map_sta_info_s               map_sta_info_t;
typedef union  map_esp_info_s               map_esp_info_t;
typedef struct map_ap_metric_s              map_ap_metric_t;
typedef struct map_sta_capability_s         map_sta_capability_t;
typedef struct map_radio_capablity_s        map_radio_capablity_t;
typedef struct map_radio_ht_capabilty_s     map_radio_ht_capabilty_t;
typedef struct map_radio_vht_capabilty_s    map_radio_vht_capabilty_t;
typedef struct map_radio_he_capabilty_s     map_radio_he_capabilty_t;
typedef struct map_radio_policy_s           map_radio_policy_t;
typedef struct map_agent_policy_s           map_agent_policy_t;
typedef struct map_agent_capablity_s        map_agent_capablity_t;
typedef struct map_beacon_report_element_s  map_beacon_report_element_t;
typedef struct map_tx_metric_params_s       map_tx_metric_params_t;
typedef struct map_rx_metric_params_s       map_rx_metric_params_t;
typedef struct map_neighbor_link_metric_s   map_neighbor_link_metric_t;


#define foreach_radio_of(ale, radio)\
map_radio_info_t **radio_ptr = NULL;\
for (radio_ptr = &ale->radio_list[0]; ((*radio_ptr != NULL) && (radio = *radio_ptr)); radio_ptr++ )\


#define foreach_bss_of(radio, bss)\
map_bss_info_t **bss_ptr = NULL;\
for (bss_ptr = &radio->bss_list[0]; ((*bss_ptr != NULL) &&( bss = *bss_ptr)); bss_ptr++ )\
 

/* FRV: Note: the way this struct is used in 1905 lib map_tlvs.c:
   - the struct must be packed
   - the subelements cannot be a member
*/
struct map_beacon_report_element_s {
    uint8_t elementId;
    uint8_t length;
    uint8_t measurement_token;
    uint8_t measurement_report_mode;
    uint8_t measurement_type;
    uint8_t operating_class;
    uint8_t channel;
    uint8_t measurement_time[BEACON_REPORT_START_TIME_SIZE];
    uint16_t measurement_duration;
    uint8_t reported_frame_information;
    uint8_t rcpi;
    uint8_t rsni;
    uint8_t bssid[MAC_ADDR_LEN];
    uint8_t antenna_id;
    uint32_t parent_tsf;
    //uint8_t subelements;
} STRUCT_PACKED;

typedef struct map_client_traffic_stats_s {
    uint32_t txbytes;
    uint32_t rxbytes;
    uint32_t txpkts;
    uint32_t rxpkts;
    uint32_t txpkterrors;
    uint32_t rxpkterrors;
    uint32_t retransmission_cnt;
}map_sta_traffic_stats_t;

typedef struct map_client_link_metrics_s {
    uint32_t age;
    uint32_t dl_mac_datarate;
    uint32_t ul_mac_datarate;
    uint8_t  rssi;
}map_sta_link_metrics_t;

typedef struct map_client_metrics_s {
    struct timespec last_sta_metric_time; /* This is different from age, age is (curr_time - last_sta_metric_time) */
    map_sta_link_metrics_t link;
    map_sta_traffic_stats_t traffic;
}map_sta_metrics_t;

struct map_sta_capability_s {
    uint8_t max_tx_spatial_streams;
    uint8_t max_rx_spatial_streams;
    uint8_t max_bandwidth;
    uint8_t supported_standard;
    uint8_t sgi_support:1;
    uint8_t dot11k_support:1;
    uint8_t dot11k_brp_support:1;
    uint8_t dot11k_bra_support:1;
    uint8_t dot11v_btm_support:1;
    uint8_t backhaul_sta:1;
};

struct map_sta_info_s
{
    uint8_t                 mac[MAC_ADDR_LEN];
    uint8_t                 state;
    uint8_t                 steer_target_bssid[MAC_ADDR_LEN];
    map_sta_capability_t    sta_caps;
    time_t                  assoc_time; /* This is different from age , age is (curr_time - assoc_time)*/
    uint16_t                since_assoc_time;
    array_list_t            *metrics;
    void                    *beacon_metrics;
    map_sta_traffic_stats_t *traffic_stats;
    map_bss_info_t          *bss;
    uint16_t                assoc_frame_len;
    uint8_t                 *assoc_frame;
};

union map_esp_info_s { //esp = estimated service parameters
    struct {
        uint8_t esp_subelement;               //This holds access_category->0-1bits, data_format->3-4bits, ba_window_size->5-7
        uint8_t estimated_air_time_fraction;
        uint8_t ppdu_target_duration;
    };
    uint8_t byte_stream[3];
};

struct map_tx_metric_params_s
{
    uint16_t phy_rate;
    uint32_t packet_errors;
    uint32_t transmitted_packets;
    uint16_t mac_throughput_capacity;
    uint16_t link_availability;
};

struct map_rx_metric_params_s
{
   uint32_t packets_received;
    uint32_t packet_errors;
    uint8_t  rssi;
};

struct map_neighbor_link_metric_s
{
    uint8_t     al_mac[MAC_ADDR_LEN]; //
    uint8_t     neighbor_iface_mac[MAC_ADDR_LEN];
    uint8_t     local_iface_mac[MAC_ADDR_LEN];
    uint16_t    intf_type;
    map_tx_metric_params_t tx_metric;
    map_rx_metric_params_t rx_metric;
};

struct map_ap_metric_s {
    uint32_t        channel_utilization;
    uint8_t         sta_count; // as per the metrics parameter
    uint8_t         esp_present; // BIT7->AC_BE, BIT6->AC_BK, BIT5->VO, BIT4->VI 
    map_esp_info_t  esp[MAX_ACCESS_CATEGORIES];
};
    
struct map_bss_info_s
{
    uint8_t             bssid[MAC_ADDR_LEN];
    char*               supported_sec_modes;
    uint8_t             ssid_len;
    uint8_t             ssid[MAX_SSID_LEN+1];
    char                iface_name[MAX_IFACE_NAME_LEN];
    uint16_t            state; /* active/configured/wps_enabled */
    uint8_t             type;   /* Fronthaul or backhaul */
    array_list_t*       neigh_link_metric_list;
    map_ap_metric_t     metrics;
    map_radio_info_t*   radio;  // parent reference
    array_list_t*       sta_list;
    array_list_t*       btm_steer_request_sta_list;
};

typedef struct dynamic_non_operable_channel_s {
    uint8_t channel_num;
    uint8_t freq_restriction;
} dynamic_non_operable_channel_t;

typedef struct map_op_class_s {
    uint8_t op_class;
    uint8_t eirp;
    uint8_t pref; // TODO : How to store "pref" and "reason" for controller preference
    uint8_t reason;
    uint8_t static_non_operable_count;
    uint8_t static_non_operable_channel[MAX_CHANNEL_IN_OPERATING_CLASS];
    uint8_t dynamic_non_operable_count;
    dynamic_non_operable_channel_t dynamic_non_operable_channel[MAX_CHANNEL_IN_OPERATING_CLASS];

    /* Typically the channel list - agent and controller is only for temporarily non-operable channels i.e PREF_0
       For other cases, the default value by itself is 15, so no need to maintain it. For effieciency, just keep count as 0
    if pref is 15 */
    /* List of channels for which agent specified preference */
    uint8_t agent_channel_count;
    uint8_t agent_channel[MAX_CHANNEL_IN_OPERATING_CLASS];
    
    uint8_t agent_non_oper_ch_cnt;
    uint8_t agent_non_oper_ch[MAX_CHANNEL_IN_OPERATING_CLASS];

    /* List of channels for which controller specified preference besides the agent channels */
    uint8_t cntlr_channel_count;
    uint8_t cntrl_channel[MAX_CHANNEL_IN_OPERATING_CLASS];
    /* We are considering only 2 values for now - PREF_0 and PREF_15 */
} map_op_class_t;

struct map_radio_capablity_s {              //ap_radio_basic_capabilities
    uint8_t max_bss_supported;
    uint8_t max_tx_spatial_streams;
    uint8_t max_rx_spatial_streams;
    uint8_t type;
    uint8_t max_bandwidth;
    uint8_t sgi_support;
    uint8_t su_beamformer_capable;
    uint8_t mu_beamformer_capable;
    uint8_t supported_standard;
    uint8_t transmit_power_limit;
};

struct map_radio_ht_capabilty_s {
    uint8_t max_supported_tx_streams:4;
    uint8_t max_supported_rx_streams:4;
    uint8_t gi_support_20mhz:1;
    uint8_t gi_support_40mhz:1;
    uint8_t ht_support_40mhz:1;
    uint8_t reserved:5;
};

struct map_radio_vht_capabilty_s {
    uint16_t supported_tx_mcs;
    uint16_t supported_rx_mcs;
    uint8_t  max_supported_tx_streams:4;
    uint8_t  max_supported_rx_streams:4;
    uint8_t  gi_support_80mhz:1;
    uint8_t  gi_support_160mhz:1;
    uint8_t  support_80_80_mhz:1;
    uint8_t  support_160mhz:1;
    uint8_t  su_beamformer_capable:1;
    uint8_t  mu_beamformer_capable:1;
    uint8_t  reserved:2;
};

struct map_radio_he_capabilty_s {
    uint8_t supported_mcs_length;
    uint8_t supported_tx_rx_mcs[12];
    uint8_t max_supported_tx_streams:4;
    uint8_t max_supported_rx_streams:4;
    uint8_t support_80_80_mhz:1;
    uint8_t support_160mhz:1;
    uint8_t su_beamformer_capable:1;
    uint8_t mu_beamformer_capable:1;
    uint8_t ul_mimo_capable:1;
    uint8_t ul_mimo_ofdma_capable:1;
    uint8_t dl_mimo_ofdma_capable:1;
    uint8_t ul_ofdma_capable:1;
    uint8_t dl_ofdma_capable:1;
    uint8_t reserved:7;
};

struct map_radio_policy_s {              //metric and steering policy per radio
    uint8_t steering_policy;
    uint8_t report_metrics;
    uint8_t channel_utilization_threshold;
    uint8_t rssi_steering_threshold;
    uint8_t reporting_rssi_threshold;
    uint8_t reporting_rssi_margin_override;
    uint8_t channel_utilization_reporting_threshold;
    uint8_t associated_sta_policy;
};

struct map_agent_policy_s{            //metric policy per agent
    uint8_t metric_reporting_interval;
    uint8_t number_of_local_steering_disallowed;
    uint8_t number_of_btm_steering_disallowed;
    array_list_t* local_steering_macs_disallowed_list;
    array_list_t* btm_steering_macs_disallowed_list;
};

struct map_agent_capablity_s{
    uint8_t ib_unassociated_sta_link_metrics_supported;
    uint8_t oob_unassociated_sta_link_metrics_supported;
    uint8_t rssi_agent_steering_supported;
};

struct map_radio_info_s
{
    char                        radio_name[MAX_RADIO_NAME_LEN];
    uint8_t                     radio_id[MAC_ADDR_LEN];
    char                        iface_name[MAX_IFACE_NAME_LEN];
    uint8_t                     supported_freq;
    uint16_t                    band_type_5G;
    uint8_t                     max_bss;
    uint8_t                     num_bss;
    uint8_t                     current_op_class;
    uint8_t                     current_op_channel;
    uint8_t                     current_bw;
    uint8_t                     current_tx_pwr;
    uint16_t                    state;
    void                        *wsc_data;
    map_bss_info_t              *bss_list[MAX_BSS_PER_RADIO];
    map_ale_info_t              *ale;
    map_radio_capablity_t       radio_caps;
    map_radio_ht_capabilty_t    *ht_caps;
    map_radio_vht_capabilty_t   *vht_caps;
    map_radio_he_capabilty_t    *he_caps;
    map_radio_policy_t          radio_policy;
    uint8_t                     op_class_count;
    map_op_class_t              *op_class_list;
    void                        *unassoc_metrics;
};

struct map_ale_info_s
{
    uint8_t                    al_mac[MAC_ADDR_LEN];
    struct timespec            keep_alive_time;
    uint8_t                    first_chan_sel_req_done;
    struct timespec            last_chan_sel_req_time;
    uint8_t                    iface_mac[MAC_ADDR_LEN]; // Remove it once agent dependency is removed
    char                       iface_name[MAX_IFACE_NAME_LEN]; // Receiving interface in controller
    char                       manufacturer_name[MAX_MANUFACTURER_NAME_LEN];
    uint8_t                    upstream_remote_iface_mac[MAC_ADDR_LEN];  // Parent interface mac
    uint8_t                    upstream_local_iface_mac[MAC_ADDR_LEN]; //bSTA mac
    uint16_t                   upstream_iface_type; /* Interface type per table 6-12 of 1905.1 specification*/
    uint8_t                    num_radios;
    uint8_t                    num_supported_radios;
    uint8_t                    bh_set;
    map_radio_info_t           *radio_list[MAX_RADIOS_PER_AGENT];
    map_agent_policy_t         agent_policy;
    map_agent_capablity_t      agent_capability;
    array_list_t*              eth_neigh_link_metric_list;
    map_neighbor_link_metric_t upstream_link_metrics;
    void                       *unassoc_metrics;
    k_tree_node                *self_tree_node;
};

/** @brief Initializes the data model
 *
 *  This will create a new hash table and handles associated error cases.
 *
 *  @param None
 *  @return -1 or error, 0 on success
 */
int8_t init_map_datamodel();

/** @brief This will create new agent node if not exist.
 *
 *  If the agent node exist in hash table "g_data_model" it creates it.
 *  If agent node doesn't exist it creates a new key value pair in hash table.
 *
 *  @param al_mac AL entity mac address of the agent.
 *  @return Pointer to the map_ale_info_t of success. Null on failure.
 */
map_ale_info_t* create_ale(uint8_t* al_mac);

/** @brief Get the agent node from the hash table
 *
 *  If the agent node exist in hash table "g_data_model" it returns it.
 *  If agent node  doesn't exist it returns NULL.
 *
 *  @param al_mac AL entity mac address of the agent.
 *  @return Pointer to the map_ale_info_t of success. Null on failure.
 */
map_ale_info_t* get_ale(uint8_t* al_mac);

/** @brief This will remove agent node if exist.
 *
 *  If the agent node exist in hash table "g_data_model" it removes it.
 *  If agent node doesn't exist it does nothing.
 *
 *  @param al_mac AL entity mac address of the agent.
 *  @return -1 or error, 0 on failure
 */
int8_t remove_ale(uint8_t* al_mac);

/** @brief This will create new radio node if not exist.
 *
 *  If the radio node exist in hash table "g_data_model" it creates it.
 *  If radio node doesn't exist it creates a new key value pair in hash table.
 *
 *  @param radio_id : MAC address of the Radio.
 *  @return Pointer to the map_radio_info_t of success. Null on failure.
 */
map_radio_info_t* create_radio(uint8_t* radio_id, uint8_t* al_mac);

/** @brief This will be used to tie ALE and radio
 *
 *  This API creates forward and reverse linking of ALE and radio
 *
 *  @param radio  : Pointer to the map_radio_info_t
 *  @param al_mac : AL mac  of the AL entity to be linked with radio
 *  @return       : None
 */
void update_ale_radio_link(map_radio_info_t* radio, uint8_t* al_mac);

/** @brief Get the radio node from the hash table
 *
 *  If the radio node exist in hash table "g_data_model" it returns it.
 *  If radio node  doesn't exist it returns NULL.
 *
 *  @param radio_id : MAC address of the Radio.
 *  @return Pointer to the map_radio_info_t of success. Null on failure.
 */
map_radio_info_t* get_radio(uint8_t* radio_id);

/** @brief This will remove radio node if exist.
 *
 *  If the radio node exist in hash table "g_data_model" it removes it.
 *  If radio node doesn't exist it does nothing.
 *
 *  @param radio_id : MAC address of the Radio.
 *  @return -1 or error, 0 on failure
 */
int8_t remove_radio(uint8_t* radio_id);

/** @brief This will create new BSS node if not exist.
 *
 *  If the BSS node exist in hash table "g_data_model" it creates it.
 *  If BSS node doesn't exist it creates a new key value pair in hash table.
 *
 *  @param radio_id : MAC address of the BSS.
 *  @return Pointer to the map_bss_info_t of success. Null on failure.
 */
map_bss_info_t* create_bss(uint8_t* bss_id, uint8_t* radio_id);

/** @brief Get the BSS node from the hash table
 *
 *  If the BSS node exist in hash table "g_data_model" it returns it.
 *  If BSS node  doesn't exist it returns NULL.
 *
 *  @param radio_id : MAC address of the BSS.
 *  @return Pointer to the map_bss_info_t of success. Null on failure.
 */
map_bss_info_t* get_bss(uint8_t* bss_id);

/** @brief This will remove BSS node if exist.
 *
 *  If the BSS node exist in hash table "g_data_model" it removes it.
 *  If BSS node doesn't exist it does nothing.
 *
 *  @param radio_id : MAC address of the BSS.
 *  @return -1 or error, 0 on failure
 */
int8_t remove_bss(uint8_t* bss_id);

/** @brief This will create new STA node if not exist.
 *
 *  1) If the STA node exist in hash table it assocciates the station to 
 *      the bss and returns the existing station object
 *  2) If STA node doesn't exist it creates a new object and 
 *      assocciates the station to the bss.
 *  3) If the BSS update failed it returns success.
 *
 *  @param sta_mac : MAC address of the client station
 *  @param bss_id  : MAC address of the BSS
 *  @return Pointer to the map_sta_info_t of success. Null on failure.
 */
map_sta_info_t* create_sta(uint8_t* sta_mac, uint8_t* bss_id);

/** @brief Get the STA node from the hash table
 *
 *  If the STA node exist in hash table "g_data_model" it returns it.
 *  If STA node  doesn't exist it returns NULL.
 *
 *  @param sta_mac : MAC address of the client station
 *  @return Pointer to the map_sta_info_t of success. Null on failure.
 */
map_sta_info_t* get_sta(uint8_t* sta_mac);

/** @brief This will remove STA node if exist.
 *
 *  If the STA node exist in hash table "g_data_model" it removes it.
 *  If STA node doesn't exist it does nothing.
 *
 *  @param sta_mac : MAC address of the station.
 *  @return -1 or error, 0 on failure
 */
int8_t remove_sta(uint8_t* sta_mac, uint8_t* bss_id);

/** @brief This will remove STA node if exist.
 *
 *  If the STA node exist in hash table "g_data_model" it removes it.
 *  If STA node doesn't exist it does nothing.
 *
 *  @param sta_mac : MAC address of the station.
 *  @return -1 or error, 0 on failure
 */
int8_t update_sta_bss(uint8_t* sta_mac, uint8_t* bss_id);

/** @brief This will convert the hex MAC address to ASCII string
 *
 *  
 *  Mac addess will be converted into a string "00:00:00:00:00:00"
 *
 *  @param addr     : MAC address in hex form,
 *         string   : MAC address in string form
 *         length   : String length
 *  @return -1 or error, 0 on failure
 */
void get_mac_as_str(uint8_t* addr, int8_t* string, int length);

/** @brief This will add a MAC to the array list
 *
 *  
 *  Mac addess will be added to the array list
 *
 *  @param addr     : MAC address in hex form,
 *         list   : list to add to
 *  @return -1 or error, 0 on failure
 */
int8_t add_sta_to_list(uint8_t *sta_mac,array_list_t *list);

/** @brief This will remove a MAC from the array list
 *
 *  
 *  Mac addess will be removed from the array list
 *
 *  @param addr     : MAC address in hex form,
 *         list   : list to remove from
 *  @return -1 or error, 0 on failure
 */
int8_t remove_sta_from_list(uint8_t *sta_mac,array_list_t *list);

/** @brief This will remove all MAC from the array list
 *
 *  
 *  All Mac addess will be removed from the array list
 *
 *  @param list   : list to remove from
 *  @return void
 */
void empty_array_list(array_list_t * arraylist);

/** @brief This will return index of a neighbor from the array list
 *
 *  @param addr     : Neighbor object,
 *         list   : list 
 *  @return index if object found, -1 if not found
 */

int8_t get_index_of_neigh(map_neighbor_link_metric_t *object,array_list_t *list);

/** @brief This will remove a neighbor from the array list
 *
 *
 *  A neighbor object will be removed from the array list
 *
 *  @param addr     : Neighbor object,
 *         list   : list to remove from
 *  @return -1 or error, 0 on failure
 */
int8_t remove_neigh_from_list(map_neighbor_link_metric_t *object, array_list_t *list);

#endif // MULTIAP_CONTROLLER_DATA_MODEL_H

#ifdef __cplusplus
}
#endif
