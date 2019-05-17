/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

#include "map_data_model_dumper.h"
#include "map_data_model.h"
#include "platform_map.h"
#include "platform_multiap_get_info.h"
#include "map_topology_tree.h"
#include "hashmap.h"
#include <string.h>

static const char* ZERO_MAC = "00:00:00:00:00:00";

void print_sta_bss_mapping() {

    uint16_t station_count = 0;

    platform_log(MAP_LIBRARY,LOG_INFO, "\n ======================================================================\n");
    platform_log(MAP_LIBRARY,LOG_INFO, " ||    Station MAC      ||       BSS ID        ||         ALE        ||\n");
    platform_log(MAP_LIBRARY,LOG_INFO, "\n ======================================================================\n");

    map_sta_info_t *sta = NULL;
    const char *key     = NULL;

    foreach_hash_node(key) {
        filter_sta(key, sta);
        if(sta) {
            int8_t bssid_str[MAX_MAC_STRING_LEN] = {0};
            int8_t ale_str[MAX_MAC_STRING_LEN] = {0};
            if(sta->bss){
                get_mac_as_str(sta->bss->bssid, bssid_str, MAX_MAC_STRING_LEN);
                if(sta->bss->radio && sta->bss->radio->ale)
                    get_mac_as_str(sta->bss->radio->ale->al_mac, ale_str, MAX_MAC_STRING_LEN);
                else
                    strncpy((char*)bssid_str, ZERO_MAC, MAX_MAC_STRING_LEN);
            }
            else {
                strncpy((char*)bssid_str, ZERO_MAC, MAX_MAC_STRING_LEN);
            }
            station_count++;
            platform_log(MAP_LIBRARY,LOG_INFO, " ||  %s  ||  %s  ||  %s  ||\n", \
                            (key + MAC_ADDR_START_OFFSET), bssid_str, ale_str);
        }
    }

    if(!station_count)
        platform_log(MAP_LIBRARY,LOG_INFO, " ||                     ||                     ||                    ||\n");
    platform_log(MAP_LIBRARY,LOG_INFO, "\n ======================================================================\n");
}

void print_sta_link_metrics(map_sta_info_t *sta, uint8_t print_last_n) {

    if(sta && sta->metrics) {
        list_iterator_t* it = new_list_iterator(sta->metrics);

                platform_log(MAP_LIBRARY,LOG_INFO, "     |    - LINK METRICS  :\n");
        for(uint8_t index = 0; it->iter != NULL && index < print_last_n; ) {
            map_sta_link_metrics_t *link_metrics = (map_sta_link_metrics_t*) get_next_list_object(it);
            if(link_metrics) {
                platform_log(MAP_LIBRARY,LOG_INFO, "     |      -[%d]\n", index);
                platform_log(MAP_LIBRARY,LOG_INFO, "     |        - Age           : %d\n", link_metrics->age);
                platform_log(MAP_LIBRARY,LOG_INFO, "     |        - DL Data rate  : %d\n", link_metrics->dl_mac_datarate);
                platform_log(MAP_LIBRARY,LOG_INFO, "     |        - UL Data rate  : %d\n", link_metrics->ul_mac_datarate);
                platform_log(MAP_LIBRARY,LOG_INFO, "     |        - RSSI          : %d\n\n", link_metrics->rssi);
                index++;
            }
        }
        free_list_iterator(it);
    }
}

void print_sta_metrics( map_sta_info_t *sta) {
    if(sta == NULL)
        return;

    if(sta->traffic_stats) {
        platform_log(MAP_LIBRARY,LOG_INFO, "     |    - TRAFFIC STATS :\n");
        platform_log(MAP_LIBRARY,LOG_INFO, "     |      - Tx bytes      : %d\n", sta->traffic_stats->txbytes);
        platform_log(MAP_LIBRARY,LOG_INFO, "     |      - Rx bytes      : %d\n", sta->traffic_stats->rxbytes);
        platform_log(MAP_LIBRARY,LOG_INFO, "     |      - Tx pkts       : %d\n", sta->traffic_stats->txpkts);
        platform_log(MAP_LIBRARY,LOG_INFO, "     |      - Rx pkts       : %d\n", sta->traffic_stats->rxpkts);
        platform_log(MAP_LIBRARY,LOG_INFO, "     |      - Tx pkt errors : %d\n", sta->traffic_stats->txpkterrors);
        platform_log(MAP_LIBRARY,LOG_INFO, "     |      - Rx pkt errors : %d\n", sta->traffic_stats->rxpkterrors);
        platform_log(MAP_LIBRARY,LOG_INFO, "     |      - ReTx count    : %d\n", sta->traffic_stats->retransmission_cnt);
    }
    print_sta_link_metrics(sta, 1);
}

void print_sta_info(array_list_t* sta_list) {
    if(sta_list == NULL)
        return;
    if(0 == list_get_size(sta_list))
        return;

    list_iterator_t* it = new_list_iterator(sta_list);
    uint8_t index = 0;
                platform_log(MAP_LIBRARY,LOG_INFO, "   -STA LIST\n");
                platform_log(MAP_LIBRARY,LOG_INFO, "     |\n");
                platform_log(MAP_LIBRARY,LOG_INFO, "     |-----------------------------------------------\n");

    while(it->iter != NULL) {
        uint8_t *sta_mac = (uint8_t*) get_next_list_object(it);

        if(sta_mac) {
            int8_t sta_mac_str[MAX_MAC_STRING_LEN] = {0};
            get_mac_as_str(sta_mac, sta_mac_str, MAX_MAC_STRING_LEN);

            map_sta_info_t *sta = get_sta(sta_mac);
            if(sta) {
                int8_t bssid_str[MAX_MAC_STRING_LEN] = {0};
                if(sta->bss)
                    get_mac_as_str(sta->bss->bssid, bssid_str, MAX_MAC_STRING_LEN);
                else
                    strncpy((char*)bssid_str, "None", MAX_MAC_STRING_LEN);

                platform_log(MAP_LIBRARY,LOG_INFO, "     | STA[%d]\n",index);
                platform_log(MAP_LIBRARY,LOG_INFO, "     |    - STA MAC       : %s\n",sta_mac_str);
                platform_log(MAP_LIBRARY,LOG_INFO, "     |    - Assoc to      : %s\n", bssid_str);
                platform_log(MAP_LIBRARY,LOG_INFO, "     |    - Assoc since   : %d\n", sta->since_assoc_time);
                platform_log(MAP_LIBRARY,LOG_INFO, "     |    - State         : %d\n", sta->state);
                get_mac_as_str(sta->steer_target_bssid, bssid_str, MAX_MAC_STRING_LEN);
                platform_log(MAP_LIBRARY,LOG_INFO, "     |    - Steer target  : %s\n", bssid_str);
                print_sta_metrics(sta);
                index++;
            }
        }
    }
    free_list_iterator(it);
                platform_log(MAP_LIBRARY,LOG_INFO, "     |\n");
                platform_log(MAP_LIBRARY,LOG_INFO, "     -----------------------------------------------\n");

}

void print_ap_metrics(map_bss_info_t *bss){
    if(bss == NULL)
        return;

                platform_log(MAP_LIBRARY,LOG_INFO, "    -Channel util  : %d\n", bss->metrics.channel_utilization);
                platform_log(MAP_LIBRARY,LOG_INFO, "    -Station count : %d\n", bss->metrics.sta_count);
                platform_log(MAP_LIBRARY,LOG_INFO, "    -ESP presence  : 0x%02x\n", bss->metrics.esp_present);
                platform_log(MAP_LIBRARY,LOG_INFO, "    -ESP\n");
                platform_log(MAP_LIBRARY,LOG_INFO, "      |-----------------------------------------------\n");

    for(uint8_t ac_index = 0; ac_index < MAX_ACCESS_CATEGORIES; ac_index++) {
        if (bss->metrics.esp_present & (1<<(7 - ac_index))) {
            if(ac_index == WIFI_AC_BE)
                platform_log(MAP_LIBRARY,LOG_INFO, "      | AC-BE:\n");
            else if(ac_index == WIFI_AC_BK)
                platform_log(MAP_LIBRARY,LOG_INFO, "      | AC-BK:\n");
            else if(ac_index == WIFI_AC_VO)
                platform_log(MAP_LIBRARY,LOG_INFO, "      | AC-VO:\n");
            else if(ac_index == WIFI_AC_VD)
                platform_log(MAP_LIBRARY,LOG_INFO, "      | AC-VI:\n");

                platform_log(MAP_LIBRARY,LOG_INFO, "      |  -ESP Sub Element      : 0x%02x\n", bss->metrics.esp[ac_index].esp_subelement);
                platform_log(MAP_LIBRARY,LOG_INFO, "      |  -Air Time Fraction    : 0x%02x\n", bss->metrics.esp[ac_index].estimated_air_time_fraction);
                platform_log(MAP_LIBRARY,LOG_INFO, "      |  -PPDU Target Duration : 0x%02x\n", bss->metrics.esp[ac_index].ppdu_target_duration);
        }
    }
                platform_log(MAP_LIBRARY,LOG_INFO, "       -----------------------------------------------\n");
}

void print_bss_in_radio(map_radio_info_t *radio) {
    platform_log(MAP_LIBRARY,LOG_INFO," Num of BSS  : %d\n",radio->num_bss);

    for (uint8_t i = 0; i < radio->num_bss; ++i)
    {
        int8_t bssid_str[MAX_MAC_STRING_LEN] = {0};

        if(radio->bss_list[i]) {
            platform_log(MAP_LIBRARY,LOG_INFO,"   BSS[%d]\n", i);
            platform_log(MAP_LIBRARY,LOG_INFO,"   |\n");

            get_mac_as_str(radio->bss_list[i]->bssid, bssid_str, MAX_MAC_STRING_LEN);
            platform_log(MAP_LIBRARY,LOG_INFO,"    -BSSID         : %s\n", bssid_str);
            platform_log(MAP_LIBRARY,LOG_INFO,"    -SSID          : %s\n", radio->bss_list[i]->ssid);
            if( (radio->bss_list[i]->type & MAP_BACKHAUL_BSS) && (radio->bss_list[i]->type & MAP_FRONTHAUL_BSS)) {
                platform_log(MAP_LIBRARY,LOG_INFO,"    -BSS TYPE      : FRONTHAUL (and/or) BACKHAUL\n");
            }
            else if (radio->bss_list[i]->type & MAP_FRONTHAUL_BSS) {
                platform_log(MAP_LIBRARY,LOG_INFO,"    -BSS TYPE      : FRONTHAUL\n");
            }
            else if (radio->bss_list[i]->type & MAP_BACKHAUL_BSS) {
                platform_log(MAP_LIBRARY,LOG_INFO,"    -BSS TYPE      : BACKHAUL\n");
            }
            else {
                platform_log(MAP_LIBRARY,LOG_INFO,"    -BSS TYPE      : UNCONFIGURED\n");
            }
            print_ap_metrics(radio->bss_list[i]);
            print_sta_info(radio->bss_list[i]->sta_list);
        }
    }
}

void print_opclass_in_radio(map_radio_info_t *radio)
{
        platform_log(MAP_LIBRARY,LOG_DEBUG, "  OP CLASS LIST:\n");
        platform_log(MAP_LIBRARY,LOG_DEBUG, "  |\n");

    for (uint8_t i = 0; i < radio->op_class_count ; ++i)
    {
        platform_log(MAP_LIBRARY,LOG_DEBUG, "  -[%d]\n", i);
        platform_log(MAP_LIBRARY,LOG_DEBUG, "      |\n");
        platform_log(MAP_LIBRARY,LOG_DEBUG, "       -OP Class                  : %d\n",radio->op_class_list[i].op_class);
        platform_log(MAP_LIBRARY,LOG_DEBUG, "       -EIRP                      : %d\n",radio->op_class_list[i].eirp);

        #define CHANNEL_LIST_STR_LEN 128  // MAX_CHANNEL_IN_OPERATING_CLASS * 5 bytes == 100
        char channel_list[CHANNEL_LIST_STR_LEN];
        int count = 0;

        if(radio->op_class_list[i].agent_channel_count){
            for(uint8_t j = 0; j < radio->op_class_list[i].agent_channel_count; j++)
                count += snprintf(channel_list + count, CHANNEL_LIST_STR_LEN - count , " %d,", radio->op_class_list[i].agent_channel[j]);
                platform_log(MAP_LIBRARY,LOG_DEBUG, "       -Agent Channel Pref       : %s", channel_list);
                count = 0;
        }

        if(radio->op_class_list[i].static_non_operable_count){
            for(uint8_t j = 0; j < radio->op_class_list[i].static_non_operable_count; j++)
                count += snprintf(channel_list + count, CHANNEL_LIST_STR_LEN - count , " %d,", radio->op_class_list[i].static_non_operable_channel[j]);
                platform_log(MAP_LIBRARY,LOG_DEBUG, "       -Static Non OP channels    : %s", channel_list);
                count = 0;
        }

        if(radio->op_class_list[i].dynamic_non_operable_count){
            for(uint8_t j = 0; j < radio->op_class_list[i].dynamic_non_operable_count; j++)
                count += snprintf(channel_list + count, CHANNEL_LIST_STR_LEN - count , " %d,", radio->op_class_list[i].dynamic_non_operable_channel[j].channel_num);
                platform_log(MAP_LIBRARY,LOG_DEBUG, "       -Dynamic Non OP channels   : %s", channel_list);
                count = 0;
        }

        if(radio->op_class_list[i].cntlr_channel_count){
            for(uint8_t j = 0; j < radio->op_class_list[i].cntlr_channel_count; j++)
                count += snprintf(channel_list + count, CHANNEL_LIST_STR_LEN - count , " %d,", radio->op_class_list[i].cntrl_channel[j]);
                platform_log(MAP_LIBRARY,LOG_DEBUG, "       -Ctrler Channel Pref       : %s", channel_list);
                count = 0;
        }
    }
}

void map_print_ht_caps(map_radio_ht_capabilty_t* ht_caps) {
    platform_log(MAP_LIBRARY,LOG_DEBUG, "   -HT Caps\n");
    platform_log(MAP_LIBRARY,LOG_DEBUG, "    |\n");
    platform_log(MAP_LIBRARY,LOG_DEBUG, "     -max_supported_tx_streams : %d\n", ht_caps->max_supported_tx_streams);
    platform_log(MAP_LIBRARY,LOG_DEBUG, "     -max_supported_rx_streams : %d\n", ht_caps->max_supported_rx_streams);
    platform_log(MAP_LIBRARY,LOG_DEBUG, "     -gi_support_20mhz         : %d\n", ht_caps->gi_support_20mhz);
    platform_log(MAP_LIBRARY,LOG_DEBUG, "     -gi_support_40mhz         : %d\n", ht_caps->gi_support_40mhz);
    platform_log(MAP_LIBRARY,LOG_DEBUG, "     -ht_support_40mhz         : %d\n", ht_caps->ht_support_40mhz);
}

void map_print_vht_caps(map_radio_vht_capabilty_t* vht_caps){
    platform_log(MAP_LIBRARY,LOG_DEBUG, "   -VHT Caps\n");
    platform_log(MAP_LIBRARY,LOG_DEBUG, "    |\n");
    platform_log(MAP_LIBRARY,LOG_DEBUG, "     -supported_tx_mcs          : %d\n", vht_caps->supported_tx_mcs);
    platform_log(MAP_LIBRARY,LOG_DEBUG, "     -supported_rx_mcs          : %d\n", vht_caps->supported_rx_mcs);
    platform_log(MAP_LIBRARY,LOG_DEBUG, "     -max_supported_tx_streams  : %d\n", vht_caps->max_supported_tx_streams);
    platform_log(MAP_LIBRARY,LOG_DEBUG, "     -max_supported_rx_streams  : %d\n", vht_caps->max_supported_rx_streams);
    platform_log(MAP_LIBRARY,LOG_DEBUG, "     -gi_support_80mhz          : %d\n", vht_caps->gi_support_80mhz);
    platform_log(MAP_LIBRARY,LOG_DEBUG, "     -gi_support_160mhz         : %d\n", vht_caps->gi_support_160mhz);
    platform_log(MAP_LIBRARY,LOG_DEBUG, "     -support_80_80_mhz         : %d\n", vht_caps->support_80_80_mhz);
    platform_log(MAP_LIBRARY,LOG_DEBUG, "     -support_160mhz            : %d\n", vht_caps->support_160mhz);
    platform_log(MAP_LIBRARY,LOG_DEBUG, "     -su_beamformer_capable     : %d\n", vht_caps->su_beamformer_capable);
    platform_log(MAP_LIBRARY,LOG_DEBUG, "     -mu_beamformer_capable     : %d\n", vht_caps->mu_beamformer_capable);
}

void map_print_he_caps(map_radio_he_capabilty_t* he_caps){
    platform_log(MAP_LIBRARY,LOG_DEBUG, "   -HE Caps\n");
    platform_log(MAP_LIBRARY,LOG_DEBUG, "    |\n");
    platform_log(MAP_LIBRARY,LOG_DEBUG, "     -supported_mcs_length      : %d\n", he_caps->supported_mcs_length);
    //TODO: Print supported mcs from 802.11ax spec
    platform_log(MAP_LIBRARY,LOG_DEBUG, "     -max_supported_tx_streams  : %d\n", he_caps->max_supported_tx_streams);
    platform_log(MAP_LIBRARY,LOG_DEBUG, "     -max_supported_rx_streams  : %d\n", he_caps->max_supported_rx_streams);
    platform_log(MAP_LIBRARY,LOG_DEBUG, "     -support_80_80_mhz         : %d\n", he_caps->support_80_80_mhz);
    platform_log(MAP_LIBRARY,LOG_DEBUG, "     -support_160mhz            : %d\n", he_caps->support_160mhz);
    platform_log(MAP_LIBRARY,LOG_DEBUG, "     -su_beamformer_capable     : %d\n", he_caps->su_beamformer_capable);
    platform_log(MAP_LIBRARY,LOG_DEBUG, "     -mu_beamformer_capable     : %d\n", he_caps->mu_beamformer_capable);
    platform_log(MAP_LIBRARY,LOG_DEBUG, "     -ul_mimo_capable           : %d\n", he_caps->ul_mimo_capable);
    platform_log(MAP_LIBRARY,LOG_DEBUG, "     -ul_mimo_ofdma_capable     : %d\n", he_caps->ul_mimo_ofdma_capable);
    platform_log(MAP_LIBRARY,LOG_DEBUG, "     -dl_mimo_ofdma_capable     : %d\n", he_caps->dl_mimo_ofdma_capable);
    platform_log(MAP_LIBRARY,LOG_DEBUG, "     -ul_ofdma_capable          : %d\n", he_caps->ul_ofdma_capable);
    platform_log(MAP_LIBRARY,LOG_DEBUG, "     -dl_ofdma_capable          : %d\n", he_caps->dl_ofdma_capable);

}

void map_print_radio_caps(map_radio_info_t* radio) {
    int8_t radio_mac_str[MAX_MAC_STRING_LEN] = {0};
    get_mac_as_str(radio->radio_id, radio_mac_str, MAX_MAC_STRING_LEN);

    if(radio->ale == NULL)
        return;

    platform_log(MAP_LIBRARY,LOG_DEBUG, "  Radio Caps  :\n");
    platform_log(MAP_LIBRARY,LOG_DEBUG, "  |\n");
    platform_log(MAP_LIBRARY,LOG_DEBUG, "   -Radio ID                   : %s\n", radio_mac_str);
    platform_log(MAP_LIBRARY,LOG_DEBUG, "   -IB UnAssocStaLinkMetricSupp: %d\n", radio->ale->agent_capability.ib_unassociated_sta_link_metrics_supported);
    platform_log(MAP_LIBRARY,LOG_DEBUG, "   -OB UnAssocStaLinkMetricSupp: %d\n", radio->ale->agent_capability.oob_unassociated_sta_link_metrics_supported);
    platform_log(MAP_LIBRARY,LOG_DEBUG, "   -Agent Initiated Steering   : %d\n", radio->ale->agent_capability.rssi_agent_steering_supported);

    if(radio->ht_caps)
        map_print_ht_caps(radio->ht_caps);

    if(radio->vht_caps)
        map_print_vht_caps(radio->vht_caps);

    if(radio->he_caps)
        map_print_he_caps(radio->he_caps);
}

void print_radios_in_agent(map_ale_info_t *ale) {
    if(ale) {
        for (uint8_t i = 0; i < ale->num_radios; ++i)
        {
            if (ale->radio_list[i] != NULL) {
                int8_t radio_id_str[MAX_MAC_STRING_LEN] = {0};
                get_mac_as_str(ale->radio_list[i]->radio_id, radio_id_str, MAX_MAC_STRING_LEN);

                platform_log(MAP_LIBRARY,LOG_INFO,"Radio[%d]\n", i);
                platform_log(MAP_LIBRARY,LOG_INFO," |\n");
                platform_log(MAP_LIBRARY,LOG_INFO," Radio MAC      : %s ", radio_id_str);

                if(ale->radio_list[i]->supported_freq == IEEE80211_FREQUENCY_BAND_2_4_GHZ)
                    platform_log(MAP_LIBRARY,LOG_INFO," Radio Type     : 2.4GHz\n");
                else if(ale->radio_list[i]->supported_freq == IEEE80211_FREQUENCY_BAND_5_GHZ)
                    platform_log(MAP_LIBRARY,LOG_INFO," Radio Type     : 5GHz\n");
                else
                    platform_log(MAP_LIBRARY,LOG_INFO," Radio Type     : Unknown\n");

                if(is_radio_configured(ale->radio_list[i]->state)) {
                    platform_log(MAP_LIBRARY,LOG_INFO," Radio State    : CONFIGURED\n");
                }
                else {
                    platform_log(MAP_LIBRARY,LOG_INFO," Radio State    : UNCONFIGURED\n");
                }
                if(ale->radio_list[i]->iface_name[0] != '\0')
                    platform_log(MAP_LIBRARY,LOG_INFO," Radio Iface    : %s\n",ale->radio_list[i]->iface_name);
                    platform_log(MAP_LIBRARY,LOG_INFO," Radio OP Class : %d\n",ale->radio_list[i]->current_op_class);
                    platform_log(MAP_LIBRARY,LOG_INFO," Radio OP Chan  : %d\n",ale->radio_list[i]->current_op_channel);
                    platform_log(MAP_LIBRARY,LOG_INFO," Radio BW       : %d\n",ale->radio_list[i]->current_bw);
                    platform_log(MAP_LIBRARY,LOG_INFO," Radio Tx Pwr   : %d\n",ale->radio_list[i]->current_tx_pwr);

                if(ale->radio_list[i]->op_class_count > 0) {
                    platform_log(MAP_LIBRARY,LOG_DEBUG," Channel Pref   :%d\n",ale->radio_list[i]->op_class_count);
                    platform_log(MAP_LIBRARY,LOG_DEBUG," OP Class Count :%d\n",ale->radio_list[i]->op_class_count);
                    print_opclass_in_radio(ale->radio_list[i]);
                }
                map_print_radio_caps(ale->radio_list[i]);
                // print the BSS
                print_bss_in_radio(ale->radio_list[i]);
                platform_log(MAP_LIBRARY,LOG_INFO,"----------------------------------------------\n");
            }
        }
    }
}

void print_agent_info(map_ale_info_t *ale) {
    if(ale) {
        int8_t mac_str[MAX_MAC_STRING_LEN] = {0};
        platform_log(MAP_LIBRARY,LOG_INFO,"***********************************************\n");

        get_mac_as_str(ale->al_mac, mac_str, MAX_MAC_STRING_LEN);
        platform_log(MAP_LIBRARY,LOG_INFO," Al ENTITY MAC          : %s \n", mac_str);

        get_mac_as_str(ale->upstream_local_iface_mac, mac_str, MAX_MAC_STRING_LEN);
        platform_log(MAP_LIBRARY,LOG_INFO," ALE UPSTREAM LOCAL MAC : %s\n", mac_str);

        platform_log(MAP_LIBRARY,LOG_INFO," ALE UPSTREAM INTERFACE Type : %d\n", ale->upstream_iface_type);

        get_mac_as_str(ale->upstream_remote_iface_mac, mac_str, MAX_MAC_STRING_LEN);
        platform_log(MAP_LIBRARY,LOG_INFO," ALE UPSTREAM REMOTE MAC: %s\n", mac_str);

        get_mac_as_str(ale->iface_mac, mac_str, MAX_MAC_STRING_LEN);
        platform_log(MAP_LIBRARY,LOG_INFO," RECEIVING INTERFACE    : %s\n", ale->iface_name);
        platform_log(MAP_LIBRARY,LOG_INFO," KEEP ALIVE TIME        : %lu\n", ale->keep_alive_time.tv_sec);
        platform_log(MAP_LIBRARY,LOG_INFO," MANUFACTURER NAME      : %s\n", ale->manufacturer_name);
        platform_log(MAP_LIBRARY,LOG_INFO," NUM OF RADIOS          : %d\n", ale->num_radios);
        platform_log(MAP_LIBRARY,LOG_INFO,"***********************************************\n");
        // Print all the radio info
        print_radios_in_agent(ale);
        platform_log(MAP_LIBRARY,LOG_INFO,"----------------------------------------------\n");
    }
    else {
        platform_log(MAP_LIBRARY,LOG_INFO,"%s Unfortunate Event!!!\n", __func__);
    }

}

void print_agent_info_tree() {
    map_ale_info_t *ale = NULL;
    const char* key     = NULL;

    foreach_hash_node(key) {
        filter_ale(key, ale);
        print_agent_info(ale);
        platform_log(MAP_LIBRARY,LOG_INFO,"\n\n\n");
    }

    platform_log(MAP_LIBRARY,LOG_INFO,"\n\n\n");

    // Print the STA and BSS mapping
    print_sta_bss_mapping();

    platform_log(MAP_LIBRARY,LOG_INFO,"\n\n\n");

    //Dump the Agent's topology tree
    dump_topology_tree();

}

void print_arraylist_object_mac(array_list_t * list)
{
    list_iterator_t* it = new_list_iterator(list);

    while(it->iter != NULL)
    {
        uint8_t* sta_mac = (uint8_t*) get_next_list_object(it);
        if(sta_mac)
        {
            platform_log(MAP_LIBRARY,LOG_INFO, "[MAP] MAC = %x:%x:%x:%x:%x:%x \n", 
                sta_mac[0], sta_mac[1], 
                sta_mac[2], sta_mac[3], 
                sta_mac[4], sta_mac[5]);
        }
    }
    free_list_iterator(it);
}

void dump_hash_keys() {
    const char* key     = NULL;
    foreach_hash_node(key) {
        platform_log(MAP_LIBRARY,LOG_ERR, " HASH KEY: %s ", key);
    }
}


