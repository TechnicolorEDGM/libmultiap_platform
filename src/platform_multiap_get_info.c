/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

#include <stdio.h>
#include <string.h>
#include "platform_multiap_get_info.h"

int get_index(uint8_t op_class);

#define ARRAY_SIZE(array,type) (sizeof(array)/sizeof(type))
#define CLASS_TABLE_LEN ARRAY_SIZE(g_wifi_class_tbl, wifi_op_class_table)

wifi_op_class_table g_wifi_class_tbl[] = {
    {81, { { 1,2,3,4,5,6,7,8,9,10,11,12,13}, 13}, 1, 20, {{"US",36},{"EU",20},{"AU",36}}, 3},
    {82, { { 14}, 1}, 1, 20, {{"\0",0}}, 0 },
    {83, { { 1,2,3,4,5,6,7,8,9}, 9}, 1, 40, {{"US",36},{"EU",20},{"AU",36}}, 3},
    {84, { { 5,6,7,8,9,10,11,12,13}, 9}, 1, 40, {{"US",36},{"EU",20},{"AU",36}}, 3},
    {115, { { 36,40,44,48}, 4}, 2, 20, {{"US",36},{"EU",23},{"AU",23}}, 3},
    {118, { { 52,56,60,64}, 4}, 2, 20, {{"US",30},{"EU",23},{"AU",23}}, 3},
    {121, { { 100,104,108,112,116,120,124,128,132,136,140}, 11}, 2, 20,{{"US",30},{"EU",30},{"AU",30}}, 3},
    {124, { { 149,153,157,161}, 4}, 2, 20, {{"US",36},{"AU",36}}, 2},
    {125, { { 149,153,157,161,165,169}, 6}, 2, 20, {{"US",36},{"AU",36}}, 2},
    {116, { { 36, 44}, 2}, 2, 40, {{"US",36},{"EU",23},{"AU",23}}, 3},
    {117, { { 40, 48}, 2}, 2, 40, {{"US",36},{"EU",23},{"AU",23}}, 3},
    {119, { { 52, 60}, 2}, 2, 40, {{"US",30},{"EU",23},{"AU",23}}, 3},
    {120, { { 56, 64}, 2}, 2, 40, {{"US",30},{"EU",23},{"AU",23}}, 3},
    {122, { { 100, 108, 116, 124, 132}, 5}, 2, 40,{{"US",30},{"EU",30},{"AU",30}}, 3},
    {123, { { 104, 112, 120, 128, 136}, 5}, 2, 40,{{"US",30},{"EU",30},{"AU",30}}, 3},
    {126, { { 149, 157}, 2}, 2, 40, {{"US",36},{"AU",36}}, 2},
    {127, { { 153, 161}, 2}, 2, 40, {{"US",36},{"AU",36}}, 2},
    {128, { { 36,40,44,48, 52,56,60,64, 100,104,108,112, 116,120,124,128, 132,136,140,144, 149,153,157,161}, 24}, 2, 80, {{"US",30},{"EU",23},{"AU",36}}, 3},
    {129, { { 36,40,44,48,52,56,60,64, 100,104,108,112,116,120,124,128,}, 16}, 2, 160, {{"US",30},{"EU",23}}, 2}
};

void dump_channel_set(int i) {
    wifi_channel_set * s = &(g_wifi_class_tbl[i].set);
    int j = 0;
    for(j = 0; j < s->length; j++) {
        printf("%d, ", s->ch[j]);
    }
}

void dump_table() {
    int i;
    for(i = 0; i < CLASS_TABLE_LEN; i++) {
        printf("%d \t", g_wifi_class_tbl[i].op_class);
        dump_channel_set(i);
        printf("\t%d", g_wifi_class_tbl[i].bw);
        printf("\t%d", g_wifi_class_tbl[i].ch_freq);
        printf("\n");
    }
}

int8_t get_frequency_type(uint8_t op_class, uint8_t *freq_type, uint16_t *band_type_5G) {
    if(NULL == freq_type || NULL == band_type_5G)
        return -1;

    int index = get_index(op_class);
    if(index != -1) {

        if(g_wifi_class_tbl[index].ch_freq == 1){
            *freq_type = IEEE80211_FREQUENCY_BAND_2_4_GHZ;
        }
        else if(g_wifi_class_tbl[index].ch_freq == 2){
            *freq_type = IEEE80211_FREQUENCY_BAND_5_GHZ;

            if(op_class >= 115 && op_class <= 119)
                *band_type_5G = MAP_M2_BSS_RADIO5GL;
            else
                *band_type_5G = MAP_M2_BSS_RADIO5GU;
        }
        else{
            return -1;
        }
    }
    else {
        return -1;
    }

    return 0;
}

int is_matching_bw_country(wifi_op_class_table* entry, uint8_t bw, char *country) {

    if((bw != 0) && (entry->bw != bw))
        return 0;

    for (uint8_t i=0; i<entry->eirp_count; i++) {
        if (strncmp((char*)(entry->eirp[i].country), country, MAX_COUNTRY_STR_LEN) == 0)  return 1;
    } 
    return 0;
}

int is_matching_channel(wifi_op_class_table* entry, wifi_channel_set* set) {
    int i = 0, j = 0;
    for(i = 0; i < set->length; i++) {
        for(j = 0; j < entry->set.length; j++) {
            if(set->ch[i] == entry->set.ch[j]) {
                return 1;
            }
        }
    }
    return 0;
}

int is_matching_country (wifi_op_class_table * op_entry, char *country, uint8_t *eirp)
{
    int i = 0;
    for (i = 0; i<op_entry->eirp_count; i++) {
        if (strncmp((char*)(op_entry->eirp[i].country), country, MAX_COUNTRY_STR_LEN) == 0) {
            *eirp = op_entry->eirp[i].eirp;
            return 1;
        }
            
    }
    return 0;
}

uint8_t get_eirp (uint8_t op_class, char* country) {

    int i = 0;
    uint8_t eirp = 0;
    for (i=0; i < CLASS_TABLE_LEN; i++) {
        if(g_wifi_class_tbl[i].op_class == op_class) {
            if (is_matching_country (&g_wifi_class_tbl[i], country, &eirp)) {
                return eirp;
            }
        }
    }
    return -1;
}


void get_operating_class(wifi_channel_set * set, uint8_t bw, char *country, wifi_op_class_array * op_class)
{
    int i;
    uint8_t freq = 0;

    if(set->ch[0] <= 14)
        freq = IEEE80211_FREQUENCY_BAND_2_4_GHZ+1;
    else
        freq = IEEE80211_FREQUENCY_BAND_5_GHZ+1;

    for(i = 0; i < CLASS_TABLE_LEN; i++) {

        if((g_wifi_class_tbl[i].ch_freq == freq) &&  (is_matching_bw_country(&(g_wifi_class_tbl[i]), bw, country)) &&
           (is_matching_channel(&(g_wifi_class_tbl[i]), set))) {
            op_class->array[op_class->length] = g_wifi_class_tbl[i].op_class;
            op_class->length++;
        }
    
    }
}

int get_index(uint8_t op_class) {
    int i = 0;
    for(i = 0; i < CLASS_TABLE_LEN; i++) {
        if(g_wifi_class_tbl[i].op_class == op_class)
            return i;
    }
    return -1;
}

int get_channel_index(uint8_t channel,int op_class_index) {
    int i = 0;
    for(i = 0; i < g_wifi_class_tbl[op_class_index].set.length; i++) {
        if(g_wifi_class_tbl[op_class_index].set.ch[i] == channel)
            return i;
    }
    return -1;
}

uint8_t get_mid_freq(uint8_t channel, uint8_t opclass, uint8_t bw)
{
    if((bw != 80) && (bw != 160))
        return channel;

    int opclass_index = get_index(opclass);
    int channel_index = get_channel_index(channel, opclass_index);

    if(channel_index != -1 && opclass_index != -1)
    {
        if(bw == 80)
        {
            int set_no = channel_index/4;
            int position = set_no * 4;
            uint8_t primary_channel = g_wifi_class_tbl[opclass_index].set.ch[position];
            return (primary_channel+6);
        }
        else if(bw == 160)
        {
            int set_no = channel_index/8;
            int position = set_no * 8;
            uint8_t primary_channel = g_wifi_class_tbl[opclass_index].set.ch[position];
            return (primary_channel+14);           
        }
    }
    return 0;    
}

void get_non_operating_ch(uint8_t op_class, wifi_channel_set * non_op_ch, wifi_channel_set * set ) {
    int tbl_index = get_index(op_class);
    if( tbl_index != -1) {
        int i = 0, j = 0;
        uint8_t bw = 0, mid_freq = 0, new_freq = 0;
        get_bw_from_operating_class(op_class, &bw);
        for(i = 0; i < g_wifi_class_tbl[tbl_index].set.length;  i++) {
            int bfound = 0;
            for(j = 0; j < set->length; j++) {
                if(set->ch[j] == g_wifi_class_tbl[tbl_index].set.ch[i]) {
                    bfound = 1;
                    break;
                }
            }
            if(bfound == 0) {
                if(mid_freq == (new_freq = get_mid_freq(g_wifi_class_tbl[tbl_index].set.ch[i], op_class, bw)))
                    continue;

                non_op_ch->ch[non_op_ch->length] = mid_freq = new_freq;
                non_op_ch->length++;
            }
        }
    }
}

int is_matching_channel_in_opclass(uint8_t op_class, uint8_t channel) {
    int i = 0, opclass_index = 0;
    uint8_t bw = 0;
    opclass_index = get_index(op_class);
    get_bw_from_operating_class(op_class, &bw);
    if((bw == 80) || (bw == 160)) 
        get_primary_channel_for_midfreq(&channel, bw);

    for(i = 0; i < g_wifi_class_tbl[opclass_index].set.length; i++) {
        if(g_wifi_class_tbl[opclass_index].set.ch[i] == channel) {
            return 1;
        }
    }
    return 0;
}

void dump_ch_set_array(wifi_channel_set * s) {
    int i = 0;
    printf("the ch set: ");
    for(i = 0; i < s->length; i++) {
        printf("%d, ", s->ch[i]);
    }
    printf("\n");
}
    
void dump_op_class_array(wifi_op_class_array * op_class) {
    int i = 0;
    printf("the operating class: ");
    for(i = 0; i < op_class->length; i++) {
        printf("%d, ", op_class->array[i]);
    }
    printf("\n");
}

int get_operating_class_basic(uint8_t channel)
{
    /* rclass: Assumption is 11h not used, use global operating classes */
    /* See 802.11 2012 Annex E, Table E.1 */

    if (channel < 14) {
        return 81;
    } else if (channel == 14) {
        return 82;
    } else if (channel < 52) {
        return 115;
    } else if (channel < 100) {
        return 118;
    } else if (channel < 149) {
        return 121;
    } else if (channel < 161) {
        return 124;
    } else {
        return 125;
    }
}

int get_bw_from_operating_class(uint8_t op_class, uint8_t *bw)
{
    for (int i = 0; i < CLASS_TABLE_LEN; i++) {
        if (g_wifi_class_tbl[i].op_class == op_class) {
             *bw = g_wifi_class_tbl[i].bw;
             return 0;
        }
    }
    return -EINVAL;
}

void get_primary_channel_for_midfreq(uint8_t *channel, uint8_t bw)
{
    if(bw == 80)
        *channel = (*channel)-6;

    else if(bw == 160)
        *channel = (*channel)-14;
    return;
}

int get_channel_set_for_rclass(uint8_t rclass, wifi_channel_set *ch_set) {
    for (int i = 0; i < CLASS_TABLE_LEN; i++) {
	    if (g_wifi_class_tbl[i].op_class == rclass) {
		    memcpy(ch_set->ch, g_wifi_class_tbl[i].set.ch, g_wifi_class_tbl[i].set.length);
			ch_set->length = g_wifi_class_tbl[i].set.length;
			return 0;
		}
	}
	return -EINVAL;
}
