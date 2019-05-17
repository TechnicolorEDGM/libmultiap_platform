/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

#include "platform_map.h"
#include "1905_platform.h"
#include "platform_multiap_get_info.h"
#include "mon_platform.h"
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <uci.h>

int g_context; // Value can be either MAP_AGENT OR MAP_CONTROLLER. It should be set in agent/controller initialisation process.

static int prepare_json_parse(lua_State *L,char* *json_str);
static int complete_parse_json(lua_State *L,char** json_str);

static int prepare_json_parse(lua_State *L,char* *json_str)
{
	const char* plua_str=NULL;
	size_t len;

	if(lua_type(L,-1) == LUA_TSTRING)
	{
		plua_str=lua_tostring(L,-1);
		len=strlen(plua_str);
		//Make a copy sothat lua dosenot garbage collect -- need optimisation
		*json_str=(char*) malloc((len*sizeof(uint8_t))+1);
		memset((void*)*json_str,0x00,((len*sizeof(uint8_t))+1));
		strncpy(*json_str,plua_str,len);
		//platform_log(MAP_LIBRARY,LOG_DEBUG,"config json string is:%s",*json_str);
		return 0;
	}
	return -1;
}
static int complete_parse_json(lua_State *L,char** json_str)
{
	free(*json_str);
	/* Doing it at one place in platform_lua - for both set and get */
	//lua_close(L);
	return 0;
}

#ifndef USE_C_API

static void get_iface_security_mode(const char *supported_security_modes , uint16_t *auth_mode,
                                    uint16_t *encryption_mode) {
    // Validate the input arguments
    if(supported_security_modes == NULL || auth_mode == NULL || encryption_mode == NULL)
        return;

    uint8_t len = strnlen(supported_security_modes, MAX_SECURITY_MODE_STR_LEN);
    if(len == 0 ||  // NULL string
       len == MAX_SECURITY_MODE_STR_LEN) // Null terminated check
        return;

    char security_modes[MAX_SECURITY_MODE_STR_LEN] = {0};
    char *auth_mode_str = NULL;
    char *delimiter     = ",";
    char *rest          = NULL;

    // strtok will change the original string.
    // Clone the string to local array
    strcpy(security_modes, supported_security_modes);
    security_modes[len] = '\0';
    *auth_mode          = 0;
    *encryption_mode    = 0;

    auth_mode_str = strtok_r(security_modes, delimiter, &rest);

    while (NULL != auth_mode_str)
    {
        if (strcmp(auth_mode_str,"wep") == 0)
           *auth_mode |= IEEE80211_AUTH_MODE_WEP;
        if (strcmp(auth_mode_str,"wpa-wpa2") == 0)
           *auth_mode |= IEEE80211_AUTH_MODE_WPA | IEEE80211_AUTH_MODE_WPA2;
        if (strcmp(auth_mode_str,"wpa-wpa2-psk") == 0)
           *auth_mode |= IEEE80211_AUTH_MODE_WPA | IEEE80211_AUTH_MODE_WPA2PSK;
        if (strcmp(auth_mode_str,"wpa2-psk") == 0)
           *auth_mode |= IEEE80211_AUTH_MODE_WPA2PSK;
        if (strcmp(auth_mode_str,"wpa2") == 0)
           *auth_mode |= IEEE80211_AUTH_MODE_WPA2;
        if (strcmp(auth_mode_str,"wpa-psk") == 0)
           *auth_mode |= IEEE80211_AUTH_MODE_WPAPSK;
        if (strcmp(auth_mode_str,"wpa") == 0)
           *auth_mode |= IEEE80211_AUTH_MODE_WPA;
        if (strcmp(auth_mode_str,"none") == 0)
           *auth_mode |= IEEE80211_AUTH_MODE_OPEN;
        auth_mode_str = strtok_r(NULL, delimiter, &rest);
    }

    if(*auth_mode & IEEE80211_AUTH_MODE_OPEN)
        *encryption_mode |= IEEE80211_ENCRYPTION_MODE_NONE;

    if(*auth_mode & IEEE80211_AUTH_MODE_WEP)
        *encryption_mode |= IEEE80211_ENCRYPTION_MODE_TKIP;
    // Other than WEP, OPEN if any other flags are enabled then enable AES
    if(*auth_mode & ~( IEEE80211_AUTH_MODE_WEP & IEEE80211_AUTH_MODE_OPEN) )
        *encryption_mode |= IEEE80211_ENCRYPTION_MODE_AES;
}

static void get_frequency_bands(const char* frequency_bands, uint16_t* bss_freq_bands)
{
    if(frequency_bands == NULL || bss_freq_bands == NULL) {
        platform_log(MAP_LIBRARY,LOG_ERR, "%s [%d] Both are NULL\n",__FUNCTION__, __LINE__);
        return;
    }

    uint8_t len = strnlen(frequency_bands, MAX_FREQUENCY_BANDS_STR_LEN);
    if(len == 0 ||  // NULL string
        len == MAX_FREQUENCY_BANDS_STR_LEN) {  // Null terminated check
            platform_log(MAP_LIBRARY,LOG_DEBUG, "%s [%d] NULL Terminated\n",__FUNCTION__, __LINE__);
            return;
    }

    char freq_bands[MAX_FREQUENCY_BANDS_STR_LEN] = {0};
    char *freq_bands_str = NULL;
    char *delimiter     = ",";
    char *rest          = NULL;

    // strtok will change the original string.
    // Clone the string to local array
    strcpy(freq_bands, frequency_bands);
    freq_bands[len] = '\0';
    *bss_freq_bands          = 0;

    freq_bands_str = strtok_r(freq_bands, delimiter, &rest);

    while (NULL != freq_bands_str)
    {
        if (strcmp(freq_bands_str,"radio_2G") == 0)
           *bss_freq_bands |= MAP_M2_BSS_RADIO2G;
        else if (strcmp(freq_bands_str,"radio_5Gu") == 0)
           *bss_freq_bands |= MAP_M2_BSS_RADIO5GU;
        else if (strcmp(freq_bands_str,"radio_5Gl") == 0)
           *bss_freq_bands |= MAP_M2_BSS_RADIO5GL;
        freq_bands_str = strtok_r(NULL, delimiter, &rest);
    }
}

static void get_FHBH_bit(const char* FH_bit, const char* BH_bit, uint8_t* bss_state)
{
    if(FH_bit == NULL || BH_bit == NULL || bss_state == NULL)
        return;

    if (strcmp(FH_bit,"1") == 0)
       *bss_state |= MAP_FRONTHAUL_BSS;
    if (strcmp(BH_bit,"1") == 0)
       *bss_state |= MAP_BACKHAUL_BSS;
}

static void set_preferred_backhaul(const char *iface_type, map_cfg *config) {

    if(iface_type) {
        if(strcmp(iface_type, "Auto") == 0 ){
            config->preferred_bh_iface = MAP_BH_PREFERENCE_AUTO;
        }
        else if(strcmp(iface_type, "radio_2G") == 0 ){
            config->preferred_bh_iface = MAP_BH_PREFERENCE_2_4GHz;
        }
        else if(strcmp(iface_type, "radio_5G") == 0 ){
            config->preferred_bh_iface = MAP_BH_PREFERENCE_5GHz;
        }
        else if(strcmp(iface_type, "Ethernet") == 0) {
            config->preferred_bh_iface = MAP_BH_PREFERENCE_ETHER;
        }
        else {
            config->preferred_bh_iface = MAP_BH_PREFERENCE_AUTO;
        }
    }
}

int load_agent_config(void* config) {
    g_context = MULTIAP_AGENT;
    return 0;
}

int load_credential_config(void* config) {
       platform_log(MAP_LIBRARY,LOG_DEBUG, "%s [%d] Called\n",__FUNCTION__, __LINE__);
       map_cfg* ctrl_config = &((plfrm_config*)config)->map_config;
       struct uci_package *multiap = NULL;
       struct uci_context *uci_ctx = uci_alloc_context ();
       int count = 0;

       if (uci_ctx) {
               if (!uci_load(uci_ctx, "multiap", &multiap)) {
                       struct uci_element *e;
                       uci_foreach_element(&multiap->sections, e) {
                               struct uci_section *s = uci_to_section(e);
                               if (0 == strcmp(s->type, "controller_credentials")) {
                                       const char* state = uci_lookup_option_string(uci_ctx, s, "state");
                                       if (0 == strcmp(state, "1")) {
                                               const char* bss_ssid = uci_lookup_option_string(uci_ctx, s, "ssid");
                                               if(bss_ssid == NULL)
                                                   strncpy(ctrl_config->credential_config[count].bss_ssid, "", MAX_WIFI_SSID_LEN);
                                               else
                                                   strncpy(ctrl_config->credential_config[count].bss_ssid, bss_ssid, MAX_WIFI_SSID_LEN);
                                               ctrl_config->credential_config[count].bss_ssid[MAX_WIFI_SSID_LEN - 1] = '\0';
                                               const char* wpa_key = uci_lookup_option_string(uci_ctx, s, "wpa_psk_key");
                                               strncpy(ctrl_config->credential_config[count].wpa_key, wpa_key, MAX_WIFI_PASSWORD_LEN);
                                               ctrl_config->credential_config[count].wpa_key[MAX_WIFI_PASSWORD_LEN - 1] = '\0';
                                               const char* security_mode = uci_lookup_option_string(uci_ctx, s, "security_mode");
                                               // Update the supported authentication/encryption mode
                                               get_iface_security_mode(security_mode, &(ctrl_config->credential_config[count].supported_auth_modes), &(ctrl_config->credential_config[count].supported_encryption_types));
                                               const char* freq_bands = uci_lookup_option_string(uci_ctx, s, "frequency_bands");
                                               // Update the supported authentication/encryption mode
                                               get_frequency_bands(freq_bands, &(ctrl_config->credential_config[count].bss_freq_bands));
                                               const char* fronthaul_bit = uci_lookup_option_string(uci_ctx, s, "fronthaul");
                                               const char* backhaul_bit = uci_lookup_option_string(uci_ctx, s, "backhaul");
                                               // Update the supported authentication/encryption mode
                                               get_FHBH_bit(fronthaul_bit, backhaul_bit, &(ctrl_config->credential_config[count].bss_state));
                                               count ++;
                                       }
                               }
                       }
                       ctrl_config->map_num_credentials = count;
               }
       }
       else
       {
               platform_log(MAP_LIBRARY,LOG_ERR, "%s [%d] Failed to get uci context\n", __FUNCTION__, __LINE__);
               return -1;
       }
       uci_free_context(uci_ctx);
       return 0;
}

int load_controller_config(void* config) {
    uint8_t freq_2_4_g = atoi(map_controller_env_freq_2_4_ghz);
    uint8_t freq_5_g = atoi(map_controller_env_freq_5_ghz);
    uint8_t freq_60_g = atoi(map_controller_env_freq_60_ghz);
    const char* bh_pref     = map_controller_env_preferred_bh_iface;

    map_cfg* controller_config = &((plfrm_config*)config)->map_config;

    if(-1 == load_credential_config(config)) {
        platform_log(MAP_LIBRARY,LOG_ERR, "%s Failed loading Credential configuration. \n",__func__);
        return -1;
    }

    // Controller BH preference
    set_preferred_backhaul(bh_pref, controller_config);

    // Reset all the supported frequency config
    controller_config->supportedfreq[IEEE80211_FREQUENCY_BAND_2_4_GHZ] = 0xFF;
    controller_config->supportedfreq[IEEE80211_FREQUENCY_BAND_5_GHZ] = 0xFF;
    controller_config->supportedfreq[IEEE80211_FREQUENCY_BAND_60_GHZ] = 0xFF;

    // Set the supported frequency

    if(freq_2_4_g == 1 )
        controller_config->supportedfreq[IEEE80211_FREQUENCY_BAND_2_4_GHZ] = IEEE80211_FREQUENCY_BAND_2_4_GHZ;

    if(freq_5_g == 1 )
        controller_config->supportedfreq[IEEE80211_FREQUENCY_BAND_5_GHZ] = IEEE80211_FREQUENCY_BAND_5_GHZ;

    if(freq_60_g == 1 )
        controller_config->supportedfreq[IEEE80211_FREQUENCY_BAND_60_GHZ] = IEEE80211_FREQUENCY_BAND_60_GHZ;

    g_context = MULTIAP_CONTROLLER;

    platform_log(MAP_LIBRARY,LOG_DEBUG,"-------------------------------------------------------------\n");
    platform_log(MAP_LIBRARY,LOG_DEBUG,"|\t\t\t --MAP CONFIG-- \t\t\t\n");
    platform_log(MAP_LIBRARY,LOG_DEBUG,"-------------------------------------------------------------\n");
    platform_log(MAP_LIBRARY,LOG_DEBUG,"| \t Credential Configuration:\n");
    platform_log(MAP_LIBRARY,LOG_DEBUG,"| \t      MAP_NUM_CREDENTIALS       : %d \n", controller_config->map_num_credentials);

    for(uint8_t i = 0; i < controller_config->map_num_credentials; i++) {
        platform_log(MAP_LIBRARY,LOG_DEBUG,"|\t\t\t --credential %d-- \t\t\t\n", i);
        platform_log(MAP_LIBRARY,LOG_DEBUG,"-------------------------------------------------------------\n");
        platform_log(MAP_LIBRARY,LOG_DEBUG,"| \t      - SSID                : %s \n", controller_config->credential_config[i].bss_ssid);
        platform_log(MAP_LIBRARY,LOG_DEBUG,"| \t      - Password            : %s \n", controller_config->credential_config[i].wpa_key);
        platform_log(MAP_LIBRARY,LOG_DEBUG,"| \t      - Authentication mode : %04x \n", controller_config->credential_config[i].supported_auth_modes);
        platform_log(MAP_LIBRARY,LOG_DEBUG,"| \t      - Encryption type     : %04x \n", controller_config->credential_config[i].supported_encryption_types);
        platform_log(MAP_LIBRARY,LOG_DEBUG,"| \t      - Frequency Bands     : %04x \n", controller_config->credential_config[i].bss_freq_bands);
        platform_log(MAP_LIBRARY,LOG_DEBUG,"| \t      - BSS State           : %02x \n", controller_config->credential_config[i].bss_state);
        platform_log(MAP_LIBRARY,LOG_DEBUG,"-------------------------------------------------------------\n");
    }

    return 0;
}

int get_operating_role(void)
{
	return g_context;
}

int controller_load_policy_config(lua_State *L,void* config)
{
	char* config_json=NULL;
	int ret=0;
	json_t * node_obj,*root_obj;
	json_error_t error;
	map_policy_config_t *policy_config=(map_policy_config_t*)config;
	
	ret=prepare_json_parse(L,&config_json);
	if(ret)
		return ret;

	root_obj = json_loads(config_json, 0, &error);
	//platform_log(MAP_LIBRARY,LOG_DEBUG," JSON_DUMP: %s", json_dumps(root_obj, 0));

	node_obj =  json_object_get(root_obj, "metrics_report_interval");	 
	if(json_typeof(node_obj) == JSON_INTEGER)
    {
		policy_config->metrics_report_interval = json_integer_value(node_obj);
	}

	node_obj =  json_object_get(root_obj, "sta_metrics_rssi_threshold_dbm");	 
	if(json_typeof(node_obj) == JSON_INTEGER)
    {
		policy_config->sta_metrics_rssi_threshold_dbm = json_integer_value(node_obj);
	}

	node_obj =  json_object_get(root_obj, "sta_metrics_rssi_hysteresis_margin");	 
	if(json_typeof(node_obj) == JSON_INTEGER)
    {
		policy_config->sta_metrics_rssi_hysteresis_margin = json_integer_value(node_obj);
	}

	node_obj =  json_object_get(root_obj, "ap_metrics_channel_utilization_threshold_dbm");	 
	if(json_typeof(node_obj) == JSON_INTEGER)
    {
		policy_config->ap_metrics_channel_utilization_threshold_dbm = json_integer_value(node_obj);
	}

	node_obj =  json_object_get(root_obj, "sta_link_sta_traffic_stats");	 
	if(json_typeof(node_obj) == JSON_INTEGER)
    {
		policy_config->sta_link_sta_traffic_stats = json_integer_value(node_obj);
	}
	json_decref(root_obj);
	ret=complete_parse_json(L,&config_json);

	return ret;
	
}


int get_map_mac_address(lua_State *L,void *config)
{
        char* config_json=NULL;
        json_t *root_obj, *node_obj;
        json_error_t error;
        int ret=0;

        ret = prepare_json_parse(L,&config_json);
        if(ret)
                return ret;

       root_obj = json_loads(config_json, 0, &error);
       //platform_log(MAP_LIBRARY,LOG_DEBUG," JSON_DUMP: %s", json_dumps(root_obj, 0));

       if (g_context == MULTIAP_CONTROLLER)
               	node_obj =  json_object_get(root_obj,"Controller_mac");
       else if (g_context == MULTIAP_AGENT)
                node_obj =  json_object_get(root_obj,"Agent_mac");
       else 
                node_obj =  json_object_get(root_obj,"Al_mac");

       if(json_typeof(node_obj) == JSON_STRING)
               	strcpy((char *)config,json_string_value(node_obj));

       json_decref(root_obj);
       ret = complete_parse_json(L,&config_json);
       if(ret)
       		return ret;
 
       return 0;
}

int get_config(lua_State *L,void *config)
{
        char* config_json=NULL;
        int ret=0;

        ret = prepare_json_parse(L,&config_json);
        if(ret)
                return ret;

        strcpy((char *)config, config_json);

        ret = complete_parse_json(L,&config_json);
        if(ret)
                return ret;

        return 0;
}

int get_frequency_band(lua_State *L,void* config)
{
        char* config_json=NULL;
        int ret=0;
        uint8_t *freq_band = (uint8_t *) config;;

        ret = prepare_json_parse(L,&config_json);
        if(ret)
                return ret;

        if(config_json != NULL)
        {
            if (0 == strcmp(config_json, "radio_2G"))
                *freq_band = IEEE80211_FREQUENCY_BAND_2_4_GHZ;
            else if ((0 == strcmp(config_json, "radio_5G")) || (0 == strcmp(config_json, "radio2")))
                *freq_band = IEEE80211_FREQUENCY_BAND_5_GHZ;
            else
                platform_log(MAP_LIBRARY,LOG_ERR, "Invalid interface, unable to fetch band");
        }

        ret=complete_parse_json(L,&config_json);
        if(ret)
                return ret;

        return 0;
}

int get_bridge_conf(lua_State *L,void* config)
{
        char*   config_json   =   NULL;
        json_t* root_obj      =   NULL;
        json_t* obj_val       =   NULL;
        json_t* v             =   NULL;
        json_error_t error;
        int     br_tuples_num =   0;
        int     ret           =   -1;
        int     i             =   0;
        const char*   json_key =   NULL;
        int     no_of_null    =   1;
        struct bridge* br_temp =   NULL;

        ret = prepare_json_parse(L,&config_json);
        if(ret)
            return ret;

        root_obj = json_loads(config_json, 0, &error);

        br_tuples_num = json_array_size(root_obj);


        br_temp = (struct bridge*)calloc(br_tuples_num + no_of_null, sizeof(struct bridge));
        if(br_temp == NULL) {
            platform_log(MAP_LIBRARY,LOG_ERR,"%s :%d, No space available for br tuple alloc\n", __func__, __LINE__);
            goto Cleanup;
        }

        for (i = 0; i<br_tuples_num; i++) {
            obj_val = json_array_get(root_obj, i);

            json_object_foreach(obj_val, json_key, v) {

                if(strncmp(json_key, "br_name", strlen("br_name")) == 0) {
                   strncpy( br_temp[i].name, json_string_value(v), MAX_IFACE_NAME_LEN);
                   br_temp[i].name[MAX_IFACE_NAME_LEN-1] = '\0';

                   platform_log(MAP_LIBRARY,LOG_DEBUG,"%s :%d, br_name %s\n", __func__, __LINE__, br_temp[i].name);
                }

                if(strncmp(json_key, "iface_list", strlen("iface_list")) == 0) {
                  /*
                   * Parse the interface list
                   */
                    int      j         = 0;
                    json_t*  iface_obj = NULL;
                    uint8_t  iface_num = 0;

                    iface_num = json_array_size(v);
                    br_temp[i].bridged_interfaces_nr = (uint8_t)iface_num;
                    for(j = 0; j<iface_num; j++) {
                        iface_obj                        = json_array_get(v, j);
                        strncpy(&(br_temp[i].bridged_interfaces[j][0]), json_string_value(iface_obj), MAX_IFACE_NAME_LEN); 
                        br_temp[i].bridged_interfaces[j][MAX_IFACE_NAME_LEN-1] = '\0';

                        platform_log(MAP_LIBRARY,LOG_DEBUG,"br_iface %s\n", br_temp[i].bridged_interfaces[j]);

                    }
                }
            }

        }

        /*
         * Update the output pointer
         */
        *((struct bridge** )config) = br_temp;
        ret = 0;

Cleanup:
        json_decref(root_obj);
        if (complete_parse_json(L,&config_json) < 0)
            ret = -1;

        return ret;
}

int set_config(void *config, char *json_string)
{
        int len;

        if (NULL == config || NULL == json_string)
        {
            platform_log(MAP_LIBRARY,LOG_ERR, "invalid parameters");
            return -1;
        }

        strncpy (json_string, (char *)config, MAX_IFACE_NAME_LEN);
        len = strnlen((char *)config, MAX_IFACE_NAME_LEN);
        json_string[len] = '\0';

        return 0;
}

int set_wifi_params(void *config, char *json_str)
{
        struct wifi_params *wp = (struct wifi_params *) config;
		char *dump_str = NULL;
       
        json_t *root = json_object();

        json_object_set_new( root, "interface", json_string(wp->interface));
        json_object_set_new( root, "passwd", json_string(wp->passwd));
        json_object_set_new( root, "ssid", json_string(wp->ssid));
        json_object_set_new( root, "auth_type", json_string(wp->auth_type));
        json_object_set_new( root, "fronthaul_bit", json_integer(wp->fronthaul_bit));
        json_object_set_new( root, "backhaul_bit",  json_integer(wp->backhaul_bit));
    

	/* Leak Detection Fix */
        dump_str = json_dumps(root, 0);

	if(dump_str != NULL)
	{
	        strcpy(json_str,dump_str );
		platform_log(MAP_LIBRARY,LOG_DEBUG,"%s %d DUMP %s\n", __func__, __LINE__, dump_str);
		free(dump_str);
	}


        json_decref(root);
        return 0;
}

int teardown_wifi_bss(void *config, char *json_str)
{
    char *dump_str = NULL;
       
        json_t *root = json_object();

        json_object_set_new( root, "interface", json_string((char *)config));
    	/* Leak Detection Fix */
        dump_str = json_dumps(root, 0);

	if(dump_str != NULL)
	{
	        strcpy(json_str,dump_str );
		platform_log(MAP_LIBRARY,LOG_DEBUG,"%s %d\n", __func__, __LINE__);
		free(dump_str);
	}


        json_decref(root);
        return 0;
}

int map_query_beacon_metrics(void *config, char *json_str) 
{ 
        beacon_metrics_query_t *beacon_query = (beacon_metrics_query_t *)config; 
        uint8_t                 channel      = 0; 
        uint8_t      ap_channel_report_count = 0; 
 
        char    bssid_str[MAX_MAC_STRING_LEN]   = {0}; 
        char    sta_mac_str[MAX_MAC_STRING_LEN] = {0}; 
        char    ssid_str[MAX_SSID_LEN];
        char   *str                             = NULL; 
        json_t *bss_obj                         = NULL; 
        json_t *channel_obj                     = NULL; 

        if (NULL == beacon_query) { 
            platform_log(MAP_LIBRARY,LOG_ERR, "beacon metrics query is NULL"); 
            return -1; 
        } 
 
        json_t *root = json_object(); 
 
        if(NULL == root) { 
            platform_log(MAP_LIBRARY,LOG_ERR,"unable to create json"); 
            return -1; 
        } 
 
        channel                 = beacon_query->channel; 
        ap_channel_report_count = beacon_query->ap_channel_report_count; 
 
        snprintf(sta_mac_str, MAX_MAC_STRING_LEN, "%02x:%02x:%02x:%02x:%02x:%02x", 
                 beacon_query->sta_mac[0], beacon_query->sta_mac[1], 
                 beacon_query->sta_mac[2], beacon_query->sta_mac[3], 
                 beacon_query->sta_mac[4], beacon_query->sta_mac[5]); 
 
        snprintf(bssid_str, MAX_MAC_STRING_LEN, "%02x:%02x:%02x:%02x:%02x:%02x", 
                 beacon_query->bssid[0], beacon_query->bssid[1], 
                 beacon_query->bssid[2], beacon_query->bssid[3], 
                 beacon_query->bssid[4], beacon_query->bssid[5]); 
 
        memcpy(ssid_str, beacon_query->ssid, beacon_query->ssid_len);
        ssid_str[beacon_query->ssid_len] = 0;
 
        json_t *sta_mac = json_string(sta_mac_str); 
        json_t *bssid   = json_string(bssid_str); 
        json_t *ssid    = json_string(ssid_str);         
        json_t *target_bss_array = json_array();
 
        if (ap_channel_report_count == 0) { 
            bss_obj = json_object(); 
            channel_obj = json_integer(beacon_query->channel); 
             
            json_object_set_new ( bss_obj, "bssid", bssid); 
            json_object_set_new ( bss_obj, "channel", channel_obj); 
            json_array_append_new (target_bss_array, bss_obj); 

        } else { 
            struct ap_channel_report *ap_channel_report = NULL; 
            uint8_t i = 0, j = 0; 
 
            /* FRV: This currently does not lead to what is intended in MAP spec.
                    ubus send_beacon_report_request should be adapted for that.
            */
            for(i = 0; i < ap_channel_report_count; i++) { 
                ap_channel_report = &beacon_query->ap_channel_report[i]; 
                for (j = 0; j < ap_channel_report->length-1; j++) { 
                    bss_obj = json_object(); 
                    channel_obj = json_integer(ap_channel_report->channel_list[j]); 
                     
                    json_object_set_new ( bss_obj, "bssid", bssid); 
                    json_object_set_new ( bss_obj, "channel", channel_obj); 
                    json_array_append_new ( target_bss_array, bss_obj); 

                } 
            } 
 
        } 
 
        json_object_set_new ( root, "macaddr",sta_mac); 
        json_object_set_new ( root, "ssid", ssid);
        json_object_set_new ( root, "target_bss_list", target_bss_array); 

        str = json_dumps(root, 0);
 
        strcpy(json_str, str); 
 
        free(str); 
        json_decref(root); 
        return 0; 
} 


int map_legacy_sta_steer(void *config, char *json_str)
{
    struct sta_steer_params *legacy_sta_steer = (struct  sta_steer_params *) config;
    char      sta_mac_str[MAX_MAC_STRING_LEN] = {0};
    char      bssid[MAX_MAC_STRING_LEN] = {0};
    uint8_t          i   = 0;
    json_t *target_sta   = json_array();
    char      *sta_str   = NULL;

    snprintf(bssid, MAX_MAC_STRING_LEN, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
                 legacy_sta_steer->source_bssid[0], legacy_sta_steer->source_bssid[1],
                 legacy_sta_steer->source_bssid[2], legacy_sta_steer->source_bssid[3],
                 legacy_sta_steer->source_bssid[4], legacy_sta_steer->source_bssid[5]);

    json_array_append_new(target_sta, json_string(bssid));

    for (i = 0; i<legacy_sta_steer->sta_count; i++) {
         snprintf(sta_mac_str, MAX_MAC_STRING_LEN, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
                 legacy_sta_steer->sta_info[i].sta_mac[0], legacy_sta_steer->sta_info[i].sta_mac[1],
                 legacy_sta_steer->sta_info[i].sta_mac[2], legacy_sta_steer->sta_info[i].sta_mac[3],
                 legacy_sta_steer->sta_info[i].sta_mac[4], legacy_sta_steer->sta_info[i].sta_mac[5]);

         json_array_append_new(target_sta, json_string(sta_mac_str));
    }

    sta_str = json_dumps(target_sta, 0);
    if(sta_str ==  NULL) {
        platform_log(MAP_LIBRARY,LOG_ERR, "%s: json_dump fails\n",__func__);
    }
    strcpy(json_str, sta_str);

    free(sta_str);
    json_decref(target_sta);
    return 0;
}


 
int map_btm_sta_steer(void *config, char *json_str)
{
    struct sta_steer_params *btm_sta_steer = (struct  sta_steer_params *) config;
    char   sta_mac_str[MAX_MAC_STRING_LEN] = {0};
    char   bssid_str[MAX_MAC_STRING_LEN] = {0};
    char    *str_json                     = NULL;

    json_t *root = json_object();


    snprintf(sta_mac_str, MAX_MAC_STRING_LEN, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
            btm_sta_steer->sta_info[0].sta_mac[0], btm_sta_steer->sta_info[0].sta_mac[1],
            btm_sta_steer->sta_info[0].sta_mac[2], btm_sta_steer->sta_info[0].sta_mac[3],
            btm_sta_steer->sta_info[0].sta_mac[4], btm_sta_steer->sta_info[0].sta_mac[5]);

    snprintf(bssid_str, MAX_MAC_STRING_LEN, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
            btm_sta_steer->sta_info[0].bssid[0], btm_sta_steer->sta_info[0].bssid[1],
            btm_sta_steer->sta_info[0].bssid[2], btm_sta_steer->sta_info[0].bssid[3],
            btm_sta_steer->sta_info[0].bssid[4], btm_sta_steer->sta_info[0].bssid[5]);

    json_object_set_new( root, "name",           json_string(btm_sta_steer->ap_name));
    json_object_set_new( root, "target_bssid",   json_string(bssid_str));
    json_object_set_new( root, "target_channel", json_integer(btm_sta_steer->sta_info[0].channel));
    json_object_set_new( root, "disassoc_timer", json_integer(btm_sta_steer->disassociation_timer));
    json_object_set_new( root, "abridged",       json_integer(btm_sta_steer->abridged_mode));
    json_object_set_new( root, "sta_mac",        json_string(sta_mac_str));

    str_json = json_dumps(root, 0);
    if(str_json == NULL) {
        platform_log(MAP_LIBRARY,LOG_ERR, "%s json dump failure\n", __func__);
    }
    strcpy(json_str, str_json);

    free(str_json);
    json_decref(root);
    return 0;
}


int map_apply_acl(void *config, char *json_str)
{
        client_acl_data_t *acl_data = (client_acl_data_t *) config;
        char bssid_str[MAX_MAC_STRING_LEN] = {0};
        int block = 0;
        int i = 0;

        if ((NULL == acl_data) || (acl_data->sta_count <= 0)) {
            platform_log(MAP_LIBRARY,LOG_ERR, "Acl Data is NULL");
            return -1;
        }

        json_t *root = json_object();
        json_t *array = json_array();

        if((NULL == array) || (NULL == root) || (0 != json_array_size(array))) {
            platform_log(MAP_LIBRARY,LOG_ERR,"unable to create json");
            return -1;
        }

        for (i = 0; i < acl_data->sta_count; i++) {
            char sta_str[MAX_MAC_STRING_LEN] = {0};
            json_t *tmp = json_object();

            snprintf(sta_str, MAX_MAC_STRING_LEN, "%02x:%02x:%02x:%02x:%02x:%02x",
                     acl_data->sta_list[i].sta_mac[0], acl_data->sta_list[i].sta_mac[1],
                     acl_data->sta_list[i].sta_mac[2], acl_data->sta_list[i].sta_mac[3],
                     acl_data->sta_list[i].sta_mac[4], acl_data->sta_list[i].sta_mac[5]);
            json_object_set_new(tmp, "sta_mac",json_string(sta_str));
            json_array_append_new(array, tmp);
        }

        block = (acl_data->block == 0) ? 1 : 0;
        snprintf(bssid_str, MAX_MAC_STRING_LEN, "%02x:%02x:%02x:%02x:%02x:%02x",
             acl_data->bssid[0], acl_data->bssid[1], acl_data->bssid[2],
             acl_data->bssid[3], acl_data->bssid[4], acl_data->bssid[5]);

        json_object_set_new ( root, "bssid", json_string(bssid_str));
        json_object_set_new ( root, "block", json_integer(block));
        json_object_set_new ( root, "sta_count", json_integer(acl_data->sta_count));
        json_object_set_new ( root, "stations", array);

        strcpy(json_str, json_dumps(root, 0));

        return 0;
}

int get_interface_info(lua_State *L,void *config)
{
        
        json_t*               node_obj    = NULL;
        json_t*               root_obj    = NULL;
        json_t*               obj_val     = NULL;
        json_error_t          error;
        char                  value[60]   = {0};
        char*                 config_json = NULL;
        int                   ret         = 0; 
        int                   i           = 0;
        struct interfaceInfo *m           = (struct interfaceInfo *)config;

        ret = prepare_json_parse(L,&config_json);
        if(ret)
            return ret;

        root_obj = json_loads(config_json, 0, &error);

        node_obj =  json_object_get(root_obj,"power_state");
        if(json_typeof(node_obj) == JSON_INTEGER)
        {
            if(json_integer_value(node_obj) == 1)
                m->power_state = INTERFACE_POWER_STATE_ON;
            else if(json_integer_value(node_obj) == 0)
                m->power_state = INTERFACE_POWER_STATE_OFF;
        }
        node_obj =  json_object_get(root_obj,"mac_address");
        if(json_typeof(node_obj) == JSON_STRING)
        {
            strcpy(value,json_string_value(node_obj));
            platform_get_mac_from_string(value, m->mac_address);
        }

        node_obj =  json_object_get(root_obj,"device_name");
        if(json_typeof(node_obj) == JSON_STRING)
        {
            strncpy(m->device_name,json_string_value(node_obj),sizeof(m->device_name));
        }

        node_obj =  json_object_get(root_obj,"model_name");
        if(json_typeof(node_obj) == JSON_STRING)
        {
            strncpy(m->model_name,json_string_value(node_obj),sizeof(m->model_name));
        }

        node_obj =  json_object_get(root_obj,"model_number");
        if(json_typeof(node_obj) == JSON_STRING)
        {
            strncpy(m->model_number,json_string_value(node_obj),sizeof(m->model_number));
        }

        node_obj =  json_object_get(root_obj,"manufacturer_name");
        if(json_typeof(node_obj) == JSON_STRING)
        {
            strncpy(m->manufacturer_name,json_string_value(node_obj),sizeof(m->manufacturer_name));
        }

        node_obj =  json_object_get(root_obj,"serial_number");
        if(json_typeof(node_obj) == JSON_STRING)
        {
            strncpy(m->serial_number,json_string_value(node_obj),sizeof(m->serial_number));
        }

        node_obj =  json_object_get(root_obj,"uuid");
        if(json_typeof(node_obj) == JSON_STRING)
        {
            platform_hexstr_to_charstr((char *)json_string_value(node_obj),m->uuid);
        }

        node_obj =  json_object_get(root_obj,"interface_type");
        if(json_typeof(node_obj) == JSON_STRING)
        {
            if(strcmp(json_string_value(node_obj),"bgn") == 0)
                m->interface_type = INTERFACE_TYPE_IEEE_802_11N_2_4_GHZ;

            else if(strcmp(json_string_value(node_obj),"anac") == 0)
                m->interface_type = INTERFACE_TYPE_IEEE_802_11AC_5_GHZ;
        }

        node_obj =  json_object_get(root_obj,"neighbor_mac_address");
        if(json_typeof(node_obj) == JSON_ARRAY && json_array_size(node_obj) > 0 )
        {
            m->neighbor_mac_addresses_nr = json_array_size(node_obj);
            platform_log(MAP_LIBRARY,LOG_DEBUG,"%s %d mac_nr %d \n", __func__, __LINE__,  m->neighbor_mac_addresses_nr);
            m->neighbor_mac_addresses    = (uint8_t (*)[6]) calloc (m->neighbor_mac_addresses_nr, sizeof(uint8_t[6]));

            for( i = 0 ; i < m->neighbor_mac_addresses_nr; i++) 
            {
                obj_val = json_array_get(node_obj, i);
                if(json_typeof(obj_val) == JSON_STRING)
                {
                    strcpy(value,json_string_value(obj_val));
                    platform_get_mac_from_string(value, m->neighbor_mac_addresses[i]);
                }
            }
        }

        node_obj =  json_object_get(root_obj,"interface_type_data");
        if(json_typeof(node_obj) == JSON_OBJECT)
        {
            node_obj = json_object_get(node_obj,"ieee80211");

            if(json_typeof(node_obj) == JSON_OBJECT)
            {
                obj_val = json_object_get(node_obj,"encryption_mode");

                if(json_typeof(obj_val) == JSON_STRING)
                {
                    if (strcmp(json_string_value(obj_val),"AES") == 0)
                        m->interface_type_data.ieee80211.encryption_mode = IEEE80211_ENCRYPTION_MODE_AES;
                    else if (strcmp(json_string_value(obj_val),"TKIP") == 0)
                        m->interface_type_data.ieee80211.encryption_mode = IEEE80211_ENCRYPTION_MODE_TKIP;
                    else
                        m->interface_type_data.ieee80211.encryption_mode = IEEE80211_ENCRYPTION_MODE_NONE;
                }

            obj_val = json_object_get(node_obj,"authentication_mode");
            if(json_typeof(obj_val) == JSON_STRING)
            {
                m->is_secured = 1;
                if (strcmp(json_string_value(obj_val),"wep") == 0)
                   m->interface_type_data.ieee80211.authentication_mode = IEEE80211_AUTH_MODE_WEP;
                else if (strcmp(json_string_value(obj_val),"wpa-wpa2") == 0)
                   m->interface_type_data.ieee80211.authentication_mode = IEEE80211_AUTH_MODE_WPA | IEEE80211_AUTH_MODE_WPA2;
                else if (strcmp(json_string_value(obj_val),"wpa-wpa2-psk") == 0)
                   m->interface_type_data.ieee80211.authentication_mode = IEEE80211_AUTH_MODE_WPA | IEEE80211_AUTH_MODE_WPA2PSK;
                else if (strcmp(json_string_value(obj_val),"wpa2-psk") == 0)
                   m->interface_type_data.ieee80211.authentication_mode = IEEE80211_AUTH_MODE_WPA2PSK;
                else if (strcmp(json_string_value(obj_val),"wpa2") == 0)
                   m->interface_type_data.ieee80211.authentication_mode = IEEE80211_AUTH_MODE_WPA2;
                else if (strcmp(json_string_value(obj_val),"wpa-psk") == 0)
                   m->interface_type_data.ieee80211.authentication_mode = IEEE80211_AUTH_MODE_WPAPSK;
                else if (strcmp(json_string_value(obj_val),"wpa") == 0)
                   m->interface_type_data.ieee80211.authentication_mode = IEEE80211_AUTH_MODE_WPA;
                else {
                   m->interface_type_data.ieee80211.authentication_mode = IEEE80211_AUTH_MODE_OPEN;
                   m->is_secured = 0;
                }
            }

            obj_val = json_object_get(node_obj,"network_key");
            if(json_typeof(obj_val) == JSON_STRING)
            {
                strcpy(m->interface_type_data.ieee80211.network_key,json_string_value(obj_val));
            }

            obj_val = json_object_get(node_obj,"ap_channel_band");
            if(json_typeof(obj_val) == JSON_INTEGER)
            {
                m->interface_type_data.ieee80211.ap_channel_band = (uint8_t) json_integer_value(obj_val);
            }
            
            obj_val = json_object_get(node_obj,"ap_channel_center_frequency_index_1");

            if(json_typeof(obj_val) == JSON_INTEGER)
            {
                m->interface_type_data.ieee80211.ap_channel_center_frequency_index_1 = (uint8_t) json_integer_value(obj_val);
            }


            obj_val = json_object_get(node_obj,"role");
            if(json_typeof(obj_val) == JSON_STRING)
            {
                if (strcmp(json_string_value(obj_val),"ap") == 0)
                   m->interface_type_data.ieee80211.role = IEEE80211_ROLE_AP;
            }

            obj_val = json_object_get(node_obj,"ssid");
            if(json_typeof(obj_val) == JSON_STRING)
            {
                strcpy(m->interface_type_data.ieee80211.ssid,json_string_value(obj_val));
            }

            obj_val = json_object_get(node_obj,"bssid");
            if(json_typeof(obj_val) == JSON_STRING)
            {
                strcpy(value,json_string_value(obj_val));
                platform_get_mac_from_string(value, m->interface_type_data.ieee80211.bssid);
            }
        }
    }

    json_decref(root_obj);
    ret=complete_parse_json(L,&config_json);
    if(ret)
        return ret;

    return 0;
}

int map_beacon_metrics_response (lua_State *L,void* config) 
{ 
         
        const char*   json_key      =   NULL; 
        const char*   key      =   NULL; 
        json_t* obj_val       =   NULL; 
        json_t* v             =   NULL; 
        char*   config_json   =   NULL; 
        json_error_t error; 
        json_t* root_obj      =   NULL; 
        uint8_t     size      =   0; 
        uint8_t     i         =   0; 
        int         ret       =   -1;
 
        cum_measurement_report_t **beacon_report_ptr = (cum_measurement_report_t **)config; 
        cum_measurement_report_t *beacon_report =  NULL; 
        map_beacon_report_element_t *report_elem = NULL; 
 
        ret = prepare_json_parse(L,&config_json);
        if(ret)
            return ret;
 
        root_obj = json_loads(config_json, 0, &error); 
         
        size = json_object_size(root_obj); 
 
 
        *beacon_report_ptr = (cum_measurement_report_t *)calloc(1, sizeof(cum_measurement_report_t)+  
                         (size * sizeof(map_beacon_report_element_t))); 
        beacon_report = *beacon_report_ptr; 
        if(beacon_report ==  NULL) { 
            platform_log(MAP_LIBRARY,LOG_ERR, "calloc failed\n");
            goto Cleanup;
        } 
 
        beacon_report->num_of_reports = size; 
 
        json_object_foreach(root_obj, key, obj_val) { 
            report_elem = &beacon_report->beacon_report[i]; 
            i++; 

            report_elem->elementId = MEASUREMENT_REPORT_ELEMENTID;
            report_elem->measurement_type = MEASUREMENT_SUBTYPE_BEACON_REPORT;
            report_elem->length    = BEACON_REPORT_ELEMENT_SIZE - BEACON_REPORT_ELEMENT_HDR_SIZE;
            /* FRV: Until NG-178572 is implemented - after advice of Nicolas Letor, use 0 as measurement time */
            memset(report_elem->measurement_time, 0, BEACON_REPORT_START_TIME_SIZE); 

            platform_get_mac_from_string((char *)key, report_elem->bssid);
            json_object_foreach(obj_val, json_key, v) { 
 
                if(strncmp("channel", json_key, strlen("channel")) == 0) { 
                    report_elem->channel = (uint8_t)json_integer_value(v); 
		   report_elem->operating_class=(uint8_t)get_operating_class_basic(report_elem->channel);
                } 
 
                if(strncmp("rcpi", json_key, strlen("rcpi")) == 0) { 
                    report_elem->rcpi = (uint8_t)json_integer_value(v); 
                } 
 
                if(strncmp("rsni", json_key, strlen("rsni")) == 0) { 
                    report_elem->rsni = (uint8_t)json_integer_value(v); 
                } 
 
                if(strncmp("antenna_id", json_key, strlen("antenna_id")) == 0) { 
                    report_elem->antenna_id = (uint8_t)json_integer_value(v); 
                } 
 
                if(strncmp("duration", json_key, strlen("duration")) == 0) { 
                    report_elem->measurement_duration = (uint16_t)json_integer_value(v); 
                } 
            } 
        } 

        ret = 0;

Cleanup:
        json_decref(root_obj); 
        if (complete_parse_json(L,&config_json) < 0)
            ret = -1;
 
        return ret;
} 
 


int get_ap_autoconfig(lua_State *L,void *config) {

    char* config_json                   = NULL;
    int ret                             = -1;
    uint8_t total_radio                 = 0;
    uint8_t i                           = 0;
    uint8_t j                           = 0;
    uint8_t regulatory_domain[20]       = {0};
    uint8_t radio[10]                   = {0};
    uint8_t state                       = 0;
    const char *key                     = NULL;
    wifi_channel_set     current_ch;
    wifi_channel_set     non_op_ch;
    wifi_op_class_array  op_class;
    uint8_t              current_fq     = 0; 
    uint8_t              current_bw     = 0;
    json_t*              node_obj       = NULL;
    json_t*              root_obj       = NULL;
    json_t*              obj_val        = NULL;
	json_t*              mac_val        = NULL;
    json_t*              value;
    json_error_t         error;
    map_ale_info_t*      agent_node = (map_ale_info_t *) config;
	map_radio_info_t *radio_node = NULL;
    uint8_t radio_id[MAC_ADDR_LEN] = {0};

    ret=prepare_json_parse(L,&config_json);
    if(ret)
        return ret;

    root_obj = json_loads(config_json, 0, &error);

    node_obj =  json_object_get(root_obj,"AP_Autoconfig_config");
    total_radio = json_array_size(node_obj);

    if(json_typeof(node_obj) == JSON_ARRAY){
         for (i = 0; i < total_radio; i++) {
			 /* For each radio first create the radio list */
             obj_val = json_array_get(node_obj, i);
			 mac_val = json_object_get(obj_val,"mac");
			 platform_log(MAP_LIBRARY,LOG_DEBUG, "CREATE RADIO \n");
             platform_get_mac_from_string((char *)json_string_value(mac_val), radio_id);
			 platform_log(MAP_LIBRARY,LOG_DEBUG, "RADIO ID %s \n",json_string_value(mac_val));
			 /* Since this is done at boot time, no need to check for existing radio unless you feel you will
			 get replicates. Ignoring it for now and going with create directly */
			 radio_node = create_radio(radio_id, agent_node->al_mac);
			 if(!radio_node) {
                platform_log(MAP_LIBRARY,LOG_ERR, "Failed to create a radio node with ID: %s .\n", radio_id);
                continue;
             }
          
             radio_node->state = 0x0000;

             json_object_foreach(obj_val, key, value) {



                 if (strcmp(key,"if_name") == 0) {
                     strcpy(radio_node->iface_name, json_string_value(value));
                 }

                 if (strcmp(key,"state") == 0) {
                     state = (uint8_t) json_integer_value(value);
                     if (1 == state)
                         set_radio_state_on(&radio_node->state);
                 }

                 if (strcmp(key, "radio_name") == 0) {
                     strcpy(radio_node->radio_name, json_string_value(value));
                 }

                 if (strcmp(key, "radio") == 0) {
                     strcpy((char*)radio, json_string_value(value));

                     if (strcmp(json_string_value(value), "2.4GHz") == 0)
                     {
                        radio_node->radio_caps.type = IEEE80211_FREQUENCY_BAND_2_4_GHZ;
			radio_node->supported_freq=IEEE80211_FREQUENCY_BAND_2_4_GHZ;
                     }

                     if (strcmp(json_string_value(value), "5GHz") == 0)
                     {
                        radio_node->radio_caps.type = IEEE80211_FREQUENCY_BAND_5_GHZ;
			radio_node->supported_freq=IEEE80211_FREQUENCY_BAND_5_GHZ;
                     }

                    current_fq = radio_node->radio_caps.type +1;
                 }

                 if (strcmp(key, "supported_bandwidth") == 0) {
                    current_bw = (int) json_integer_value(value);
                 }

                 if (strcmp(key, "bandwidth_capability") == 0) {
                    radio_node->radio_caps.max_bandwidth = (int) json_integer_value(value);
                 }

                 if (strcmp(key, "supported_standard") == 0) {
                     if (strcmp(json_string_value(value), "802.11b") == 0)
                        radio_node->radio_caps.supported_standard = STD_80211_B;
                     else if(strcmp(json_string_value(value), "802.11g") == 0)
                        radio_node->radio_caps.supported_standard = STD_80211_G;
                     else if(strcmp(json_string_value(value), "802.11a") == 0)
                        radio_node->radio_caps.supported_standard = STD_80211_A;
                     else if((strcmp(json_string_value(value), "802.11n") == 0) || (strcmp(json_string_value(value), "802.11bgn") == 0))
                        radio_node->radio_caps.supported_standard = STD_80211_N;
                     else if(strcmp(json_string_value(value), "802.11ac") == 0)
                        radio_node->radio_caps.supported_standard = STD_80211_AC;
                     else if(strcmp(json_string_value(value), "802.11an") == 0)
                        radio_node->radio_caps.supported_standard = STD_80211_AN;
                     else if(strcmp(json_string_value(value), "802.11anac") == 0)
                        radio_node->radio_caps.supported_standard = STD_80211_ANAC;
                     else if(strcmp(json_string_value(value), "802.11ax") == 0)
                        radio_node->radio_caps.supported_standard = STD_80211_AX;
                     else
                         platform_log(MAP_LIBRARY,LOG_ERR,"Unsupported standard");
                 }

                 if (strcmp(key, "max_rx_streams") == 0) {
                    radio_node->radio_caps.max_rx_spatial_streams = (uint8_t) json_integer_value(value);
                 }

                 if (strcmp(key, "max_tx_streams") == 0) {
                    radio_node->radio_caps.max_tx_spatial_streams = (uint8_t) json_integer_value(value);
                 }

                 if (strcmp(key, "sgi_support") == 0) {
                    radio_node->radio_caps.sgi_support = (uint8_t) json_integer_value(value);
                 }

                 if (strcmp(key, "su_beamformer_capable") == 0) {
                    radio_node->radio_caps.su_beamformer_capable = (uint8_t) json_integer_value(value);
                 }

                 if (strcmp(key, "mu_beamformer_capable") == 0) {
                    radio_node->radio_caps.mu_beamformer_capable = (uint8_t) json_integer_value(value);
                 }

				 if (strcmp(key, "channel") == 0) {
                    radio_node->current_op_channel = (uint8_t) json_integer_value(value);
                 }

                 if (strcmp(key, "channel_list") == 0) {
                     char*   str        = NULL;
                     uint8_t channel    = 0;
                     char*   delimiters = " ";
                     char*   token      = NULL;

                     str = strdup(json_string_value(value));
                     j = 0;
                     token = strtok(str, delimiters);

                     while (token != NULL) {
                         platform_str_to_int(token, &channel);
                         current_ch.ch[j] = channel; 
                         j++;
                         token = strtok(NULL, delimiters);
                     }

                     current_ch.length= j;
                     free(str);
                 }

                 if (strcmp(key, "regulatory_domain") == 0) {
                     strcpy((char*)regulatory_domain, json_string_value(value));
                 }

                 if(strncmp(key,"bss_info", strlen("bss_info")) == 0) {

                     json_t *obj_val = NULL;
					 json_t *bss_val = NULL;
                     const  char *json_key  = NULL; 
                     json_t *v       = NULL;
                     int    bss_num  = 0;
                     int    sta_num  = 0;
                     int    k        = 0;
                     map_bss_info_t *bss_node = NULL;
                     uint8_t bss_id[MAC_ADDR_LEN] = {0};
		     uint8_t bss_admin_state = 0, bss_oper_state = 0;

                     bss_num = json_array_size(value);
                     radio_node->num_bss = bss_num;
                     platform_log(MAP_LIBRARY,LOG_DEBUG, "Total BSS no %d\n", bss_num);
                     for (j = 0; j<bss_num; j++) {
                         obj_val = json_array_get(value, j);
			 bss_val = json_object_get(obj_val,"bssid");
		         /* Create a bss node entry in the hashtable */
                        platform_log(MAP_LIBRARY,LOG_DEBUG, "bssid \"%s\"\n", json_string_value(bss_val));
                        platform_get_mac_from_string((char *)json_string_value(bss_val), bss_id);
                        bss_node = create_bss(bss_id, radio_node->radio_id);
                        if(!bss_node){
                            platform_log(MAP_LIBRARY,LOG_ERR, "Failed creating BSS node %s in Radio node %s .\n", bss_id, radio_node->radio_id);
                            continue;
                        }
			bss_admin_state = 0;
			bss_oper_state = 0;
                        json_object_foreach(obj_val, json_key, v) {
                             if(strncmp(json_key, "station", strlen("station")) == 0) {
                                json_t *sta_obj  = NULL;
                                json_t *sta_val  = NULL;
                                const char   *index    = NULL; 
                                map_sta_metrics_t *sta_metrics = NULL;
                                map_sta_info_t *sta_node = NULL;
                                uint8_t sta_id[MAC_ADDR_LEN] = {0};
                                 /*
			          * Get all the station mac addr
			          */
                                 sta_num = json_array_size(v);
                                /* Update number of stations in this BSS */

                                 for (k = 0; k<sta_num; k++) {

                                     sta_obj = json_array_get(v, k);

                                     sta_val = json_object_get(sta_obj,"sta_mac");
                                     /* Create a sta node entry in the hashtable */
                                     platform_log(MAP_LIBRARY,LOG_DEBUG, "sta mac \"%s\"\n", json_string_value(sta_val));
                                     platform_get_mac_from_string((char *)json_string_value(sta_val), sta_id);
                                     sta_node  = create_sta(sta_id, bss_id);
                                     if(!sta_node){
                                         platform_log(MAP_LIBRARY,LOG_ERR, "Failed creating/updating the station %s.\n", sta_id);
                                         continue;
                                     }

                                     if(list_get_size(sta_node->metrics) == 0) {
                                         sta_metrics = (map_sta_metrics_t*)calloc(1, sizeof(map_sta_metrics_t));
                                         if(sta_metrics != NULL) {
                                             insert_last_object(sta_node->metrics, (void *)sta_metrics);
                                         }
                                     }
                                     /* Allocate only if sta supports beacon metrics reporting */ 
                                     sta_node->beacon_metrics = (beacon_metrics_query_t *)calloc(1, sizeof(beacon_metrics_query_t) + 
                                                       (MAX_AP_REPORT_CHANNELS * sizeof(struct ap_channel_report))); 
                                     if(sta_node->beacon_metrics ==  NULL) { 
                                        platform_log(MAP_LIBRARY,LOG_ERR, "%s mallco failed\n",__func__); 
                                        goto Cleanup;
                                     } 


                                     sta_node->assoc_frame   = NULL;
                                     sta_node->assoc_frame_len = 0;
                                     json_object_foreach(sta_obj, index, sta_val) {
                                         if(strncmp(index, "assoc_time", strlen("assoc_time")) == 0) {
                                             struct tm time_c;
                                             strptime(json_string_value(sta_val), "%H:%M:%S-%d/%m/%Y", &time_c);
                                            sta_node->assoc_time = mktime(&time_c);
                                             platform_log(MAP_LIBRARY,LOG_DEBUG, "station assoc time \"%s\"\n", json_string_value(sta_val));
                                         }

                                         if(strncmp(index, "assoc_frame", strlen("assoc_frame"))==0) {
                                             const char * assoc_str = json_string_value(sta_val);
                                             platform_log(MAP_LIBRARY,LOG_DEBUG, "\n\n\n%s %d\n", __func__, __LINE__);
                                             hexstream_to_bytestream((char *)assoc_str, &sta_node->assoc_frame, &sta_node->assoc_frame_len);
                                             platform_log(MAP_LIBRARY,LOG_DEBUG, "assoc_frame_len \"%d\"\n", sta_node->assoc_frame_len);
                                         }


                                      }
                                 } 
                             }

                             if(strncmp(json_key, "name", strlen("name")) == 0) {
                                 platform_log(MAP_LIBRARY,LOG_DEBUG, "name \"%s\"\n", json_string_value(v));
                                 strncpy(bss_node->iface_name, json_string_value(v), MAX_IFACE_NAME_LEN);
                                 bss_node->iface_name[MAX_IFACE_NAME_LEN-1] = '\0';
                             }

                             if(strncmp(json_key, "ssid", strlen("ssid")) == 0) {
                                 platform_log(MAP_LIBRARY,LOG_DEBUG, "ssid \"%s\"\n", json_string_value(v));
                                 strncpy((char*)bss_node->ssid, json_string_value(v), MAX_WIFI_SSID_LEN);
                                 bss_node->ssid[MAX_WIFI_SSID_LEN-1] = '\0';
                             }

                             if(strncmp(json_key, "bssid", strlen("bssid")) == 0) {
                                 platform_log(MAP_LIBRARY,LOG_DEBUG, "bssid \"%s\"\n", json_string_value(v));
                                 platform_get_mac_from_string((char *)json_string_value(v), bss_node->bssid);
                             }

                             if(strncmp(json_key, "supported_security_modes", strlen("supported_security_modes")) == 0) {
                                 const char * sec_modes = json_string_value(v);
                                 platform_log(MAP_LIBRARY,LOG_DEBUG, "supported_security_modes \"%s\"\n", sec_modes);
                                 if(strlen(sec_modes) > 0)
                                     bss_node->supported_sec_modes = strdup(sec_modes);
                                 else
                                     bss_node->supported_sec_modes = NULL;
                             }
                             if(strncmp(json_key, "admin_state", strlen("admin_state")) == 0) {
                                 platform_log(MAP_LIBRARY,LOG_DEBUG, "admin_state \"%d\"\n", (uint8_t)json_integer_value(v));
                                 bss_admin_state = (uint8_t) json_integer_value(v);
                             }

                             if(strncmp(json_key, "oper_state", strlen("oper_state")) == 0) {
                                 platform_log(MAP_LIBRARY,LOG_DEBUG, "oper_state \"%d\"\n", (uint8_t)json_integer_value(v));
                                 bss_oper_state = (uint8_t) json_integer_value(v);
                             }

			     //bss_node->state = bss_admin_state & bss_oper_state

                             if(strncmp(json_key, "wps_enabled", strlen("wps_enabled")) == 0) {
                                 if((uint8_t) json_integer_value(v) == 1)
                                 {
                                     //bss_node->wps_state = MAP_BSS_TYPE_WPS_ENABLED;
                                     set_bss_state_wps_supported(&bss_node->state);
                                 }
				 platform_log(MAP_LIBRARY,LOG_DEBUG, "wps_enabled \"%d\"\n", is_bss_wps_supported(bss_node->state)?1:0);
                             }

                         }
			 if(bss_admin_state && bss_oper_state)
			 {
			     set_bss_state_on(&bss_node->state);
			     platform_log(MAP_LIBRARY,LOG_DEBUG, "BSS active \"%d\"\n", is_bss_on(bss_node->state)?1:0);
			 }
                     }
                 }

             }


              platform_log(MAP_LIBRARY,LOG_DEBUG, "channel freq-%d, bw-%d\n", current_fq, current_bw);
                 
              platform_log(MAP_LIBRARY,LOG_DEBUG, "regulatory_domain :%s\n",regulatory_domain);

              memset (&op_class, 0, sizeof(op_class));

               get_operating_class (&current_ch, current_bw, (char*)regulatory_domain, &op_class);

              /*
	               * Update the global multiap structure
	               */
            #if 0
              memcpy(radio_capability->radio_config[i].current_ch.ch, current_ch.ch, current_ch.length);
              radio_capability->radio_config[i].current_ch.count = current_ch.length;
            #endif
              /* 
	               * copy operating_class to global multiap structure
	               */
	        /* allocate memory for op_class_list. This MUST be freed when the radio is removed */
			radio_node->op_class_count = op_class.length;
			radio_node->op_class_list = (map_op_class_t *)calloc(op_class.length, sizeof(map_op_class_t));
			if(radio_node->op_class_list != NULL)
			{
           		    	for(j = 0; j<op_class.length; j++) 
                		radio_node->op_class_list[j].op_class = op_class.array[j];

		                 memset (&non_op_ch, 0, sizeof(non_op_ch));
              			 for (j=0; j<op_class.length; j++) {
                    			get_non_operating_ch(op_class.array[j], &non_op_ch, &current_ch);

			                    //##copy non operating_channels to global multiap structure
                   			 if (non_op_ch.length >0) {
						if(non_op_ch.length > MAX_CHANNEL_IN_OPERATING_CLASS)
						{
							non_op_ch.length = MAX_CHANNEL_IN_OPERATING_CLASS;
						}
                    				radio_node->op_class_list[j].static_non_operable_count = non_op_ch.length;
                    				memcpy( radio_node->op_class_list[j].static_non_operable_channel, non_op_ch.ch, non_op_ch.length );
                    			 }
		    			 else
                   	 			radio_node->op_class_list[j].static_non_operable_count = 0;

                    			 radio_node->op_class_list[j].eirp = get_eirp(op_class.array[j], (char*)regulatory_domain);
                    			 memset(&non_op_ch, 0, sizeof(non_op_ch));
              			}
              			memset(&op_class, 0, sizeof(op_class));
          		}
        	}
    	}

    ret = 0;

Cleanup:
    json_decref(root_obj);
    if (complete_parse_json(L,&config_json) < 0)
        ret = -1;

    return ret;
}


int get_assoc_frame (lua_State *L,void* config)
{
        char*   config_json   =   NULL;
        int     ret           =   0;

        stn_event_t *stn_event  = (stn_event_t *)config;

        ret = prepare_json_parse(L,&config_json);
        if(ret)
            return ret;

        stn_event->assoc_frame   = NULL;
        stn_event->assoc_frame_len = 0;

        platform_log(MAP_LIBRARY,LOG_DEBUG, "\n\n\n%s %d\n", __func__, __LINE__);
        hexstream_to_bytestream(config_json, &stn_event->assoc_frame, &stn_event->assoc_frame_len);
        platform_log(MAP_LIBRARY,LOG_DEBUG, "assoc_frame_len \"%d\"\n", stn_event->assoc_frame_len);

        ret = complete_parse_json(L,&config_json);
        if(ret)
            return ret;

        return 0;
}



int get_radio_info(lua_State *L,void *config)
{
    int     ret         = 0;
    json_t* node_obj    = NULL;
    json_t* root_obj    = NULL;
    char*   config_json = NULL;
    char    value[MAX_MAC_STRING_LEN]    = {0};
    json_error_t         error;
    radio_channel_event_t *radio_channel = (radio_channel_event_t *)config;

    ret = prepare_json_parse(L,&config_json);
    if(ret)
        return ret;

    root_obj = json_loads(config_json, 0, &error);

    node_obj =  json_object_get(root_obj,"channel");
    if(json_typeof(node_obj) == JSON_INTEGER)
    {
        radio_channel->channel = json_integer_value(node_obj);
    }

    node_obj =  json_object_get(root_obj,"radio_mac");
    if(json_typeof(node_obj) == JSON_STRING)
    {
        strncpy(value,json_string_value(node_obj), MAX_MAC_STRING_LEN);
        platform_get_mac_from_string(value, radio_channel->radio_id);
    }

    json_decref(root_obj);
    ret=complete_parse_json(L,&config_json);
    if(ret)
        return ret;

    return 0;
}

int get_radio_bss_state(lua_State *L,void *config)
{
    int     ret         = 0;
    json_t* node_obj    = NULL;
    json_t* root_obj    = NULL;
    char*   config_json = NULL;
    json_error_t         error;
    ssid_radio_state_t *state_info = (ssid_radio_state_t *)config;
    uint8_t bss_admin_state = 0, bss_oper_state = 0;
    uint8_t radio_admin_state = 0, radio_oper_state = 0;

    ret = prepare_json_parse(L,&config_json);
    if(ret)
        return ret;

    root_obj = json_loads(config_json, 0, &error);

    node_obj =  json_object_get(root_obj,"radio_admin_state");
    radio_admin_state = json_integer_value(node_obj);

    node_obj =  json_object_get(root_obj,"radio_oper_state");
    radio_oper_state = json_integer_value(node_obj);

    node_obj =  json_object_get(root_obj,"bss_admin_state");
    bss_admin_state = json_integer_value(node_obj);

    node_obj =  json_object_get(root_obj,"bss_oper_state");
    bss_oper_state = json_integer_value(node_obj);

    if(radio_admin_state && radio_oper_state)
        state_info->radio_state = 1;

    if(bss_admin_state && bss_oper_state)
	state_info->bss_state = 1;
	
    json_decref(root_obj);
	
    ret=complete_parse_json(L,&config_json);
    if(ret)
        return ret;

    return 0;
}


int get_current_channel_preference(lua_State *L,void *config)
{
	/* This is a placeholder for getting the current channel preferences assuming they are from UBUS
	But for now ignoring all LUA references as there is no value returned from it */
	int i;
	map_op_class_t * chan_pref = (map_op_class_t *) config;

	/* for now giving no values for channel preference and letting it to be default highest preferred value*/
	if(chan_pref != NULL)
	{


		#if 0
		chan_pref->agent_channel_count = 0;
		for(i=0;i<chan_pref->agent_channel_count;i++)
			chan_pref->agent_channel[i] = 0;

		chan_pref->pref = PREF_SCORE_0;
		#else
		if(chan_pref->op_class == 81)
		{
			chan_pref->agent_channel_count = 1;
			chan_pref->agent_channel[0] = 8;
			chan_pref->pref = PREF_SCORE_0;
		}
    	        else
	        {
	    	    chan_pref->agent_channel_count = 0;
		    for(i=0;i<chan_pref->agent_channel_count;i++)
			    chan_pref->agent_channel[i] = 0;

		    chan_pref->pref = PREF_SCORE_15;
	        }
		#endif

		chan_pref->reason = PREF_REASON_UNSPECFIED;
	}
	return 0;

}

int get_cumulative_bss_stats (lua_State *L,void* config)
{
        char*   config_json   =   NULL;
        json_t* root_obj      =   NULL;
        json_t* obj_val       =   NULL;
        json_t* v             =   NULL;
        json_error_t error;
        int     ret           =   0;
        int     index         =   0;
        int     j             =   0;
        const char*   json_key      =   NULL;
        const char*   key           =   NULL;
        uint8_t bss_count     =   0;

        cum_stats_t *cum_bss =  (cum_stats_t *)config; 
        map_bss_stats_t* bss_node = NULL;
        map_bss_stats_t* cum_stats = NULL;

        ret = prepare_json_parse(L,&config_json);
        if(ret)
            return ret;

        root_obj = json_loads(config_json, 0, &error);

        bss_count = json_array_size(root_obj);

        cum_bss->stats_count = bss_count;

        cum_stats = (map_bss_stats_t *)cum_bss->cum_stats;

        for(j = 0; j<bss_count; j++) {
            obj_val  = json_array_get(root_obj, j);
            bss_node = &cum_stats[j];
            
            json_object_foreach(obj_val, json_key, v) {

                 if(strncmp(json_key, "channel_util", strlen("channel_util")) == 0) {
                     bss_node->metrics.channel_utilization = json_integer_value(v);
                 }
          
                 if(strncmp(json_key, "esp_BE", strlen("esp_BE")) == 0) {
 
                     uint8_t ampdu          = 0;
                     uint8_t amsdu          = 0;
                     uint8_t amsdu_in_ampdu = 0;
                     json_t  *json_value    = NULL;
 
                     bss_node->metrics.esp_present = (1<<(7 - WIFI_AC_BE));
#if ESP_AS_FRAME
                     /* FIXME: Check if UTF-8 serves this for converting frames */
                     memcpy(bss_node->metrics.bytes_stream, json_string_value(v), 3);
#else
                     index = WIFI_AC_BE;

                     bss_node->metrics.esp[index].esp_subelement |= set_esp_access_category(0x01);

                     json_object_foreach(v, key, json_value) {
                         if(strncmp(key, "amsdu", strlen("amsdu")) == 0) {
                             amsdu = json_integer_value(json_value);
                             if(amsdu)
                                 bss_node->metrics.esp[index].esp_subelement |= set_esp_data_format(AMSDU);
                         }


                         if (strncmp(key, "ampdu", strlen("ampdu")) == 0) { 
                             ampdu = json_integer_value(json_value);
                             if(ampdu) 
                                 bss_node->metrics.esp[index].esp_subelement |= set_esp_data_format(AMPDU);
                         }
                         
                         if (strncmp(key, "amsdu_in_ampdu", strlen("amsdu_in_ampdu")) == 0) { 
                             amsdu_in_ampdu = json_integer_value(json_value);
                             if(amsdu_in_ampdu) 
                                 bss_node->metrics.esp[index].esp_subelement |= set_esp_data_format(AMSDU_AMPDU);
                         }

                         if (strncmp(key, "estATF", strlen("estATF")) == 0) {
                             /*
                              * The Air Time Fraction extimation for 1s
                              * 
                              */
                             bss_node->metrics.esp[index].estimated_air_time_fraction = json_integer_value(json_value);
                         }

                         if (strncmp(key, "BAwindow", strlen("BAwindow")) == 0) {
                             uint8_t ba_window_size = (uint8_t)json_integer_value(json_value);
                             switch(ba_window_size) {
                              case 2:
                                  bss_node->metrics.esp[index].esp_subelement |= set_esp_ba_window(BLK_ACK_TWO_BYTE_WNDOW_SIZE);
                                  break;
                              case 4:
                                  bss_node->metrics.esp[index].esp_subelement |= set_esp_ba_window(BLK_ACK_FOUR_BYTE_WNDOW_SIZE);
                                  break;
                              case 6:
                                  bss_node->metrics.esp[index].esp_subelement |= set_esp_ba_window(BLK_ACK_SIX_BYTE_WNDOW_SIZE);
                                  break;
                              case 8:
                                  bss_node->metrics.esp[index].esp_subelement |= set_esp_ba_window(BLK_ACK_EIGHT_BYTE_WNDOW_SIZE);
                                  break;
                              case 16:
                                  bss_node->metrics.esp[index].esp_subelement |= set_esp_ba_window(BLK_ACK_SIXTEEN_BYTE_WNDOW_SIZE);
                                  break;
                              case 32:
                                  bss_node->metrics.esp[index].esp_subelement |= set_esp_ba_window(BLK_ACK_THIRTY_TWO_BYTE_WNDOW_SIZE);
                                  break;
                              case 64:
                                  bss_node->metrics.esp[index].esp_subelement |= set_esp_ba_window(BLK_ACK_SIXTYFOUR_BYTE_WNDOW_SIZE);
                                  break;
                              default:
                                  bss_node->metrics.esp[index].esp_subelement |= set_esp_ba_window(NO_BLOCK_ACK);
                                  break;
                              }
                         }

                         if (strncmp(key, "txphyrate", strlen("txphyrate")) == 0) {
                             uint32_t phy_rate = 0;
                             phy_rate = json_integer_value(json_value);
                             /*
                              * For 1500 bytes
                              * target_duration for 1500B = (1500B * 8 * 20)/phytate_in_kbps (in units of 50 us)
                              *
                              */
                             if (phy_rate > 0)
                                 bss_node->metrics.esp[index].ppdu_target_duration = (uint8_t)(240000/phy_rate);
                         }
                     }
#endif

                 }

                if(strncmp(json_key, "bssid", strlen("bssid")) == 0) {
                    char mac[MAX_MAC_STRING_LEN] = {0};

                    strncpy(mac, json_string_value(v), MAX_MAC_STRING_LEN);
                    platform_get_mac_from_string(mac, bss_node->bssid);
                }
            }
        }

        json_decref(root_obj);
        ret = complete_parse_json(L,&config_json);
        if(ret)
            return ret;

        return 0;
}


int get_cumulative_sta_stats (lua_State *L,void* config)
{
        char*   config_json   =   NULL;
        json_t* root_obj      =   NULL;
        json_t* obj_val       =   NULL;
        json_t* v             =   NULL;
        json_error_t error;
        int     ret           =   0;
        int     i             =   0;
        const char*   json_key      =   NULL;
        char mac[MAX_MAC_STRING_LEN] = {0};

        cum_stats_t*     cum_sta =  (cum_stats_t *)config;
        map_sta_stats_t* sta_list = NULL;

        ret = prepare_json_parse(L,&config_json);
        if(ret)
            return ret;

        root_obj = json_loads(config_json, 0, &error);

        cum_sta->stats_count = json_array_size(root_obj);

        sta_list = (map_sta_stats_t*)cum_sta->cum_stats;

        for(i=0; i<json_array_size(root_obj); i++) {

            obj_val = json_array_get(root_obj, i);

            json_object_foreach(obj_val, json_key, v) {

                if(strncmp("bssid", json_key, strlen("bssid")) == 0) { 
                    memset(mac, 0, MAX_MAC_STRING_LEN);
                    strncpy(mac, json_string_value(v), MAX_MAC_STRING_LEN);
                   platform_get_mac_from_string(mac, sta_list[i].bssid);
                }

                if(strncmp("mac", json_key, strlen("mac")) == 0) {
                    memset(mac, 0, MAX_MAC_STRING_LEN);
                    strncpy(mac, json_string_value(v), MAX_MAC_STRING_LEN);
                   platform_get_mac_from_string(mac, sta_list[i].mac);
                }

                 if(strncmp(json_key, "tx_bytes", strlen("tx_bytes")) == 0) {
                     sta_list[i].metrics.traffic.txbytes = json_integer_value(v);
                 }
         
                 if(strncmp(json_key, "rx_bytes", strlen("rx_bytes")) == 0) {
                     sta_list[i].metrics.traffic.rxbytes = json_integer_value(v);
                 }

                 if(strncmp(json_key, "tx_packets", strlen("tx_packets")) == 0) {
                      sta_list[i].metrics.traffic.txpkts = json_integer_value(v);
                 }

                 if(strncmp(json_key, "rx_packets", strlen("rx_packets")) == 0) {
                     sta_list[i].metrics.traffic.rxpkts = json_integer_value(v);
                 }

                 if(strncmp(json_key, "tx_pkts_errors", strlen("tx_pkts_errors")) == 0) {
                     sta_list[i].metrics.traffic.txpkterrors = json_integer_value(v);
                 }

                 if(strncmp(json_key, "rx_pkts_errors", strlen("rx_pkts_errors")) == 0) {
                     sta_list[i].metrics.traffic.rxpkterrors = json_integer_value(v);
                 }

                 if(strncmp(json_key, "uplink_data_rate", strlen("uplink_data_rate")) == 0) {
                     sta_list[i].metrics.link.ul_mac_datarate = json_integer_value(v);
                 }

                 if(strncmp(json_key, "downlink_data_rate", strlen("downlink_data_rate")) == 0) {
                     sta_list[i].metrics.link.dl_mac_datarate = json_integer_value(v);
                 }

                 if(strncmp(json_key, "uplink_rssi", strlen("uplink_rssi")) == 0) {
                     sta_list[i].metrics.link.rssi = json_integer_value(v);
                 }

                 if(strncmp(json_key, "retransmission_cnt", strlen("retransmission_cnt")) == 0) {
                     sta_list[i].metrics.traffic.retransmission_cnt = json_integer_value(v);
                 }

            }
        }

        json_decref(root_obj);
        ret = complete_parse_json(L,&config_json);
        if(ret)
            return ret;

        return 0;
}

void print_json(json_t *root) {
	print_json_aux(root, 0);
}


void print_json_aux(json_t *element, int indent) {
	switch (json_typeof(element)) {
	case JSON_OBJECT:
		print_json_object(element, indent);
		break;
	case JSON_ARRAY:
		print_json_array(element, indent);
		break;
	case JSON_STRING:
		print_json_string(element, indent);
		break;
	case JSON_INTEGER:
		print_json_integer(element, indent);
		break;
	case JSON_REAL:
		print_json_real(element, indent);
		break;
	case JSON_TRUE:
		print_json_true(element, indent);
		break;
	case JSON_FALSE:
		print_json_false(element, indent);
		break;
	case JSON_NULL:
		print_json_null(element, indent);
		break;
	default:
	    platform_log(MAP_LIBRARY,LOG_CRIT,"unrecognized JSON type %d\n", json_typeof(element));
	}
}

void print_json_indent(int indent) {
	int i;
	for (i = 0; i < indent; i++) { printf(" "); }
}

const char *json_plural(int count) {
	return count == 1 ? "" : "s";
}

void print_json_array(json_t *element, int indent) {
	size_t i;
	size_t size = json_array_size(element);
	print_json_indent(indent);

	platform_log(MAP_LIBRARY,LOG_DEBUG,"JSON Array of %u element %s", size, json_plural(size));
	for (i = 0; i < size; i++) {
		print_json_aux(json_array_get(element, i), indent + 2);
	}
}

void print_json_string(json_t *element, int indent) {
	print_json_indent(indent);
	platform_log(MAP_LIBRARY,LOG_DEBUG,"JSON String: %s", json_string_value(element));
}

void print_json_integer(json_t *element, int indent) {
	print_json_indent(indent);
	platform_log(MAP_LIBRARY,LOG_DEBUG,"JSON Integer: %lld ", json_integer_value(element));
}

void print_json_real(json_t *element, int indent) {
	print_json_indent(indent);
	platform_log(MAP_LIBRARY,LOG_DEBUG,"JSON Real: %f ", json_real_value(element));
}

void print_json_true(json_t *element, int indent) {
	(void)element;
	print_json_indent(indent);
	platform_log(MAP_LIBRARY,LOG_DEBUG,"JSON True");
}

void print_json_false(json_t *element, int indent) {
	(void)element;
	print_json_indent(indent);
	platform_log(MAP_LIBRARY,LOG_DEBUG,"JSON False");
}

void print_json_null(json_t *element, int indent) {
	(void)element;
	print_json_indent(indent);
	platform_log(MAP_LIBRARY,LOG_DEBUG,"JSON Null ");
}

void print_json_object(json_t *element, int indent) {
	size_t size;
	const char *key;
	json_t *value;

	print_json_indent(indent);
	size = json_object_size(element);

	platform_log(MAP_LIBRARY,LOG_DEBUG,"JSON Object of %u pair%s:", size, json_plural(size));
	json_object_foreach(element, key, value) {
	       platform_log(MAP_LIBRARY,LOG_DEBUG,"JSON Key: %s", key);
	    print_json_aux(value, indent + 2);
	}
}

#endif

void def_config_path(unsigned int cmd,const char** path){

	switch(cmd)
	{
		case MAP_PLATFORM_GET_AGENT_CONFIG:
			*path=MULTIAP_CONFIG;
		break;
		case MAP_PLATFORM_GET_CONTROLLER_CONFIG:
			*path=MULTIAP_CONFIG;
		break;
		default:
			*path = NULL;
		break;
	}
	return;
}


#if (defined OPENWRT) && (defined USE_C_API)




int load_multiapagent_allconfig(const char* path,void*data)
{
	struct uci_context *ctx;
	struct uci_package *pkg;
	struct uci_section *s;
	struct uci_element *e;
	unsigned int i;

	if(path == NULL)
	{
		platform_log(MAP_LIBRARY,LOG_EMERG,"uci config file path not set\n");
		return -1;
	}
	ctx = uci_alloc_context();
	if (uci_load(ctx, path, &pkg) != UCI_OK)
	{
		platform_log(MAP_LIBRARY,LOG_EMERG,"Unable to Load the uci config file\n");
		uci_free_context(ctx);
		return -1;
	}

	 uci_free_context(ctx);
	return 0;
ERR:
	platform_log(MAP_LIBRARY,LOG_EMERG,"Incorrect config section %s",s->type);
	return -1;

}


int save_multiapagent_allconfig(const char* path,void*data)
{

	//TBD

	return 0;
}

int get_multiapagent_config(const char* path,void *value)
{
	struct uci_context *ctx;
	struct uci_ptr ptr;

	ctx = uci_alloc_context();
	if(!ctx)
		return -1;

	if ((uci_lookup_ptr(ctx, &ptr, (char*)path, true) != UCI_OK) ||
		(ptr.o==NULL || ptr.o->v.string==NULL))
	{
		uci_free_context(ctx);
		return -1;
	}

	if(ptr.flags & UCI_LOOKUP_COMPLETE)
	{
		strncpy((char*)value, ptr.o->v.string,strlen(ptr.o->v.string));
		return 0;
	}
	else
	{
		uci_free_context(ctx);
		return -1;
	}


}

int set_multiapagent_config(const char* path,void *value)
{
	struct uci_context *ctx;
	struct uci_ptr ptr;
	char uci_buf[128];

	ctx = uci_alloc_context();
	if(!ctx)
		return -1;

	snprintf(uci_buf, sizeof(uci_buf), "%s=%s",path,(char*)value);

	if (uci_lookup_ptr(ctx, &ptr, uci_buf, true) == UCI_OK) {
		//add logs here
		uci_set(ctx, &ptr);
	}
	else
		return -1;

	if (uci_commit(ctx, &ptr.p, false) != UCI_OK)
	{
		uci_free_context(ctx);
		//add logs here
		return -1;
	}
	return 0;
}

#endif
