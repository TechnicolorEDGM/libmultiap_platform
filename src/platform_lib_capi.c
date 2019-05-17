/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

#include <string.h>
#include <math.h>
#include <sys/ioctl.h>        // ioctl(), SIOCGIFINDEX
#include <net/if.h>           // struct ifreq, IFNAZSIZE
#include <sys/types.h>		  // socket
#include <sys/socket.h>
#include <pthread.h>
#include <libubus.h>
#include "1905_platform.h"
#include "mon_platform.h"
#include "platform_lib_capi.h"
#include "platform_lib_capi_util.h"
#include "platform_utils.h"
#include "platform_lib_test.h"
#include "platform_multiap_get_info.h"

#define ETHERTYPE_1905  (0x893a)
#define ETHERTYPE_LLDP  (0x88cc)

#define IFACE_NAME_LEN 16
#define MAX_UUID_LEN								64
#define MAX_UCI_STRING 								100
#define MAX_80211_AUTHENTICATION_MOD_NAME_LEN		32
#define MAX_80211_ENCRYPTION_MODE_NAME_LEN			32
#define MAX_80211_NETWORK_KEY_LEN 					64
#define MAX_WIFI_RADIO_NAME_LEN						64
#define MAX_80211_SSID_NAME_LEN						50
#define CHANNEL_WIDTH_STR_LEN						16
#define SUPPORTED_STANDARD_NAME_LEN					16

#define UBUS_TIMEOUT								5000
#define GET_SSID_DATA								"wireless.ssid"
#define GET_STA_DATA								"wireless.accesspoint.station"
#define GET_RADIO_DATA								"wireless.radio"
#define GET_AP_DATA									"wireless.accesspoint"
#define GET_AP_SECURITY_DATA						"wireless.accesspoint.security"
#define GET_AP_ACL_DATA                                                 "wireless.accesspoint.acl"
#define GET_NET_DEVICES                             "network.link"

/* read process's environment variables */
#define map_interfaces getenv("MAP_INTERFACES")
#define map_device_modes getenv("MAP_DEV_MODES")
#define map_model_name getenv("MAP_MODEL_NAME")
#define map_model_number getenv("MAP_MODEL_NUMBER")
#define map_serial_number getenv("MAP_SERIAL_NUMBER")
#define map_manufacturer_name getenv("MAP_MANUFACTURER_NAME")
#define map_wireless_device_name getenv("MAP_DEV_NAMES")
#define map_agent_bsslist getenv("MAP_AGENT_BSSLIST")


typedef struct _if_info_wireless_ssid_t {
	char radio_name[MAX_WIFI_RADIO_NAME_LEN];
	uint8_t mac_addr[MAC_ADDR_LEN];
	uint8_t bssid[MAC_ADDR_LEN];
	char bssid_str[MAX_MAC_STRING_LEN];
	char ssid[MAX_80211_SSID_NAME_LEN];
	unsigned int admin_state;
	unsigned int oper_state;
	unsigned int power_state;
	char if_name[MAX_IFACE_NAME_LEN];
} if_info_wireless_ssid_t;

typedef struct _if_info_wireless_radio_t {
    char ap_channel_band[CHANNEL_WIDTH_STR_LEN];
	char interface_type[SUPPORTED_STANDARD_NAME_LEN];
    char country[MAX_COUNTRY_STR_LEN];
	uint8_t center_freq_index_1;
} if_info_wireless_radio_t;

typedef struct _if_info_wireless_ap_t {
    char uuid[MAX_UUID_LEN];
	char ap_no[MAX_AP_NAME_LEN];
	char if_name[MAX_IFACE_NAME_LEN];		/*i/p param for blob parsing wireless.accesspoint */
} if_info_wireless_ap_t;

typedef struct _if_info_wireless_ap_security_t {
	char authentication_mode[MAX_80211_AUTHENTICATION_MOD_NAME_LEN];
	char encryption_mode[MAX_80211_ENCRYPTION_MODE_NAME_LEN];
	char network_key[MAX_80211_NETWORK_KEY_LEN];	
} if_info_wireless_ap_security_t;

typedef struct _if_info_wireless_neighbor_station_t {
	uint8_t neighbor_sta_mac[MAX_STATIONS][MAC_ADDR_LEN];
	unsigned short neighbor_count;
	char neighbor_sta_mac_str[MAX_MAC_STRING_LEN];
	char ap_no[MAX_AP_NAME_LEN];
	unsigned short assoc_frame_type;
	uint8_t *frame_data;
} if_info_wireless_neighbor_station_t;

typedef struct _if_info_interface_pwr_state_t {
	char if_name[MAX_IFACE_NAME_LEN]; /* i/p param for the blob parsing */
	uint8_t powerstate;
} if_info_interface_pwr_state_t;

typedef struct _if_info_if_list_data_t {
    char if_list[MAX_INTERFACE_COUNT][MAX_IFACE_NAME_LEN];
	uint8_t dynamic_if_cnt;

} if_info_if_list_data_t;
/* ubus invoke call back functions */
static void get_if_info_wireless_ssid_cb(struct ubus_request *req, int type, struct blob_attr *msg);
static void get_if_info_wireless_radio_cb(struct ubus_request *req, int type, struct blob_attr *msg);
static void get_if_info_wireless_ap_cb(struct ubus_request *req, int type, struct blob_attr *msg);
static void get_if_info_wireless_ap_security_cb(struct ubus_request *req, int type, struct blob_attr *msg);
static void get_if_info_wireless_ap_station_cb(struct ubus_request *req, int type, struct blob_attr *msg);
static void get_if_info_power_stae_cb(struct ubus_request *req, int type, struct blob_attr *msg);

/* static functions */
static int get_wireless_interface_data(struct ubus_context *ctx, char *interface, struct interfaceInfo *m, char *ap_name, char *radio_name);
static int get_wired_interface_data(struct ubus_context *ctx, const char *interface, struct interfaceInfo *m);
static int get_wireless_if_neighbor_sta_data(struct ubus_context *ctx, const char *ap_no, if_info_wireless_neighbor_station_t *ap_neighbor_data);
static int get_wireless_if_ssid_data(struct ubus_context *ctx, const char *interface, if_info_wireless_ssid_t *ssid_data);

static pthread_rwlock_t map1905if_info_rw_lock = PTHREAD_RWLOCK_INITIALIZER;
static map1905if_interface_info_t map1905if_info_interfaces[MAX_INTERFACE_COUNT];
static struct blob_buf b = {0};
static uint8_t onetime_data_collected = 0;

int get_ap_from_bssid(char* bssid, char* ap_no, void* context)
{
	int status = 0;
        struct ubus_context *ctx = (struct ubus_context *)context;
        unsigned int id = 0;
        if_info_wireless_ssid_t ssid_data = {0};
        if_info_wireless_ap_t ap_data = {0};

        if(context == NULL)
        {
                platform_log(MAP_LIBRARY,LOG_DEBUG,"%s %d Context NULL for event callback\n", __FUNCTION__, __LINE__);
                return -1;
        }

        strncpy(ssid_data.bssid_str, bssid, sizeof(ssid_data.bssid_str));
        // call wireless.ssid get
        if(UBUS_STATUS_OK != ubus_lookup_id(ctx, GET_SSID_DATA, &id)) {
                platform_log(MAP_LIBRARY,LOG_ERR, "%s %d Failed to get object id for %s\n", __FUNCTION__, __LINE__, GET_SSID_DATA);
                return -1;
        }
        blob_buf_init(&b, 0);
        if(UBUS_STATUS_OK != ubus_invoke(ctx, id, "get", b.head, get_if_info_wireless_ssid_cb, &ssid_data, UBUS_TIMEOUT)) {
                platform_log(MAP_LIBRARY,LOG_ERR, "%s [%d] ubus_invoke Failed for %s get\n", __FUNCTION__, __LINE__, GET_SSID_DATA);
                status = 1;
        }
	blob_buf_free(&b);

	if(status) {
		platform_log(MAP_LIBRARY,LOG_ERR, "%s [%d] Failed to get %s\n", __FUNCTION__, __LINE__, GET_SSID_DATA);
		return -1;
	}

        strncpy(ap_data.if_name, ssid_data.if_name, sizeof(ap_data.if_name));
        if(ap_data.if_name[0] != '\0') {
                // call wireless.accesspoint get
                if(UBUS_STATUS_OK != ubus_lookup_id(ctx, GET_AP_DATA, &id)) {
                        platform_log(MAP_LIBRARY,LOG_ERR, "%s %d Failed to get object id for %s\n", __FUNCTION__, __LINE__, GET_AP_DATA);
                        return -1;
                }
                blob_buf_init(&b, 0);
                if(UBUS_STATUS_OK != ubus_invoke(ctx, id, "get", b.head, get_if_info_wireless_ap_cb, &ap_data, UBUS_TIMEOUT)) {
                        platform_log(MAP_LIBRARY,LOG_ERR, "%s [%d] ubus_invoke Failed for %s get\n", __FUNCTION__, __LINE__, GET_AP_DATA);
                        status = 1;
                }
		blob_buf_free(&b);

		if(status) {
                	platform_log(MAP_LIBRARY,LOG_ERR, "%s [%d] Failed to get %s\n", __FUNCTION__, __LINE__, GET_AP_DATA);
                	return -1;
        	}
        }

        else {
                platform_log(MAP_LIBRARY,LOG_ERR, "%s [%d] Failed to get the interface\n", __FUNCTION__, __LINE__);
                return -1;
        }

        strncpy(ap_no, ap_data.ap_no, MAX_AP_NAME_LEN);

        return 0;
}

int platform_query_beacon_metrics(void* config, void* context)
{
        beacon_metrics_query_t *beacon_query = (beacon_metrics_query_t *)config;
        uint8_t channel;
        uint8_t ap_channel_report_count;
        char    sta_mac_str[MAX_MAC_STRING_LEN] = {0};
        char    bssid_str[MAX_MAC_STRING_LEN]   = {0};
        char    ssid_str[MAX_SSID_LEN];
        if_info_wireless_neighbor_station_t ap_neighbor_data = {0};
        struct ubus_context *ctx = (struct ubus_context *)context;
        void* table, *array, *array_channel;
        char ap_no[MAX_AP_NAME_LEN] = {0};

        if (NULL == beacon_query) {
            platform_log(MAP_LIBRARY,LOG_ERR, "beacon metrics query is NULL");
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

        strncpy(ap_neighbor_data.neighbor_sta_mac_str, sta_mac_str, MAX_MAC_STRING_LEN);

        blob_buf_init(&b, 0);
        blobmsg_add_string(&b, "macaddress", ap_neighbor_data.neighbor_sta_mac_str);

        /* ubus call wireless.accesspoint.station get '{"macaddress":"<mac>"}' */

        if (!(invoke_ubus_command_ex(ctx, GET_STA_DATA, "get", &b, NULL, get_if_info_wireless_ap_station_cb, &ap_neighbor_data))) {
                platform_log(MAP_LIBRARY,LOG_ERR, "%s [%d] Failed to get %s\n", __FUNCTION__, __LINE__, GET_STA_DATA);
                return -1;
        }

        if(ap_neighbor_data.ap_no[0] != '\0') {
                strncpy(ap_no, ap_neighbor_data.ap_no, MAX_AP_NAME_LEN);
        }

        blob_buf_init(&b, 0);
        blobmsg_add_string(&b, "name", ap_no);
        blobmsg_add_string(&b, "macaddr", sta_mac_str);
        blobmsg_add_u32(&b, "max_duration", 20);
        blobmsg_add_string(&b, "mode", "active");
        blobmsg_add_u32(&b, "timeout", 3000);
        blobmsg_add_u32(&b, "report_detail", beacon_query->report_detail);
        blobmsg_add_string(&b, "ssid", ssid_str);
        if (ap_channel_report_count == 0) {
            array = blobmsg_open_array(&b, "target_bss_list");
            table = blobmsg_open_table(&b, NULL);
            blobmsg_add_string(&b, "bssid", bssid_str);
            blobmsg_add_u32(&b, "channel", channel);
            blobmsg_close_table(&b, table);
            blobmsg_close_array(&b, array);
        }
        else {
            struct ap_channel_report *ap_channel_report = NULL;
            uint8_t i = 0, j = 0;

            /* FRV: This currently does not lead to what is intended in MAP spec.
               ubus send_beacon_report_request should be adapted for that.
             */
                array = blobmsg_open_array(&b, "target_bss_list");
                for(i = 0; i < ap_channel_report_count; i++) {
                ap_channel_report = &beacon_query->ap_channel_report[i];
                table = blobmsg_open_table(&b, NULL);
                blobmsg_add_string(&b, "bssid", bssid_str);
                blobmsg_add_u32(&b, "rclass", ap_channel_report->operating_class);
                blobmsg_add_u32(&b, "channel", 255);
                array_channel = blobmsg_open_array(&b, "channel_list");
                for (j = 0; j < ap_channel_report->length-1; j++) {
                    blobmsg_add_u32(&b, NULL, ap_channel_report->channel_list[j]);
                }
                blobmsg_close_array(&b, array_channel);
                blobmsg_close_table(&b, table);
                }
                blobmsg_close_array(&b, array);
        }

        /* ubus call wireless.accesspoint.station send_beacon_report_request '{"name":"ap_no","macaddr":"<mac>","timeout":1000,"mode":"active","max_duration":20,"target_bss_list":[{"bssid":"<bssid>","channel":}],"ssid":"<ssid>"}' */

        if (!(invoke_ubus_command_ex(ctx, GET_STA_DATA, "send_beacon_report_request", &b, NULL, NULL, NULL))) {
                platform_log(MAP_LIBRARY,LOG_ERR, "%s [%d] Failed to get %s\n", __FUNCTION__, __LINE__, GET_STA_DATA);
                return -1;
        }

        return 0;
}

int platform_get_assoc_frame(const char * input_str, void *config, void * context)
{
        json_t *root_obj;
        json_t *node_obj;
        json_error_t error;
        if_info_wireless_neighbor_station_t ap_neighbor_data = {0};
        char macaddr[MAX_MAC_STRING_LEN] = {0};
        char ap_name[MAX_AP_NAME_LEN] = {0};

        struct ubus_context *ctx = (struct ubus_context *)context;
        stn_event_t *stn_event  = (stn_event_t *)config;

        stn_event->assoc_frame   = NULL;
        stn_event->assoc_frame_len = 0;

        if(context == NULL)
        {
                platform_log(MAP_LIBRARY,LOG_DEBUG,"%s [%d] Context NULL for event callback\n", __FUNCTION__, __LINE__);
                return -1;
        }

        root_obj = json_loads(input_str, 0, &error);

        node_obj =  json_object_get(root_obj,"macaddr");
        if(json_typeof(node_obj) == JSON_STRING)
          strncpy(macaddr,json_string_value(node_obj),MAX_MAC_STRING_LEN);

        node_obj =  json_object_get(root_obj,"name");
        if(json_typeof(node_obj) == JSON_STRING)
          strncpy(ap_name,json_string_value(node_obj),MAX_AP_NAME_LEN);

        ap_neighbor_data.assoc_frame_type = 1;

        blob_buf_init(&b, 0);
        blobmsg_add_string(&b, "name", ap_name);
        blobmsg_add_string(&b, "macaddr",macaddr);
        blobmsg_add_u32(&b, "report_assoc_frame", 1);

        /* ubus call wireless.accesspoint.station get '{"name":"<ap_name>","macaddr":"<mac>","report_assoc_frame":1}' */

        if (!(invoke_ubus_command_ex(ctx, GET_STA_DATA, "get", &b, NULL, get_if_info_wireless_ap_station_cb, &ap_neighbor_data))) {
                if (NULL != ap_neighbor_data.frame_data)
                    free(ap_neighbor_data.frame_data);
                platform_log(MAP_LIBRARY,LOG_ERR, "%s [%d] Failed to get %s\n", __FUNCTION__, __LINE__, GET_STA_DATA);
                return -1;
        }

        if(ap_neighbor_data.frame_data != NULL)
        {
            hexstream_to_bytestream((char *)ap_neighbor_data.frame_data, &stn_event->assoc_frame, &stn_event->assoc_frame_len);
            free(ap_neighbor_data.frame_data);
            platform_log(MAP_LIBRARY,LOG_DEBUG, "assoc_frame_len \"%d\"\n", stn_event->assoc_frame_len);
        }

        return 0;
}


int is_agent_preferred_channel(int channel, uint8_t *agent_pref_ch_set, uint8_t array_cnt) {
    int i = 0;

    if(agent_pref_ch_set == NULL || channel == 0) 
        return -EINVAL;

    for (i = 0; i<array_cnt; i++) {
        if (channel == agent_pref_ch_set[i]) {
		    break;
	}
    }

    if(i < array_cnt) {
        /* agent preferred */
	return 1;
    }
	
    return 0;
}

int platform_update_5g_chan_pref(wifi_channel_set * chan_pref_set, wifi_channel_set * dfs_affected_set, struct blob_attr * msg) {

        struct blob_attr *c1 = NULL;
        struct blob_attr *data1 = blobmsg_data(msg);
        int rem1 = blobmsg_data_len(msg);
        int i = 0;

        __blob_for_each_attr(c1, data1, rem1)
        {
                struct blob_attr *data2 = blobmsg_data(c1);
                struct blob_attr *c2 = NULL;
                int rem2 = blobmsg_data_len(c1);

                __blob_for_each_attr(c2, data2, rem2)
                {
                        if (strcmp(blobmsg_name(c2), "available_channel") == 0) {
                            char *channel_list = strdup(blobmsg_get_string(c2));
                            char *temp  = channel_list;
                            char *token = NULL;

                            while((token = strtok_r(temp, " ", &temp)) != NULL) {
                                chan_pref_set->ch[i] = atoi(token);
                                i++;
                            }

                            free(channel_list);
                        }

                        if (strcmp(blobmsg_name(c2), "usable_channel") == 0) {
                            char *channel_list = strdup(blobmsg_get_string(c2));
                            char *temp = channel_list;

                            char *token = NULL;
                            while((token = strtok_r(temp, " ", &temp)) != NULL) {
                                chan_pref_set->ch[i] = atoi(token);
                                i++;
                            }
                            free(channel_list);
                        }

                        if (strcmp(blobmsg_name(c2), "unusable_channel") == 0) {
                            int j = 0;
                            char *channel_list = strdup(blobmsg_get_string(c2));
                            char *temp = channel_list;

                            char *token = NULL;
                            while((token = strtok_r(temp, " ", &temp)) != NULL) {
                                dfs_affected_set->ch[j] = atoi(token);
                                j++;
                            }
                            dfs_affected_set->length = j;
                            free(channel_list);
                        }
                }
        }
        chan_pref_set->length = i;
        return 0;
}


int platform_update_chan_pref(wifi_channel_set * chan_pref_set, struct blob_attr * msg) {

        struct blob_attr *c1 = NULL;
        struct blob_attr *data1 = blobmsg_data(msg);
        int rem1 = blobmsg_data_len(msg);

        __blob_for_each_attr(c1, data1, rem1)
        {
                struct blob_attr *data2 = blobmsg_data(c1);
                struct blob_attr *c2 = NULL;
                int rem2 = blobmsg_data_len(c1);

                __blob_for_each_attr(c2, data2, rem2)
                {
                        if (strcmp(blobmsg_name(c2), "allowed_channels") == 0) {
                            char *channel_list = strdup(blobmsg_get_string(c2));
                            char *temp = channel_list;
                            int i = 0;
                            char *token = NULL;
                            while((token = strtok_r(temp, " ", &temp)) != NULL) {
                                chan_pref_set->ch[i] = atoi(token);
                                i++;
                            }
                            chan_pref_set->length = i;
                            free(channel_list);
                        }
                }
        }
        return 0;
}

int is_channel_non_operable(int channel, uint8_t *non_oper_chan_array, uint8_t array_cnt, uint8_t bandwidth , uint8_t op_class) {

        if(non_oper_chan_array ==  NULL) {
            return -EINVAL;
        }
        channel = get_mid_freq(channel, op_class, bandwidth);
        for(uint8_t i = 0; i<array_cnt; i++) {
	    if(channel == non_oper_chan_array[i]) {
		    return 1;
		}
	}
	return 0;
}

int update_radar_affected_ch_set(wifi_channel_set *radar_affected_ch_set, wifi_channel_set *update_radar_ch_set, uint8_t bandwidth, uint8_t opclass)
{
    if(bandwidth == 80 || bandwidth == 160)
    {
        for(uint8_t i = 0; i < radar_affected_ch_set->length; i++)
            update_radar_ch_set->ch[i] = get_mid_freq(radar_affected_ch_set->ch[i], opclass, bandwidth);

        update_radar_ch_set->length = radar_affected_ch_set->length;
    }
    else
        update_radar_ch_set = radar_affected_ch_set;
    return 0;
}

int platform_get_5g_channel_pref(const char* input_str, void* config, void *ctx)
{
     map_op_class_t * dev_rclass = (map_op_class_t *) config;
     struct blob_buf input_args = {0};
     struct blob_attr *msg      = NULL;
     char  *radio_name          = (char*) input_str;

     wifi_channel_set   agent_pref_ch_set     = {0};
     wifi_channel_set   radar_affected_ch_set = {0};
     wifi_channel_set   new_radar_aftd_ch_set = {0};
     wifi_channel_set   rclass_ch_set         = {0};
     int                cnt                   =  0;
     int                op_ch_cnt             =  0;
     uint8_t            bandwidth             =  0;
     uint8_t            mid_freq              =  0;
     uint8_t            new_freq              =  0;

     blob_buf_init(&input_args, 0);
     blobmsg_add_string(&input_args, "name", radio_name);

     if(invoke_ubus_command(ctx, "wireless.radio.dfs", "get", &input_args, &msg)) {
	platform_update_5g_chan_pref(&agent_pref_ch_set, &radar_affected_ch_set, msg);

        /* Leak Detection Fix */
        free(msg);

        if(agent_pref_ch_set.length == 0) {
             /* 
              * There should be atleast one channel, preferrable
              * something went wrong with radio.
              */
             /* Leak Detection Fix */
             blob_buf_free(&input_args);
             return 0;
        }
        
        memset(dev_rclass->agent_channel, 0,
                           sizeof(dev_rclass->agent_channel));

        memset(dev_rclass->agent_non_oper_ch, 0,
                           sizeof(dev_rclass->agent_non_oper_ch));
	/* 
	 * Now update the non-pref channel list 
	 * Along with its score.
	 *
	 */

         if(get_channel_set_for_rclass(dev_rclass->op_class, &rclass_ch_set) < 0) {
             /*
              * There should be atleast one channel, preferrable
              * something went wrong woth radio.
              */
             /* Leak Detection Fix */
             blob_buf_free(&input_args);
             return 0;
	 }

         /* Default reason */	 
         dev_rclass->reason  = PREF_REASON_UNSPECFIED;
         get_bw_from_operating_class(dev_rclass->op_class, &bandwidth);
         update_radar_affected_ch_set(&radar_affected_ch_set, &new_radar_aftd_ch_set, bandwidth, dev_rclass->op_class);

	 for (int i = 0; i<rclass_ch_set.length; i++) {

            if(is_channel_non_operable(rclass_ch_set.ch[i],
                    dev_rclass->static_non_operable_channel,
                    dev_rclass->static_non_operable_count, bandwidth, dev_rclass->op_class) == 1) {
                 /* Exclude non-operable channels */
                 continue;
            }

	       if (is_agent_preferred_channel (rclass_ch_set.ch[i],
                    agent_pref_ch_set.ch,
                    agent_pref_ch_set.length) == 1) {
		     /* Hinghly preferred channel */
                    if(mid_freq == (new_freq = get_mid_freq(rclass_ch_set.ch[i], dev_rclass->op_class, bandwidth)))
                        continue;
                    dev_rclass->agent_channel[op_ch_cnt] = mid_freq = new_freq;
                    op_ch_cnt++;
		            continue;
            }

            if(is_channel_non_operable(rclass_ch_set.ch[i], 
                            new_radar_aftd_ch_set.ch, 
                            new_radar_aftd_ch_set.length, bandwidth, dev_rclass->op_class) == 1) {
                /*
                 * There is Radar activity detected on the 
                 * channel in this operating class, and hence give reason as RADAR DETECTED.
                 */ 
                dev_rclass->reason  = PREF_REASON_RADAR_DETECT;

                dev_rclass->agent_non_oper_ch[cnt] = rclass_ch_set.ch[i];
                cnt++;
            }
         }
	 
         dev_rclass->agent_non_oper_ch_cnt = cnt;
         dev_rclass->agent_channel_count   = op_ch_cnt;

         if(op_ch_cnt < 0) {
             /* 
              * There is no operable channel in this operating class,
              * and hence preference set to "0".
              */
             dev_rclass->pref                  = PREF_SCORE_0;
         } else {
             dev_rclass->pref                  = PREF_SCORE_15;
         }
    }

    /* Leak Detection Fix */
    blob_buf_free(&input_args);

    return 0;
}


int platform_get_2g_channel_pref(const char* input_str, void* config, void *ctx)
{
     map_op_class_t * dev_rclass = (map_op_class_t *) config;
     struct blob_buf input_args = {0};
     struct blob_attr *msg      = NULL;
     char  *radio_name          = (char*) input_str;

     wifi_channel_set   agent_pref_ch_set = {0};
     wifi_channel_set   rclass_ch_set     = {0};
     int                cnt               =  0;
     int                op_ch_cnt         =  0;
     uint8_t            bandwidth         =  0;

     blob_buf_init(&input_args, 0);
     blobmsg_add_string(&input_args, "name", radio_name);

     invoke_ubus_command(ctx, "wireless.radio.acs", "get", &input_args, &msg);

     if (msg) {
	platform_update_chan_pref(&agent_pref_ch_set, msg);

        /* Leak Detection Fix */
        free(msg);

        if(agent_pref_ch_set.length == 0) {
             /* 
              * There should be atleast one channel, preferrable
              * something went wrong woth radio.
              */
             /* Leak Detection Fix */
             blob_buf_free(&input_args);
             return 0;
        }	

        memset(dev_rclass->agent_channel, 0,
                           sizeof(dev_rclass->agent_channel));

        memset(dev_rclass->agent_non_oper_ch, 0,
                           sizeof(dev_rclass->agent_non_oper_ch));
	/* 
	 * Now update the non-pref channel list 
	 * Along with its score.
	 *
	 */
	 
         if(get_channel_set_for_rclass(dev_rclass->op_class, &rclass_ch_set) < 0) {
             /* 
              * There should be atleast one channel, preferrable
              * something went wrong woth radio.
              */
             /* Leak Detection Fix */
             blob_buf_free(&input_args);
             return 0;
	 }

         /* Default reason */	 
         dev_rclass->reason  = PREF_REASON_UNSPECFIED;
         get_bw_from_operating_class(dev_rclass->op_class, &bandwidth);
	 
	 for (int i = 0; i<rclass_ch_set.length; i++) {

            if(is_channel_non_operable(rclass_ch_set.ch[i], 
                    dev_rclass->static_non_operable_channel, 
                    dev_rclass->static_non_operable_count, bandwidth, dev_rclass->op_class) == 1) {
                 /* Exclude non-operable channels */
                 continue;
            }
 
	    if (is_agent_preferred_channel (rclass_ch_set.ch[i], 
                     agent_pref_ch_set.ch, 
                     agent_pref_ch_set.length) == 1) {
		     /* Hinghly preferred channel */
                     dev_rclass->agent_channel[op_ch_cnt] = rclass_ch_set.ch[i];
                     op_ch_cnt++;
		     continue;
            }


            dev_rclass->agent_non_oper_ch[cnt] = rclass_ch_set.ch[i];
            cnt++;
         }
	 
         dev_rclass->agent_non_oper_ch_cnt = cnt;
         dev_rclass->agent_channel_count   = op_ch_cnt;
         if(op_ch_cnt < 0) {
             /* 
              * There is no operable channel in this operating class,
              * and hence preference set to "0".
              */
             dev_rclass->pref                  = PREF_SCORE_0;
         } else {
             dev_rclass->pref                  = PREF_SCORE_15;
         }
    }

    /* Leak Detection Fix */
    blob_buf_free(&input_args);

    return 0;
}

int platform_get_bridge_info(const char* sub_cmd, void* bridge_list_data, void* context)
{
       char ieee1905_ifaces[MAX_IFACE_NAME_LIST * MAX_IFACE_NAME_LEN] = {0};
       char network_type[MAX_IFACE_NAME_LEN] = {0};
       char br_ifaces[MAX_IFACES_IN_BRIDGE * MAX_IFACE_NAME_LEN] = {0};
       char* iface,*saveptr = NULL;

       int i = 0;
       int no_of_null = 1;
       int iface_count = 0;
       int bridge_count = 0;
       struct bridge* br_temp = NULL;

       if(!(get_uci_config("multiap", "al_entity", "interfaces", ieee1905_ifaces, MAX_IFACE_NAME_LIST * MAX_IFACE_NAME_LEN))) {
               platform_log(MAP_LIBRARY,LOG_ERR, "%s [%d] Unable to fetch al_entity interfaces from multiap config\n", __FUNCTION__, __LINE__);
               return -1;
       }

       if(!(get_uci_config("network", "lan", "type", network_type, MAX_IFACE_NAME_LEN))) {
               platform_log(MAP_LIBRARY,LOG_ERR, "%s [%d] Unable to fetch lan type from network config\n", __FUNCTION__, __LINE__);
               return -1;
       }

       if(0 == strcmp(network_type, "bridge"))
               bridge_count++;

       br_temp = (struct bridge*)calloc(bridge_count + no_of_null, sizeof(struct bridge));
       if(br_temp == NULL) {
               platform_log(MAP_LIBRARY,LOG_ERR,"%s [%d] No space available for br tuple alloc\n", __func__, __LINE__);
               return -1;
       }

       for( i = 0; i < bridge_count; i++) {
               strncpy( br_temp[i].name, "br-lan", MAX_IFACE_NAME_LEN);
               br_temp[i].name[MAX_IFACE_NAME_LEN-1] = '\0';

               if(get_uci_config("network", "lan", "ifname", br_ifaces, MAX_IFACES_IN_BRIDGE * MAX_IFACE_NAME_LEN)) {
                       iface = strtok_r (br_ifaces," ", &saveptr);
                       iface_count = 0;
                       if(ieee1905_ifaces[0] != '\0') {
                               while (iface != NULL) {
                                       if(is_string_in_line(ieee1905_ifaces, iface)) {
                                               strncpy(&(br_temp[i].bridged_interfaces[iface_count][0]), iface, MAX_IFACE_NAME_LEN);
                                               br_temp[i].bridged_interfaces[iface_count][MAX_IFACE_NAME_LEN-1] = '\0';
                                               iface_count++;
                                       }
                                       iface = strtok_r (NULL, " ", &saveptr);
                               }
                       }
                       br_temp[i].bridged_interfaces_nr = iface_count;
               }
               else {
                       platform_log(MAP_LIBRARY,LOG_ERR, "%s [%d] Unable to fetch lan ifname from network config\n", __FUNCTION__, __LINE__);
		       free(br_temp);
                       return -1;
               }
       }
       /*
        * Update the output pointer
        */
       *((struct bridge** )bridge_list_data) = br_temp;

       return 0;
}

int platform_set_controller_interface_link(void* interface_name, void* context)
{
        char if_name[MAX_IFACE_NAME_LEN] = {0};
        strncpy(if_name, (char *)interface_name, MAX_IFACE_NAME_LEN);
        if_name[MAX_IFACE_NAME_LEN-1] = '\0';

        if(!(set_uci_config("multiap", "agent", "backhaul_link", (char*)if_name))) {
                platform_log(MAP_LIBRARY,LOG_ERR, "%s [%d] Unable to set and/or commit backhaul_link for agent in multiap config\n", __FUNCTION__, __LINE__);
                return -1;
        }

        return 0;
}

int platform_get_controller_policy_config(const char* sub_cmd, void* policy_data, void* context)
{
        int status = 0;
        char report_interval[MAX_UCI_STRING] = {0};
        char rssi_threshold_dbm[MAX_UCI_STRING] = {0};
        char rssi_hysteresis_margin[MAX_UCI_STRING] = {0};
        char channel_utilization_threshold_dbm[MAX_UCI_STRING] = {0};
        char sta_traffic_stats[MAX_UCI_STRING] = {0};
        map_policy_config_t *policy_config=(map_policy_config_t*)policy_data;

        if(!(get_uci_config("multiap", "controller_policy_config", "metrics_report_interval", report_interval, MAX_UCI_STRING))) {
                platform_log(MAP_LIBRARY,LOG_ERR, "%s [%d] Unable to fetch controller_policy_config metrics_report_interval from multiap config\n", __FUNCTION__, __LINE__);
                status = 1;
        }

        if(!(get_uci_config("multiap", "controller_policy_config", "sta_metrics_rssi_threshold_dbm", rssi_threshold_dbm, MAX_UCI_STRING))) {
                platform_log(MAP_LIBRARY,LOG_ERR, "%s [%d] Unable to fetch controller_policy_config sta_metrics_rssi_threshold_dbm from multiap config\n", __FUNCTION__, __LINE__);
                status = 1;
        }

        if(!(get_uci_config("multiap", "controller_policy_config", "sta_metrics_rssi_hysteresis_margin", rssi_hysteresis_margin, MAX_UCI_STRING))) {
                platform_log(MAP_LIBRARY,LOG_ERR, "%s [%d] Unable to fetch controller_policy_config sta_metrics_rssi_hysteresis_margin from multiap config\n", __FUNCTION__, __LINE__);
                status = 1;
        }

        if(!(get_uci_config("multiap", "controller_policy_config", "ap_metrics_channel_utilization_threshold_dbm", channel_utilization_threshold_dbm, MAX_UCI_STRING))) {
                platform_log(MAP_LIBRARY,LOG_ERR, "%s [%d] Unable to fetch controller_policy_config ap_metrics_channel_utilization_threshold_dbm from multiap config\n", __FUNCTION__, __LINE__);
                status = 1;
        }

        if(!(get_uci_config("multiap", "controller_policy_config", "sta_link_sta_traffic_stats", sta_traffic_stats, MAX_UCI_STRING))) {
                platform_log(MAP_LIBRARY,LOG_ERR, "%s [%d] Unable to fetch controller_policy_config sta_link_sta_traffic_stats from multiap config\n", __FUNCTION__, __LINE__);
                status = 1;
        }

        if(status) {
                platform_log(MAP_LIBRARY,LOG_ERR, "%s [%d] Unable to fetch controller_policy_config from multiap config\n", __FUNCTION__, __LINE__);
                return -1;
        }

        policy_config->metrics_report_interval = atoi(report_interval);
        policy_config->sta_metrics_rssi_threshold_dbm = atoi(rssi_threshold_dbm);
        policy_config->sta_metrics_rssi_hysteresis_margin = atoi(rssi_hysteresis_margin);
        policy_config->ap_metrics_channel_utilization_threshold_dbm = atoi(channel_utilization_threshold_dbm);
        policy_config->sta_link_sta_traffic_stats = atoi(sta_traffic_stats);

        return 0;
}

int platform_get_frequency_band(const char* interface, void* freq_band_data, void* context)
{
        char radio_name[MAX_WIFI_RADIO_NAME_LEN] = {0};

        if(!(get_uci_config("wireless", (char*)interface, "device", radio_name, MAX_WIFI_RADIO_NAME_LEN))) {
                platform_log(MAP_LIBRARY,LOG_ERR, "%s [%d] Failed to get radio_name\n", __FUNCTION__, __LINE__);
                return -1;
        }

	if(radio_name[0] != '\0') {
		uint8_t *freq_band = (uint8_t *) freq_band_data;

		if (0 == strcmp(radio_name, "radio_2G"))
			*freq_band = IEEE80211_FREQUENCY_BAND_2_4_GHZ;
		else if ((0 == strcmp(radio_name, "radio_5G")) || (0 == strcmp(radio_name, "radio2")))
			*freq_band = IEEE80211_FREQUENCY_BAND_5_GHZ;
		else
			platform_log(MAP_LIBRARY,LOG_ERR, "%s [%d] Invalid interface, unable to fetch frequency band\n", __FUNCTION__, __LINE__);
	}
	else {
		platform_log(MAP_LIBRARY,LOG_ERR, "%s [%d] Fetched radio_name is empty\n", __FUNCTION__, __LINE__);
		return -1;
	}

	return 0;
}

static void get_if_info_wireless_ssid_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct blob_attr *data1 = NULL, *c1 = NULL; // first level
	struct blob_attr *data2 = NULL, *c2 = NULL; // second level

	if_info_wireless_ssid_t *ssid_data = (if_info_wireless_ssid_t *)req->priv;

	data1 = blobmsg_data(msg);
	int rem1 = blobmsg_data_len(msg);

	__blob_for_each_attr(c1, data1, rem1)
	{
		data2 = blobmsg_data(c1);
		int rem2 = blobmsg_data_len(c1);
		__blob_for_each_attr(c2, data2, rem2)
		{
			if(0 == strcmp(blobmsg_name(c2),"radio")) {
				strncpy(ssid_data->radio_name, blobmsg_get_string(c2), sizeof(ssid_data->radio_name));
			}
			else if(0 == strcmp(blobmsg_name(c2),"bssid")) {
				if(ssid_data->bssid_str[0] != '\0') {
                                        if(0 == strcmp(blobmsg_get_string(c2), ssid_data->bssid_str)) {
                                                strncpy(ssid_data->if_name, blobmsg_name(c1), sizeof(ssid_data->if_name));
                                                return;
                                        }
                                }
                                else {
                                        platform_get_mac_from_string(blobmsg_get_string(c2), ssid_data->bssid);
                                        strncpy(ssid_data->bssid_str, blobmsg_get_string(c2), sizeof(ssid_data->bssid_str));
                                }
			}
			else if(0 == strcmp(blobmsg_name(c2),"mac_address")) {
				platform_get_mac_from_string(blobmsg_get_string(c2), ssid_data->mac_addr);
			}
			else if(0 == strcmp(blobmsg_name(c2),"ssid")) {
				strncpy(ssid_data->ssid, blobmsg_get_string(c2), sizeof(ssid_data->ssid));
			}
			else if(0 == strcmp(blobmsg_name(c2),"admin_state")) {
				ssid_data->admin_state = blobmsg_get_u32(c2);
			}
			else if(0 == strcmp(blobmsg_name(c2),"oper_state")) {
				ssid_data->oper_state= blobmsg_get_u32(c2);
			}
		}
	}
}

static void get_if_info_wireless_radio_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct blob_attr *data1 = NULL, *c1 = NULL; // first level
	struct blob_attr *data2 = NULL, *c2 = NULL; // second level

	if_info_wireless_radio_t *radio_data = (if_info_wireless_radio_t *)req->priv;

	data1 = blobmsg_data(msg);
	int rem1 = blobmsg_data_len(msg);

	__blob_for_each_attr(c1, data1, rem1)
	{
		data2 = blobmsg_data(c1);
		int rem2 = blobmsg_data_len(c1);
		__blob_for_each_attr(c2, data2, rem2)
		{			
			if(0 == strcmp(blobmsg_name(c2),"supported_standards")) {
				strncpy(radio_data->interface_type, blobmsg_get_string(c2), sizeof(radio_data->interface_type));				
			}
			else if(0 == strcmp(blobmsg_name(c2),"channel_width")) {
				strncpy(radio_data->ap_channel_band, blobmsg_get_string(c2), sizeof(radio_data->ap_channel_band));
			}
			else if(0 == strcmp(blobmsg_name(c2),"channel")) {
				radio_data->center_freq_index_1 =  blobmsg_get_u32(c2);
			}
            else if(0 == strcmp(blobmsg_name(c2),"country")) {
                strncpy(radio_data->country, blobmsg_get_string(c2), sizeof(radio_data->country));                
            }
		}
	}
}

static void get_if_info_wireless_ap_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct blob_attr *data1 = NULL, *c1 = NULL; // first level
	struct blob_attr *data2 = NULL, *c2 = NULL; // second level
	char if_name[MAX_UCI_STRING] = {0};

	if_info_wireless_ap_t *ap_data = (if_info_wireless_ap_t *)req->priv;

	data1 = blobmsg_data(msg);
	int rem1 = blobmsg_data_len(msg);

	__blob_for_each_attr(c1, data1, rem1)
	{
		data2 = blobmsg_data(c1);
		int rem2 = blobmsg_data_len(c1);
		__blob_for_each_attr(c2, data2, rem2)
		{			
			if(0 == strcmp(blobmsg_name(c2),"ssid"))
			{
				if(ap_data->if_name[0] != '\0') {
                                        strncpy(if_name, blobmsg_get_string(c2), MAX_UCI_STRING);
                                }
                                else {
                                        strncpy(ap_data->if_name, blobmsg_get_string(c2), sizeof(ap_data->if_name));
                                        return;
                                }
			}
			if(0 == strcmp(blobmsg_name(c2),"uuid"))
			{
				if((if_name[0] != '\0') && (0 == strcmp(ap_data->if_name, if_name)))
				{
					platform_hexstr_to_charstr(blobmsg_get_string(c2), ap_data->uuid);
					strncpy(ap_data->ap_no, blobmsg_name(c1), MAX_AP_NAME_LEN);
					break;
				}
			}
		}
	}
}

static void get_if_info_wireless_ap_security_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct blob_attr *data1 = NULL, *c1 = NULL; // first level
	struct blob_attr *data2 = NULL, *c2 = NULL; // second level

	if_info_wireless_ap_security_t *ap_security_data = (if_info_wireless_ap_security_t *)req->priv;

	data1 = blobmsg_data(msg);
	int rem1 = blobmsg_data_len(msg);
	__blob_for_each_attr(c1, data1, rem1)
	{	
		data2 = blobmsg_data(c1);
		int rem2 = blobmsg_data_len(c1);
		__blob_for_each_attr(c2, data2, rem2)
		{			
			if(0 == strcmp(blobmsg_name(c2),"mode"))
			{
				strncpy(ap_security_data->authentication_mode, blobmsg_get_string(c2), sizeof(ap_security_data->authentication_mode));
				if(0 == strcmp(ap_security_data->authentication_mode, "none")) {
					strcpy(ap_security_data->encryption_mode, "NONE");
					memset(ap_security_data->network_key, 0, sizeof(ap_security_data->network_key));
					break;
				}			
			}
			if((0 == strcmp(blobmsg_name(c2),"wep_key") && (0 == strcmp(ap_security_data->authentication_mode, "wep")) )) {	
				strncpy(ap_security_data->network_key, blobmsg_get_string(c2), sizeof(ap_security_data->network_key));
				strcpy(ap_security_data->encryption_mode, "TKIP");
				break;
			} else if((0 == strcmp(blobmsg_name(c2),"wpa_psk_passphrase") && (0 == strcmp(ap_security_data->authentication_mode, "wpa")) )) {
				strncpy(ap_security_data->network_key, blobmsg_get_string(c2), sizeof(ap_security_data->network_key));
				strcpy(ap_security_data->encryption_mode, "TKIP");
				break;
			} else if(0 == strcmp(blobmsg_name(c2),"wpa_psk_passphrase")) {				
				strncpy(ap_security_data->network_key, blobmsg_get_string(c2), sizeof(ap_security_data->network_key));
				strcpy(ap_security_data->encryption_mode, "AES");
			} 	 			
		}
	}		
}

static void get_if_info_wireless_ap_station_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct blob_attr *data1 = NULL, *c1 = NULL; // first level
	struct blob_attr *data2 = NULL, *c2 = NULL; // second level
	struct blob_attr *data3 = NULL, *c3 = NULL; // third level
	int i = 0;

	if_info_wireless_neighbor_station_t *ap_station_data = (if_info_wireless_neighbor_station_t *)req->priv;

	data1 = blobmsg_data(msg);
	int rem1 = blobmsg_data_len(msg);
	__blob_for_each_attr(c1, data1, rem1)
	{
		data2 = blobmsg_data(c1);
		int rem2 = blobmsg_data_len(c1);
		__blob_for_each_attr(c2, data2, rem2)
		{
			data3 = blobmsg_data(c2);
			int rem3 = blobmsg_data_len(c2);
			__blob_for_each_attr(c3, data3, rem3)
			{				
                           if(ap_station_data->assoc_frame_type == 1)
                           {
                                if(0 == strcmp(blobmsg_name(c3),"assoc_frame"))
                                {
                                    int len = strlen(blobmsg_get_string(c3));
                                    if (len > 0)
                                    {
                                        ap_station_data->frame_data = (void *) malloc((len*sizeof(uint8_t))+1);
                                        if(ap_station_data->frame_data != NULL)
                                        {
                                            memset((void*)ap_station_data->frame_data,0x00,((len*sizeof(uint8_t))+1));
                                            memcpy(ap_station_data->frame_data,blobmsg_get_string(c3),len);
                                            return;
                                        }
                                    }
                                }
                           }
                           else
                           {		
				if(0 == strcmp(blobmsg_name(c3),"state"))
				{
					if(NULL != strstr(blobmsg_get_string(c3),"Associated"))
					{
						if(ap_station_data->neighbor_sta_mac_str[0] != '\0') {
                                                        if(0 == strcmp(ap_station_data->neighbor_sta_mac_str, blobmsg_name(c2))) {
                                                                strncpy(ap_station_data->ap_no, blobmsg_name(c1), MAX_AP_NAME_LEN);
                                                                platform_log(MAP_LIBRARY,LOG_DEBUG, "%s [%d] ap_station_data->ap_no : %s\n", __FUNCTION__, __LINE__, ap_station_data->ap_no);
                                                                return;
                                                        }
                                                }
                                                if (ap_station_data->neighbor_count < MAX_STATIONS) {
                                                    ap_station_data->neighbor_count++;
                                                    platform_get_mac_from_string((char*)blobmsg_name(c2), ap_station_data->neighbor_sta_mac[i++]);
                                                }
                                                else {
                                                    platform_log(MAP_LIBRARY,LOG_DEBUG,"Number of stations exceeded limit, hence not adding the rest");
                                                    return;
                                                }
					}
				}			
			    }
			}			
		}
	}
}

static void get_if_info_power_stae_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct blob_attr *data1 = NULL, *c1 = NULL; // first level
	struct blob_attr *data2 = NULL, *c2 = NULL; // second level
	struct blob_attr *data3 = NULL, *c3 = NULL; // third level
	char if_name[32] = {0};

	if_info_interface_pwr_state_t *if_pwrstate_data = (if_info_interface_pwr_state_t *)req->priv;

	data1 = blobmsg_data(msg);
	int rem1 = blobmsg_data_len(msg);
	__blob_for_each_attr(c1, data1, rem1)
	{		
		data2 = blobmsg_data(c1);
		int rem2 = blobmsg_data_len(c1);
		__blob_for_each_attr(c2, data2, rem2)
		{
			data3 = blobmsg_data(c2);
			int rem3 = blobmsg_data_len(c2);
			__blob_for_each_attr(c3, data3, rem3)
			{	
				if(0 == strcmp(blobmsg_name(c3),"interface")) {
					strncpy(if_name, blobmsg_get_string(c3), sizeof(if_name));					
				}
				if(0 == strcmp(if_name, if_pwrstate_data->if_name) && (0 == strcmp(blobmsg_name(c3),"action"))) {
					if(0 == strcmp(blobmsg_get_string(c3),"up")) {
						if_pwrstate_data->powerstate = 0x01;
					} else if(0 == strcmp(blobmsg_get_string(c3),"down")){
						if_pwrstate_data->powerstate = 0x02;
					} else {
						if_pwrstate_data->powerstate = 0x03;
					}					
					break;
				}
			}
			if(if_pwrstate_data->powerstate != 0)
			{
				break;
			}
		}
	}
}



int platform_get_radio_info(const char* radio_name, void* radio_channel_data, void* context)
{
	int status = 0;
    wifi_op_class_array cur_opclass;
    wifi_channel_set channel;
    struct ubus_context *ctx = (struct ubus_context *)context;
    unsigned int id = 0;
    if_info_wireless_radio_t radio_data = {0};
    char* interface = NULL;
    if_info_wireless_ssid_t ssid_data = {0};

    if(context == NULL)
    {
        platform_log(MAP_LIBRARY,LOG_DEBUG,"%s [%d] Context NULL for event callback\n", __FUNCTION__, __LINE__);
        return -1;
    }

    // call wireless.radio get
    if(UBUS_STATUS_OK != ubus_lookup_id(ctx, GET_RADIO_DATA, &id)) {
        platform_log(MAP_LIBRARY,LOG_ERR, "%s [%d] Failed to get object id for %s\n", __FUNCTION__, __LINE__, GET_RADIO_DATA);
        return -1;
    }
    blob_buf_init(&b, 0);
    blobmsg_add_string(&b, "name", radio_name);
    if(UBUS_STATUS_OK != ubus_invoke(ctx, id, "get", b.head, get_if_info_wireless_radio_cb, &radio_data, UBUS_TIMEOUT)) {
        platform_log(MAP_LIBRARY,LOG_ERR, "%s [%d] ubus_invoke Failed for %s get\n", __FUNCTION__, __LINE__, GET_RADIO_DATA);
        status = 1;
    }
	blob_buf_free(&b);

	if(status) {
                platform_log(MAP_LIBRARY,LOG_ERR, "%s [%d] Failed to get %s\n", __FUNCTION__, __LINE__, GET_RADIO_DATA);
                return -1;
        }

        interface = get_interface_for_radio(radio_name);

        if(interface != NULL) {
                // call wireless.ssid get
                if(UBUS_STATUS_OK != ubus_lookup_id(ctx, GET_SSID_DATA, &id)) {
                        platform_log(MAP_LIBRARY,LOG_ERR, "%s [%d] Failed to get object id for %s\n", __FUNCTION__, __LINE__, GET_SSID_DATA);
                        return -1;
                }
                blob_buf_init(&b, 0);
                blobmsg_add_string(&b, "name", interface);
                if(UBUS_STATUS_OK != ubus_invoke(ctx, id, "get", b.head, get_if_info_wireless_ssid_cb, &ssid_data, UBUS_TIMEOUT)) {
                        platform_log(MAP_LIBRARY,LOG_ERR, "%s [%d] ubus_invoke Failed for %s get\n", __FUNCTION__, __LINE__, GET_SSID_DATA);
                        status = 1;
                }
		blob_buf_free(&b);

		if(status) {
	                platform_log(MAP_LIBRARY,LOG_ERR, "%s [%d] Failed to get %s\n", __FUNCTION__, __LINE__, GET_SSID_DATA);
                	return -1;
        	}
        }

        else {
                platform_log(MAP_LIBRARY,LOG_ERR, "%s [%d] Failed to get the interface\n", __FUNCTION__, __LINE__);
                return -1;
        }

        radio_channel_event_t *radio_channel = (radio_channel_event_t *)radio_channel_data;
        radio_channel->channel = radio_data.center_freq_index_1;
        radio_channel->bandwidth = atoi(radio_data.ap_channel_band);
        memcpy(radio_channel->radio_id, ssid_data.mac_addr, sizeof(radio_channel->radio_id));


        channel.ch[0] = radio_channel->channel;
        channel.length = 1;
        memset (&cur_opclass, 0, sizeof(cur_opclass));
        get_operating_class(&channel, radio_channel->bandwidth, radio_data.country, &cur_opclass);
        radio_channel->op_class = cur_opclass.array[0];

        return 0;
}

int platform_get_agent_bssid(const char* ap_name, void* agent_bssid_data, void* context)
{
	int status = 0;
        struct ubus_context *ctx = (struct ubus_context *)context;
        unsigned int id = 0;
        if_info_wireless_ap_t ap_data = {0};
        if_info_wireless_ssid_t ssid_data = {0};

        if(context == NULL)
        {
                platform_log(MAP_LIBRARY,LOG_DEBUG,"%s %d Context NULL for event callback\n", __FUNCTION__, __LINE__);
                return -1;
        }

        strncpy(ap_data.ap_no, ap_name, sizeof(ap_data.ap_no));
        // call wireless.accesspoint get
        if(UBUS_STATUS_OK != ubus_lookup_id(ctx, GET_AP_DATA, &id)) {
                platform_log(MAP_LIBRARY,LOG_ERR, "%s %d Failed to get object id for %s\n", __FUNCTION__, __LINE__, GET_AP_DATA);
                return -1;
        }
        blob_buf_init(&b, 0);
        blobmsg_add_string(&b, "name", ap_data.ap_no);
        if(UBUS_STATUS_OK != ubus_invoke(ctx, id, "get", b.head, get_if_info_wireless_ap_cb, &ap_data, UBUS_TIMEOUT)) {
                platform_log(MAP_LIBRARY,LOG_ERR, "%s [%d] ubus_invoke Failed for %s get\n", __FUNCTION__, __LINE__, GET_AP_DATA);
                status = 1;
        }
	blob_buf_free(&b);

	if(status) {
                platform_log(MAP_LIBRARY,LOG_ERR, "%s [%d] Failed to get %s\n", __FUNCTION__, __LINE__, GET_AP_DATA);
                return -1;
        }

        if(ap_data.if_name[0] != '\0') {
                // call wireless.ssid get
                if(UBUS_STATUS_OK != ubus_lookup_id(ctx, GET_SSID_DATA, &id)) {
                        platform_log(MAP_LIBRARY,LOG_ERR, "%s %d Failed to get object id for %s\n", __FUNCTION__, __LINE__, GET_SSID_DATA);
                        return -1;
                }
                blob_buf_init(&b, 0);
                blobmsg_add_string(&b, "name", ap_data.if_name);
                if(UBUS_STATUS_OK != ubus_invoke(ctx, id, "get", b.head, get_if_info_wireless_ssid_cb, &ssid_data, UBUS_TIMEOUT)) {
                        platform_log(MAP_LIBRARY,LOG_ERR, "%s [%d] ubus_invoke Failed for %s get\n", __FUNCTION__, __LINE__, GET_SSID_DATA);
                        status = 1;
                }
		blob_buf_free(&b);

		if(status) {
                	platform_log(MAP_LIBRARY,LOG_ERR, "%s [%d] Failed to get %s\n", __FUNCTION__, __LINE__, GET_SSID_DATA);
        	        return -1;
	        }
        }

        else {
                platform_log(MAP_LIBRARY,LOG_ERR, "%s [%d] Failed to get the interface\n", __FUNCTION__, __LINE__);
                return -1;
        }

        memcpy(agent_bssid_data, ssid_data.bssid_str, MAX_MAC_STRING_LEN);

        return 0;
}

int platform_apply_acl(void* client_acl_data, void* context)
{
        client_acl_data_t *acl_data = (client_acl_data_t *) client_acl_data;
        char bssid_str[MAX_MAC_STRING_LEN] = {0};
        char ap_name[MAX_AP_NAME_LEN] = {0};
        char* action = NULL;
        struct ubus_context *ctx = (struct ubus_context *)context;
        unsigned int id = 0;
        int i = 0;
        char sta_str[MAX_MAC_STRING_LEN] = {0};

        if ((NULL == acl_data) || (acl_data->sta_count <= 0)) {
            platform_log(MAP_LIBRARY,LOG_DEBUG, "%s [%d] Acl Data is NULL\n", __FUNCTION__, __LINE__);
            return -1;
        }

        snprintf(bssid_str, MAX_MAC_STRING_LEN, "%02x:%02x:%02x:%02x:%02x:%02x",
             acl_data->bssid[0], acl_data->bssid[1], acl_data->bssid[2],
             acl_data->bssid[3], acl_data->bssid[4], acl_data->bssid[5]);

        if(-1 == get_ap_from_bssid(bssid_str, ap_name, context)) {
                platform_log(MAP_LIBRARY,LOG_ERR,"%s [%d] Failed to get ap from bssid\n", __FUNCTION__, __LINE__);
                return -1;
        }

        if(acl_data->block == 0) {
                action = "deny";
        } else {
                action = "delete";
        }

        if(action != NULL && ap_name[0] != '\0')
        {
                // call wireless.accesspoint.acl <action>
                if(UBUS_STATUS_OK != ubus_lookup_id(ctx, GET_AP_ACL_DATA, &id)) {
                        platform_log(MAP_LIBRARY,LOG_ERR, "%s %d Failed to get object id for %s\n", __FUNCTION__, __LINE__, GET_AP_ACL_DATA);
                        return -1;
                }
                for (i = 0; i < acl_data->sta_count; i++) {

                        snprintf(sta_str, MAX_MAC_STRING_LEN, "%02x:%02x:%02x:%02x:%02x:%02x",
                                acl_data->sta_list[i].sta_mac[0], acl_data->sta_list[i].sta_mac[1],
                                acl_data->sta_list[i].sta_mac[2], acl_data->sta_list[i].sta_mac[3],
                                acl_data->sta_list[i].sta_mac[4], acl_data->sta_list[i].sta_mac[5]);

                        blob_buf_init(&b, 0);
                        blobmsg_add_string(&b, "name", ap_name);
                        blobmsg_add_string(&b, "macaddr", sta_str);
                        if(UBUS_STATUS_OK != ubus_invoke(ctx, id, action, b.head, NULL, NULL, UBUS_TIMEOUT)) {
                                platform_log(MAP_LIBRARY,LOG_ERR, "%s [%d] ubus_invoke Failed for %s %s\n", __FUNCTION__, __LINE__, GET_AP_ACL_DATA, action);
                        }
			blob_buf_free(&b);
                }
        }
        else {
                platform_log(MAP_LIBRARY,LOG_ERR, "%s [%d] Failed to apply acl\n", __FUNCTION__, __LINE__);
                return -1;
        }
        return 0;
}

static int get_wireless_if_ssid_data(struct ubus_context *ctx, const char *interface, if_info_wireless_ssid_t *ssid_data)
{
	unsigned int id = 0;
	int status = UBUS_STATUS_OK;

	/* call wireless.ssid get '{"name":"<interface>"}' */
	if(UBUS_STATUS_OK != ubus_lookup_id(ctx, GET_SSID_DATA, &id)) {
		platform_log(MAP_LIBRARY,LOG_ERR, "%s Failed to get object id for %s\n", __FUNCTION__,"wireless.ssid");
	}				
	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "name", interface); 
	status = ubus_invoke(ctx, id, "get", b.head, get_if_info_wireless_ssid_cb, ssid_data, UBUS_TIMEOUT);
	if(UBUS_STATUS_OK != status) {
		platform_log(MAP_LIBRARY,LOG_ERR, "%s ubus_invoke Failed for %s get\n", __FUNCTION__,"wireless.ssid");
	}
	blob_buf_free(&b);
	platform_log(MAP_LIBRARY,LOG_DEBUG, "%s wireless ssid %s oper state %u \tadmin state %u\n", __FUNCTION__, ssid_data->ssid, ssid_data->oper_state, ssid_data->admin_state);

	return status;	
}

static int get_wireless_if_neighbor_sta_data(struct ubus_context *ctx, const char *ap_no, if_info_wireless_neighbor_station_t *ap_neighbor_data)
{	
	unsigned int id = 0;
	int status = UBUS_STATUS_OK;

	/* ubus call wireless.accesspoint.station  get '{"name", "<apno>"}'*/		
	if(UBUS_STATUS_OK != ubus_lookup_id(ctx, GET_STA_DATA, &id)) {
		platform_log(MAP_LIBRARY,LOG_ERR, "%s Failed to get object id for %s\n", __FUNCTION__,"wireless.accesspoint.station");
	}
	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "name", ap_no);		
	status = ubus_invoke(ctx, id, "get", b.head, get_if_info_wireless_ap_station_cb, ap_neighbor_data, UBUS_TIMEOUT);
	if(UBUS_STATUS_OK != status) {
		platform_log(MAP_LIBRARY,LOG_ERR, "%s ubus_invoke Failed for %s get\n", __FUNCTION__,"wireless.accesspoint.station");
	}
	blob_buf_free(&b);
	platform_log(MAP_LIBRARY,LOG_DEBUG, "%s ap neighbor mac cnt %u\n", __FUNCTION__, ap_neighbor_data->neighbor_count);

	return status;
}

static int get_wireless_interface_data(struct ubus_context *ctx, char *interface, struct interfaceInfo *m, char *ap_name, char *radio_name)
{
	unsigned int id = 0;
	int status = 0;
	
	if_info_wireless_ssid_t ssid_data = {0};
	if_info_wireless_radio_t radio_data = {0};
	if_info_wireless_ap_t ap_data = {0};
	if_info_wireless_ap_security_t ap_security_data = {0};
	if_info_wireless_neighbor_station_t ap_neighbor_data = {0};

	/* get ssid data for given interface */
	/* check if wireless.ssid object exists */
	if(UBUS_STATUS_OK != ubus_lookup_id(ctx, GET_SSID_DATA, &id)) {
		platform_log(MAP_LIBRARY,LOG_ERR, "%s Failed to get object id for %s\n", __FUNCTION__,"wireless.ssid");
		status = -1;
		return status;
	}
	status = get_wireless_if_ssid_data(ctx, (const char*)interface, &ssid_data);
	if(UBUS_STATUS_OK != status) {
		platform_log(MAP_LIBRARY,LOG_ERR, "%s Failed to get ssid data \n", __FUNCTION__);
		status = -1;
		return status;
	}

	/* update o/p data struct with ssid data */
	if((1 == ssid_data.admin_state) && (1 == ssid_data.oper_state)) {
		m->power_state = INTERFACE_POWER_STATE_ON;
	} else {
		m->power_state = INTERFACE_POWER_STATE_OFF;
	}


	strncpy(radio_name, ssid_data.radio_name, MAX_RADIO_NAME_LEN);

	strncpy(m->interface_type_data.ieee80211.ssid,ssid_data.ssid,sizeof(m->interface_type_data.ieee80211.ssid));
	memcpy(m->interface_type_data.ieee80211.bssid,ssid_data.bssid, sizeof(ssid_data.bssid));
	memcpy(m->mac_address, ssid_data.mac_addr, sizeof(ssid_data.mac_addr));							

	/* ubus call wireless.radio get '{"name":"<radioname>"}' */
	if(UBUS_STATUS_OK != ubus_lookup_id(ctx, GET_RADIO_DATA, &id)) {
		platform_log(MAP_LIBRARY,LOG_ERR, "%s Failed to get object id for %s\n", __FUNCTION__, "wireless.radio");
		status = -1;
		return status;
	}		
	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "name", ssid_data.radio_name);		
	status = ubus_invoke(ctx, id, "get", b.head, get_if_info_wireless_radio_cb, &radio_data, UBUS_TIMEOUT);
	if(UBUS_STATUS_OK != status) {
		platform_log(MAP_LIBRARY,LOG_ERR, "%s Failed to get radio data \n", __FUNCTION__);
		status = 1;
	}
	blob_buf_free(&b);

	if(status) {
                platform_log(MAP_LIBRARY,LOG_ERR, "%s [%d] Failed to get %s\n", __FUNCTION__, __LINE__, GET_RADIO_DATA);
		status = -1;
                return status;
        }

	if(0 == strcmp(radio_data.interface_type,"bgn")) {
		m->interface_type = INTERFACE_TYPE_IEEE_802_11N_2_4_GHZ;
	} else if(0 == strcmp(radio_data.interface_type,"anac")) {
		m->interface_type = INTERFACE_TYPE_IEEE_802_11AC_5_GHZ;
	}

	/* strip off "MHz"	and conver to integer */
	char *bw_number = NULL;
	bw_number = strstr(radio_data.ap_channel_band, "MHz");	
	if(NULL != bw_number)
	{	
		*bw_number = '\0';
		m->interface_type_data.ieee80211.ap_channel_band = atoi(radio_data.ap_channel_band);
		platform_log(MAP_LIBRARY,LOG_DEBUG, "%s the channel width as integer %d \n", __FUNCTION__, m->interface_type_data.ieee80211.ap_channel_band);
	} else {
		platform_log(MAP_LIBRARY,LOG_ERR, "%s Failed to parse channel_band, expected 'MHz' %s\n", __FUNCTION__, radio_data.ap_channel_band);
	}

	m->interface_type_data.ieee80211.ap_channel_center_frequency_index_1  = radio_data.center_freq_index_1;

	/* ubus call wireless.accesspoint get, extract info for matching i/f name */
	if(UBUS_STATUS_OK != ubus_lookup_id(ctx, GET_AP_DATA, &id)) {
		platform_log(MAP_LIBRARY,LOG_ERR, "%s Failed to get object id for %s\n", __FUNCTION__, "wireless.accesspoint");
		status = -1;
		return status;
	}
	strncpy(ap_data.if_name,interface,sizeof(ap_data.if_name));
	blob_buf_init(&b, 0);
	status = ubus_invoke(ctx, id, "get", b.head, get_if_info_wireless_ap_cb, &ap_data, UBUS_TIMEOUT);
	if(UBUS_STATUS_OK != status) {
		platform_log(MAP_LIBRARY,LOG_ERR, "%s Failed to get accesspoint data \n", __FUNCTION__);
		status = 1;
	}
	blob_buf_free(&b);

	if(status) {
                platform_log(MAP_LIBRARY,LOG_ERR, "%s [%d] Failed to get %s\n", __FUNCTION__, __LINE__, GET_AP_DATA);
		status = -1;
                return status;
        }

	strncpy(m->uuid, ap_data.uuid, sizeof(ap_data.uuid));
	/* store matching apno of this interface for next ubus call */
	strncpy(ap_name, ap_data.ap_no, sizeof(ap_data.ap_no));

	/* ubus call wireless.accesspoint.security get '{"name":"<apno>"}' */
	if(UBUS_STATUS_OK != ubus_lookup_id(ctx, GET_AP_SECURITY_DATA, &id)) {
		platform_log(MAP_LIBRARY,LOG_ERR,"%s Failed to get object id for %s\n", __FUNCTION__, "wireless.accesspoint.security");
		status = -1;
		return status;
	}
	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "name", ap_data.ap_no);		
	status = ubus_invoke(ctx, id, "get", b.head, get_if_info_wireless_ap_security_cb, &ap_security_data, UBUS_TIMEOUT);
	if(UBUS_STATUS_OK != status) {
		platform_log(MAP_LIBRARY,LOG_ERR, "%s Failed to get ap security data \n", __FUNCTION__);
		status = 1;
	}
	blob_buf_free(&b);

	if(status) {
                platform_log(MAP_LIBRARY,LOG_ERR, "%s [%d] Failed to get %s\n", __FUNCTION__, __LINE__, GET_AP_SECURITY_DATA);
		status = -1;
                return status;
        }

	if (0 == strcmp(ap_security_data.encryption_mode,"AES")) {
		m->interface_type_data.ieee80211.encryption_mode = IEEE80211_ENCRYPTION_MODE_AES;
	} else if (0 == strcmp(ap_security_data.encryption_mode,"TKIP")) {
		m->interface_type_data.ieee80211.encryption_mode = IEEE80211_ENCRYPTION_MODE_TKIP;
	} else {
		m->interface_type_data.ieee80211.encryption_mode = IEEE80211_ENCRYPTION_MODE_NONE;
	}

	m->is_secured = 1;
	if (0 == strcmp(ap_security_data.authentication_mode,"wep"))
	   m->interface_type_data.ieee80211.authentication_mode = IEEE80211_AUTH_MODE_WEP;
	else if (0 == strcmp(ap_security_data.authentication_mode,"wpa-wpa2"))
	   m->interface_type_data.ieee80211.authentication_mode = IEEE80211_AUTH_MODE_WPA | IEEE80211_AUTH_MODE_WPA2;
	else if (0 == strcmp(ap_security_data.authentication_mode,"wpa-wpa2-psk"))
	   m->interface_type_data.ieee80211.authentication_mode = IEEE80211_AUTH_MODE_WPA | IEEE80211_AUTH_MODE_WPA2PSK;
	else if (0 == strcmp(ap_security_data.authentication_mode,"wpa2-psk"))
	   m->interface_type_data.ieee80211.authentication_mode = IEEE80211_AUTH_MODE_WPA2PSK;
	else if (0 == strcmp(ap_security_data.authentication_mode,"wpa2"))
	   m->interface_type_data.ieee80211.authentication_mode = IEEE80211_AUTH_MODE_WPA2;
	else if (0 == strcmp(ap_security_data.authentication_mode,"wpa-psk"))
	   m->interface_type_data.ieee80211.authentication_mode = IEEE80211_AUTH_MODE_WPAPSK;
	else if (0 == strcmp(ap_security_data.authentication_mode,"wpa"))
	   m->interface_type_data.ieee80211.authentication_mode = IEEE80211_AUTH_MODE_WPA;
	else {
	   m->interface_type_data.ieee80211.authentication_mode = IEEE80211_AUTH_MODE_OPEN;
	   m->is_secured = 0;
	}
	if('\0' != ap_security_data.network_key[0]) {
		strncpy(m->interface_type_data.ieee80211.network_key, ap_security_data.network_key, sizeof(m->interface_type_data.ieee80211.network_key));
	}

	/* get neighbor data for given ap name */
	/* check if "wireless.accesspoint.station" object exists */
	if(UBUS_STATUS_OK != ubus_lookup_id(ctx, GET_STA_DATA, &id)) {
		platform_log(MAP_LIBRARY,LOG_ERR, "%s Failed to get object id for %s\n", __FUNCTION__,"wireless.accesspoint.station");
		status = -1;
		return status;
	}
	
	status = get_wireless_if_neighbor_sta_data(ctx, (const char*)ap_data.ap_no, &ap_neighbor_data);	
	if(UBUS_STATUS_OK != status) {
		platform_log(MAP_LIBRARY,LOG_ERR, "%s Failed to get neighbor sta data \n", __FUNCTION__);
		status = -1;
		return status;
	}
	
	if(ap_neighbor_data.neighbor_count  > 0) {
		m->neighbor_mac_addresses_nr = ap_neighbor_data.neighbor_count;
		m->neighbor_mac_addresses = (uint8_t (*)[6]) calloc(ap_neighbor_data.neighbor_count, sizeof(uint8_t[6]));
		memcpy(m->neighbor_mac_addresses, ap_neighbor_data.neighbor_sta_mac, m->neighbor_mac_addresses_nr*sizeof(uint8_t[6]));
	}

	for(int i =0; i < m->neighbor_mac_addresses_nr && m->neighbor_mac_addresses[i][0] != '\0'; i++) {
		platform_log(MAP_LIBRARY,LOG_DEBUG, "%s \t interface %s \t Neighbor MAC[%d] : %s \n", __FUNCTION__, interface, i, m->neighbor_mac_addresses[i]);
	}

	/* read data from env vars to fill in */	
	strncpy(m->model_number,map_model_number,sizeof(m->model_number));
	strncpy(m->manufacturer_name,map_manufacturer_name,sizeof(m->manufacturer_name));
	strncpy(m->serial_number,map_serial_number,sizeof(m->serial_number));
	strncpy(m->model_name,map_model_name,sizeof(m->model_name));
	platform_log(MAP_LIBRARY,LOG_DEBUG, "%s \t model_name %s \t serial_number %s \t manufacturer_name %s \n", __FUNCTION__, m->model_name, m->serial_number, m->manufacturer_name);

	platform_log(MAP_LIBRARY,LOG_DEBUG, "%s the macros are map_device_modes %s \t map_wireless_device_name%s\n", __FUNCTION__,map_device_modes, map_wireless_device_name);
	/* parse mode string from env var, format "wl0_1:AP,wl0:AP,wl1:AP," */
	char tmp1[MAX_IFACE_NAME_LEN] = {0};
	char *token = NULL;
	char *mode = NULL;
	char *search_str1 = NULL;

	search_str1 = strdup(map_device_modes);
	token = strtok(search_str1, ",");
	while (token != NULL) {
	  mode = NULL;
  	  memset(tmp1, 0, sizeof(tmp1));
	  platform_log(MAP_LIBRARY,LOG_DEBUG, "%s the token is %s\n",__FUNCTION__,token);
	  /* search for current wireless interface name in the token */
	  if(strstr(token,interface)) {
	  	 /* Find : in the token and subsequent chars form mode name*/
		 mode = strchr(token, ':');
		 if(NULL != mode) {
			 strncpy(tmp1, token, (mode-token));
			 /* check for the interface name for exact match */
			 platform_log(MAP_LIBRARY,LOG_DEBUG, "%s the interface is %s mode is %s\n",__FUNCTION__,tmp1, mode+1);
			 if(!strcmp(tmp1, interface)) {
				   if (strcmp(mode+1,"ap") == 0) {
                   	  m->interface_type_data.ieee80211.role = IEEE80211_ROLE_AP;
					  break;
				   }
				   platform_log(MAP_LIBRARY,LOG_DEBUG, "%s 1905 configured if is %s, mode is %s, role is %d\n",__FUNCTION__,interface,mode+1, m->interface_type_data.ieee80211.role );
			 } else {
				platform_log(MAP_LIBRARY,LOG_DEBUG, "%s Interface name not matching %s\n",__FUNCTION__,tmp1);
			 }
		 }
	  }
	  token = strtok(NULL, ",");
	}
	if(NULL != search_str1) {
		free(search_str1);
	}

	/* Parse device name from string, format "wl0:radio_2G, wl1:radio_5G," */
	char tmp2[MAX_WIFI_RADIO_NAME_LEN] = {0};	
	char *devname = NULL;
	char *search_str2 = NULL;

	search_str2 = strdup(map_wireless_device_name);	
	token = strtok(search_str2, ",");
	while (token != NULL) {
	  devname = NULL;
	  memset(tmp2, 0, sizeof(tmp2));
	  platform_log(MAP_LIBRARY,LOG_DEBUG, "%s the token is %s\n", __FUNCTION__,token);
	  /* search for current wireless interface name in the token */
	  if(strstr(token,interface)) {
	  	 /* Find : in the token and subsequent chars form device name*/
		 devname = strchr(token, ':');
		 if(NULL != devname) {
			 strncpy(tmp2, token, (devname-token));
			 /* check for the interface name for exact match */
			 platform_log(MAP_LIBRARY,LOG_DEBUG, "%s the interface name is %s, device name is %s\n", __FUNCTION__,tmp2, devname+1);
			 if(!strcmp(tmp2, interface)) {
                                   strncpy(m->device_name,m->model_name,sizeof(m->device_name));
                                   int len = strnlen(m->device_name,sizeof(m->device_name));
                                   strncat(m->device_name,"-",sizeof(m->device_name)-len);
                                   strncat(m->device_name,devname+1,sizeof(m->device_name)-(len+1));
				   platform_log(MAP_LIBRARY,LOG_DEBUG, "%s 1905 configured if is %s device name is %s\n",__FUNCTION__,interface,m->device_name);
				   break;
			 } else {
				platform_log(MAP_LIBRARY,LOG_DEBUG,"%s Interface name not matching %s\n",__FUNCTION__,tmp2);
			 }
		 }
	  }	 
	  token = strtok(NULL, ",");
	}
	if(NULL != search_str2) {
		free(search_str2);
	}

	return status;
}

static int get_wired_interface_data(struct ubus_context *ctx, const char *interface, struct interfaceInfo *m)
{
	unsigned int id = 0;
	int status = 0;
	if_info_interface_pwr_state_t if_pwr_state_data = {0};

	/* NG-177826: Indicate that there is no neighbor info for lo and eth (which is not the same as 0 neighbors) */
	m->neighbor_mac_addresses_nr = INTERFACE_NEIGHBORS_UNKNOWN;

        /* read data from env vars to fill in */
        strncpy(m->model_number,map_model_number,sizeof(m->model_number));
        strncpy(m->manufacturer_name,map_manufacturer_name,sizeof(m->manufacturer_name));
        strncpy(m->serial_number,map_serial_number,sizeof(m->serial_number));
        strncpy(m->model_name,map_model_name,sizeof(m->model_name));
        strncpy(m->device_name,m->model_name,sizeof(m->device_name));
        int len = strnlen(m->device_name,sizeof(m->device_name));
        strncat(m->device_name,"-",sizeof(m->device_name)-len);
        strncat(m->device_name,interface,(sizeof(m->device_name)- (len+1)));
        platform_log(MAP_LIBRARY,LOG_DEBUG, "%s \t model_name %s \t serial_number %s \t manufacturer_name %s \t device_name %s \n", __FUNCTION__, m->model_name, m->serial_number, m->manufacturer_name, m->device_name);

        m->interface_type = INTERFACE_TYPE_IEEE_802_3AB_GIGABIT_ETHERNET;

	if(0 == strcmp(interface, "lo")) {
		m->power_state = INTERFACE_POWER_STATE_ON; 
		return status;
	}
	
	strncpy(if_pwr_state_data.if_name, interface, sizeof(if_pwr_state_data.if_name));
	
	/* call network.link status */
	if(UBUS_STATUS_OK != ubus_lookup_id(ctx, "network.link", &id)) {
		platform_log(MAP_LIBRARY,LOG_ERR, "%s Failed to get object id for %s\n", __FUNCTION__, "network.link");
		status = -1;
		return status;
	}				

	blob_buf_init(&b, 0);	
	status = ubus_invoke(ctx, id, "status", b.head, get_if_info_power_stae_cb, &if_pwr_state_data, UBUS_TIMEOUT);
	if(UBUS_STATUS_OK != status) {
		platform_log(MAP_LIBRARY,LOG_ERR, "%s Failed to get network link state data \n", __FUNCTION__);
		status = 1;
	}
	blob_buf_free(&b);

	if(status) {
                platform_log(MAP_LIBRARY,LOG_ERR, "%s [%d] Failed to get network.link\n", __FUNCTION__, __LINE__);
                status = -1;
                return status;
        }

	switch(if_pwr_state_data.powerstate)
	{
		case 0x01:
		{
			m->power_state = INTERFACE_POWER_STATE_ON; 
			break;
		}
		case 0x02:
		{
			m->power_state = INTERFACE_POWER_STATE_OFF;
			break;
		}
		default:
                {
			m->power_state =  0xff;
			break;
                }
	}

        /* Get interface MAC address and cache it */
        int fd  = 0;
        struct ifreq s;
        fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
        strncpy(s.ifr_name, interface,sizeof(s.ifr_name));
        if (0 != ioctl(fd, SIOCGIFHWADDR, &s)) {
                platform_log(MAP_LIBRARY,LOG_ERR, "%s Could not obtain MAC address of interface %s\n", __FUNCTION__, interface);
                close(fd);
                status = -1;
                return status;
        }
        close(fd);
        memcpy(m->mac_address, s.ifr_addr.sa_data, 6);

	return status;
}

/* extract special if prefix interfaces */    
static void get_if_net_device_list_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
    struct blob_attr *data1 = NULL, *c1 = NULL; // first level
    struct blob_attr *data2 = NULL, *c2 = NULL; // second level
    struct blob_attr *data3 = NULL, *c3 = NULL; // third level
    int i = 0;

    inout_t* inout = (inout_t*)req->priv;
    if (inout) {
        if_info_if_list_data_t *ifdata = (if_info_if_list_data_t*)inout->outptr;
        const char *spl_if_prefix = (const char*)inout->inptr;
        platform_log(MAP_LIBRARY,LOG_DEBUG, "%s Special if prefix %s\n", __FUNCTION__, spl_if_prefix);
        data1 = blobmsg_data(msg);
        int rem1 = blobmsg_data_len(msg);
    
        __blob_for_each_attr(c1, data1, rem1) {
            data2 = blobmsg_data(c1);
            int rem2 = blobmsg_data_len(c1);
            __blob_for_each_attr(c2, data2, rem2) {
                data3 = blobmsg_data(c2);
                int rem3 = blobmsg_data_len(c2);
                __blob_for_each_attr(c3, data3, rem3) {
                    if(0 == strcmp(blobmsg_name(c3),"interface")) {
                        platform_log(MAP_LIBRARY,LOG_DEBUG, "%s if %s \n", __FUNCTION__, blobmsg_get_string(c3));
                        if(NULL != strstr(blobmsg_get_string(c3), spl_if_prefix)) {
                            platform_log(MAP_LIBRARY,LOG_DEBUG, "%s Special if %s \n", __FUNCTION__, blobmsg_get_string(c3));
                            strncpy(ifdata->if_list[i], blobmsg_get_string(c3), MAX_IFACE_NAME_LEN-1);
                            i++;
                        }
                    }
                }
            }
        }
        ifdata->dynamic_if_cnt = i;
    }
}
 
static int get_interface_list(struct ubus_context *ctx, const char *spl_if_prefix, char interface_list[MAX_INTERFACE_COUNT][MAX_IFACE_NAME_LEN], int *interface_cnt)
{   
    int status = 0;
    int j = 0;
    if_info_if_list_data_t if_list_data = {0};
    inout_t inout = {0};

    inout.inptr = (void*)spl_if_prefix;
    inout.outptr = (void*)&if_list_data;
    if(invoke_ubus_command_ex(ctx, GET_NET_DEVICES, "status", NULL, NULL, get_if_net_device_list_cb, &inout)) {
        /* Copy special interfaces(dynamic) from interface list */
        do {
            platform_log(MAP_LIBRARY,LOG_DEBUG, "%s special interface  %s\n", __FUNCTION__, if_list_data.if_list[j]);
            strncpy(interface_list[j], if_list_data.if_list[j], MAX_IFACE_NAME_LEN-1);
            j++;            
        } while((if_list_data.if_list[j][0] != '\0') && (j < MAX_INTERFACE_COUNT));
        if(NULL != interface_cnt) {
            *interface_cnt = j;
            platform_log(MAP_LIBRARY,LOG_DEBUG, "%s special interface  count %d \n", __FUNCTION__, j);
        }
    }else {
        platform_log(MAP_LIBRARY,LOG_ERR, "%s ubus_invoke Failed for %s get\n", __FUNCTION__, GET_NET_DEVICES);
        status = -1;
    }

    return status;  
}

int getInterfaceIndex(const char *ifname)
{
        struct ifreq ifr;
        int sockfd;
        int ifindex;

        if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
                return -1;
        }

        strncpy(ifr.ifr_name, ifname, IFACE_NAME_LEN);
        ifr.ifr_name[IFACE_NAME_LEN-1] = '\0';
        if (ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1) {
        close(sockfd);
        return -1;
        }

        ifindex = ifr.ifr_ifindex;

        close(sockfd);
        return ifindex;
}

int ifaceSocketUpdate(const char* interface_name)
{
        int send_socket_1905 = 0;
        int send_socket_lldp = 0;
        int if_index = 0;
        int status = 0;
        int i = 0;

        /* acquire lock and do the look up */
        pthread_rwlock_wrlock(&map1905if_info_rw_lock);
        for(i = 0; i < MAX_INTERFACE_COUNT; i++)
        {
                if(!strcmp(interface_name, map1905if_info_interfaces[i].if_name))
                {
                        break;
                }
        }

        if(i >= MAX_INTERFACE_COUNT)
        {       /* release the lock */
                pthread_rwlock_unlock(&map1905if_info_rw_lock);
                platform_log(MAP_LIBRARY,LOG_ERR, "%s [%d] Interface not found in the cache\n", __FUNCTION__, __LINE__);
                status = -1;
                return status;
        }

        if(map1905if_info_interfaces[i].is_new_interface == 1)
        {
            platform_log(MAP_LIBRARY,LOG_DEBUG, "%s [%d] Initialize socket fds to -1 for interface %s\n", __FUNCTION__, __LINE__, interface_name);

            map1905if_info_interfaces[i].if_info.interface_index = -1;
            map1905if_info_interfaces[i].if_info.send_socket_1905_fd = -1;
            map1905if_info_interfaces[i].if_info.send_socket_lldp_fd = -1;
            map1905if_info_interfaces[i].is_new_interface = 0;
        }

        if(map1905if_info_interfaces[i].if_info.power_state == INTERFACE_POWER_STATE_OFF)
        {
            platform_log(MAP_LIBRARY,LOG_DEBUG, "%s [%d] Interface %s power state off, closing socket fds if any\n", __FUNCTION__, __LINE__, interface_name);

            if(map1905if_info_interfaces[i].if_info.interface_index != -1) {
                map1905if_info_interfaces[i].if_info.interface_index = -1;
            }
            if(map1905if_info_interfaces[i].if_info.send_socket_1905_fd != -1) {
                close(map1905if_info_interfaces[i].if_info.send_socket_1905_fd);
                map1905if_info_interfaces[i].if_info.send_socket_1905_fd = -1;
            }
            if(map1905if_info_interfaces[i].if_info.send_socket_lldp_fd != -1) {
                close(map1905if_info_interfaces[i].if_info.send_socket_lldp_fd);
                map1905if_info_interfaces[i].if_info.send_socket_lldp_fd = -1;
            }
        }

        else if(map1905if_info_interfaces[i].if_info.power_state == INTERFACE_POWER_STATE_ON)
        {
            platform_log(MAP_LIBRARY,LOG_DEBUG, "%s [%d] Interface %s power state on, flushing old sockets and creating new sockets\n", __FUNCTION__, __LINE__, interface_name);

            if(map1905if_info_interfaces[i].if_info.interface_index != -1) {
                map1905if_info_interfaces[i].if_info.interface_index = -1;
            }
            if(map1905if_info_interfaces[i].if_info.send_socket_1905_fd != -1) {
                close(map1905if_info_interfaces[i].if_info.send_socket_1905_fd);
                map1905if_info_interfaces[i].if_info.send_socket_1905_fd = -1;
            }
            if(map1905if_info_interfaces[i].if_info.send_socket_lldp_fd != -1) {
                close(map1905if_info_interfaces[i].if_info.send_socket_lldp_fd);
                map1905if_info_interfaces[i].if_info.send_socket_lldp_fd = -1;
            }

            // Retrieve ethernet interface index
            //
            platform_log(MAP_LIBRARY,LOG_DEBUG, "%s [%d] Retrieving interface index for interface %s\n", __FUNCTION__, __LINE__, interface_name);
            if_index = getInterfaceIndex(interface_name);
            if (-1 == if_index)
            {
                platform_log(MAP_LIBRARY,LOG_ERR, "%s [%d] Failed to get interface index for %s\n", __FUNCTION__, __LINE__, interface_name);
                pthread_rwlock_unlock(&map1905if_info_rw_lock);
                status = -1;
                return status;
            }
            // Open RAW socket for ETHERTYPE_1905 protocol
            //
            platform_log(MAP_LIBRARY,LOG_DEBUG, "%s [%d] Opening RAW socket for ETHERTYPE_1905 protocol\n", __FUNCTION__, __LINE__);
            send_socket_1905 = socket(AF_PACKET, SOCK_RAW, htons(ETHERTYPE_1905));
            if (-1 == send_socket_1905)
            {
                platform_log(MAP_LIBRARY,LOG_ERR, "%s [%d] socket('%s') returned with errno=%d (%s) while opening a RAW socket\n", __FUNCTION__, __LINE__, interface_name, errno, strerror(errno));
                pthread_rwlock_unlock(&map1905if_info_rw_lock);
                status = -1;
                return status;
            }
            // Open RAW socket for ETHERTYPE_LLDP protocol
            //
            platform_log(MAP_LIBRARY,LOG_DEBUG, "%s [%d] Opening RAW socket for ETHERTYPE_LLDP protocol\n", __FUNCTION__, __LINE__);
            send_socket_lldp = socket(AF_PACKET, SOCK_RAW, htons(ETHERTYPE_LLDP));
            if (-1 == send_socket_lldp)
            {
                platform_log(MAP_LIBRARY,LOG_ERR, "%s [%d] socket('%s') returned with errno=%d (%s) while opening a RAW socket\n", __FUNCTION__, __LINE__, interface_name, errno, strerror(errno));
                pthread_rwlock_unlock(&map1905if_info_rw_lock);
                close(send_socket_1905);
                status = -1;
                return status;
            }
            if(status != -1)
            {
                platform_log(MAP_LIBRARY,LOG_DEBUG, "%s [%d] Initialize socket fds to -1 for interface %s\n", __FUNCTION__, __LINE__, interface_name);

                map1905if_info_interfaces[i].if_info.interface_index = if_index;
                map1905if_info_interfaces[i].if_info.send_socket_1905_fd = send_socket_1905;
                map1905if_info_interfaces[i].if_info.send_socket_lldp_fd = send_socket_lldp;
            }
        }

        /* release the read lock */
        pthread_rwlock_unlock(&map1905if_info_rw_lock);

        return status;
}

int platform_if_info_init()
{
    int j =0;   
    int status = 0;
    struct ubus_context *ctx = NULL;
    struct interfaceInfo m = {0};
    char ap_no[MAX_AP_NAME_LEN] = {0};
    char radio_name[MAX_RADIO_NAME_LEN] = {0};  
    int dynamic_if_cnt = 0;
    char *saveptr = NULL;   
    char* token = NULL; 
    char interfaces[MAX_INTERFACE_COUNT][MAX_IFACE_NAME_LEN] = {0};
    char special_if_prefix[MAX_IFACE_NAME_LEN] = {'\0'};
    char interface_name[MAX_UCI_STRING] = {0};

    platform_log(MAP_LIBRARY,LOG_DEBUG, " %s env vars 1905 INTEFACES %s\n",__FUNCTION__, map_interfaces);
    
    if(!onetime_data_collected)
    {
        /* Do UBUS connect */       
        ctx = ubus_connect(NULL);
        if (NULL == ctx) {
            platform_log(MAP_LIBRARY,LOG_ERR,"%s Failed to connect to ubus\n", __FUNCTION__);
            status = -1;
            return status;
        }
        /* Parse 1905 interface names and wds interfaces via ubus if wds configured */
        token = strtok_r(map_interfaces, ",", &saveptr);
        while (token != NULL) {
            strncpy(&interfaces[j][0], token, MAX_IFACE_NAME_LEN-1);
            platform_log(MAP_LIBRARY,LOG_DEBUG,"%s iterating for %s\n", __FUNCTION__, interfaces[j]);            
            char *special_if_char = NULL;
            
            /* check for special dynamic interface support configuration */
            special_if_char = strchr(interfaces[j], '*');
            if(NULL != special_if_char) {               
                char special_if_list[MAX_INTERFACE_COUNT][MAX_IFACE_NAME_LEN] = {'\0'};
                *special_if_char = '\0';
                
                strncpy(special_if_prefix, interfaces[j], MAX_IFACE_NAME_LEN-1);
                platform_log(MAP_LIBRARY,LOG_DEBUG, " %s special interface name prefix %s!!\n", __FUNCTION__, interfaces[j]);

                /* get all dynamic interfaces, update interface list */
                status = get_interface_list(ctx, (const char*)special_if_prefix, special_if_list, &dynamic_if_cnt);
                for(int i = 0; i < dynamic_if_cnt && (j+i) < MAX_INTERFACE_COUNT; i++) {
                    /* overwrite special i/f name config with dynamic interface names */
                    strncpy(&interfaces[j+i][0], &special_if_list[i][0], MAX_IFACE_NAME_LEN-1);
                    platform_log(MAP_LIBRARY,LOG_DEBUG, " %s special interface name  %s\n", __FUNCTION__, interfaces[j+i]);
                }

                /* special dynamic interface configured, but no wds interfaces exist*/
                if(0 == dynamic_if_cnt) {
                    platform_log(MAP_LIBRARY,LOG_ERR, " %s special interface config enabled, prefix %s, but non-existent!!\n", __FUNCTION__, special_if_prefix);
                    memset(&interfaces[j][0], '\0', MAX_IFACE_NAME_LEN);
                    j--;
                } 
            }
            token = strtok_r(NULL, ",", &saveptr);
            j++;
        }

        /* collect if data and cache it */
        if(!status) {
            j = 0;
            while(interfaces[j][0] != '\0') {
                memset(&m, 0, sizeof(m));
                memset(ap_no, 0, sizeof(ap_no));
                memset(radio_name, 0, sizeof(radio_name));
                
                strncpy(interface_name, interfaces[j], sizeof(interface_name)-1);
                if('\0' != interface_name[0]) {
                    if(NULL != strstr(interface_name, "wl"))  {
                        status = get_wireless_interface_data(ctx, interface_name, &m, ap_no, radio_name); 
                    } else if(('\0' != special_if_prefix[0]) && (NULL != strstr(interface_name, special_if_prefix))) {
                        status = platform_if_info_wds_if_info_update(ctx, interface_name, NULL, NULL);
                        platform_log(MAP_LIBRARY,LOG_DEBUG, " %s collected data for %s \n", __FUNCTION__,interface_name);                
                    } else {
                        status = get_wired_interface_data(ctx, interface_name, &m);
                    }
                    if(status) {
                        platform_log(MAP_LIBRARY,LOG_ERR, " %s failed in getinterface info of %s!!\n", __FUNCTION__, interface_name);
                        break;
                    }

                    if(map1905if_info_interfaces[j].if_name[0] == '\0') {
                        strncpy(map1905if_info_interfaces[j].ap_name, ap_no, sizeof(map1905if_info_interfaces[j].ap_name)-1);
                        strncpy(map1905if_info_interfaces[j].radio_name, radio_name, sizeof(map1905if_info_interfaces[j].radio_name)-1);
                        strncpy(map1905if_info_interfaces[j].if_name, interface_name, sizeof(map1905if_info_interfaces[j].if_name)-1);
                        map1905if_info_interfaces[j].is_new_interface = 1;
                        memcpy(&map1905if_info_interfaces[j].if_info, &m, sizeof(m));
                        platform_log(MAP_LIBRARY,LOG_DEBUG, " %s cached data for %s \n", __FUNCTION__,interface_name);
                    }               
                }else {
                    platform_log(MAP_LIBRARY,LOG_DEBUG, " %s invalid interface name at slot %d in platform cache\n", __FUNCTION__,j);
                }           

                if(-1 == ifaceSocketUpdate(interface_name))
                {
                    platform_log(MAP_LIBRARY,LOG_ERR,"%s [%d] Failed to update socket for interface %s\n",__FUNCTION__, __LINE__, interface_name);
                    status = -1;
                }

                j++;            
            }
        }
        ubus_free(ctx);
        onetime_data_collected++;
    } else {
        platform_log(MAP_LIBRARY,LOG_ERR, " %s Already if info data collected!!\n", __FUNCTION__);
        status = -1;
    }
    return status;

}

int platform_auth_check(char *if_name,uint16_t *auth_type)
{
    int i;
    int status=0;
    if(if_name == NULL || '\0' == if_name[0] || auth_type == NULL) {
        platform_log(MAP_LIBRARY,LOG_ERR, " %s Invalid i/p params\n", __FUNCTION__);
        return status;
    }
    /* acquire lock and do the look up */
    pthread_rwlock_wrlock(&map1905if_info_rw_lock); 
    for(i = 0; i < MAX_INTERFACE_COUNT; i++) 
    {
      if(!strncmp(if_name, map1905if_info_interfaces[i].if_name,MAX_IFACE_NAME_LEN))
      {
        break;
      }   
    }
    if(i >= MAX_INTERFACE_COUNT)
    { /* release the lock */
      pthread_rwlock_unlock(&map1905if_info_rw_lock); 
      platform_log(MAP_LIBRARY,LOG_ERR, "%s Interface not found in the cache\n", __FUNCTION__);
      return status;
    }
    if(map1905if_info_interfaces[i].if_info.interface_type_data.ieee80211.authentication_mode != *auth_type)
    {
        map1905if_info_interfaces[i].if_info.interface_type_data.ieee80211.authentication_mode = *auth_type;
        status = 1;
    }
        /* release the read lock */
    pthread_rwlock_unlock(&map1905if_info_rw_lock);
    return status; 
}

int platform_if_info_get(const char *name, void *data, void *ctx)
{
	int status = 0;
	int i;
	(void)ctx;

	struct interfaceInfo *map1905_if_info = (struct interfaceInfo *) data;

	if((NULL == map1905_if_info ) || ('\0' == name[0])) {
		platform_log(MAP_LIBRARY,LOG_ERR, " %s Invalid i/p params\n", __FUNCTION__);
		status = -1;
		return status;
	}
	/* acquire lock and do the look up */
	pthread_rwlock_rdlock(&map1905if_info_rw_lock);	
	for(i = 0; i < MAX_INTERFACE_COUNT; i++) 
	{
		if(!strcmp(name, map1905if_info_interfaces[i].if_name))
		{
			break;
		}		
	}

	if(i >= MAX_INTERFACE_COUNT)
	{	/* release the lock */
		pthread_rwlock_unlock(&map1905if_info_rw_lock);	
		platform_log(MAP_LIBRARY,LOG_ERR, "%s Interface %s not found in the cache\n", __FUNCTION__,name);
		status = -1;
		return status;
	}
 	memcpy(map1905_if_info, &map1905if_info_interfaces[i].if_info, sizeof(struct interfaceInfo));	
	/* release the read lock */
	pthread_rwlock_unlock(&map1905if_info_rw_lock);

	return status;
}

int platform_if_info_neighbor_list_update(struct ubus_context *ctx, const char *ap_no)
{	
	int status = 0; 
	int i;
	if_info_wireless_neighbor_station_t ap_neighbor_data = {0};

	platform_log(MAP_LIBRARY,LOG_DEBUG,"%s ",__FUNCTION__);

	if((NULL == ctx ) || ('\0' == ap_no[0])) {
		platform_log(MAP_LIBRARY,LOG_ERR," %s Invalid i/p params\n", __FUNCTION__);
		status = -1;
		return status;
	}

	/* Get the data */
	status = get_wireless_if_neighbor_sta_data(ctx, ap_no, &ap_neighbor_data);
	if(UBUS_STATUS_OK != status) {
		platform_log(MAP_LIBRARY,LOG_ERR, "%s Failed to get neighbor sta data \n", __FUNCTION__);
		status = -1;
		return status;
	}
	
	/* acquire the rw lock and do llok up */
	pthread_rwlock_wrlock(&map1905if_info_rw_lock);

	for(i = 0; i < MAX_INTERFACE_COUNT; i++) 
	{
		if(!strcmp(ap_no, map1905if_info_interfaces[i].ap_name))
		{
			break;
		}		
	}

	if(i >= MAX_INTERFACE_COUNT)
	{
		/* release the lock */
		pthread_rwlock_unlock(&map1905if_info_rw_lock);	
		platform_log(MAP_LIBRARY,LOG_ERR, "%s Interface not found in the cache\n", __FUNCTION__);
		status = -1;
		return status;
	}	
	/* clear old data */
	if(map1905if_info_interfaces[i].if_info.neighbor_mac_addresses_nr > 0) {
		free(map1905if_info_interfaces[i].if_info.neighbor_mac_addresses);
		map1905if_info_interfaces[i].if_info.neighbor_mac_addresses = NULL;
		map1905if_info_interfaces[i].if_info.neighbor_mac_addresses_nr = 0;
	}
	/* update the latest values */	
	if(ap_neighbor_data.neighbor_count > 0) {
		map1905if_info_interfaces[i].if_info.neighbor_mac_addresses_nr = ap_neighbor_data.neighbor_count;
		map1905if_info_interfaces[i].if_info.neighbor_mac_addresses = (uint8_t (*)[6]) calloc(ap_neighbor_data.neighbor_count, sizeof(uint8_t[6]));
		memcpy(map1905if_info_interfaces[i].if_info.neighbor_mac_addresses, ap_neighbor_data.neighbor_sta_mac, ap_neighbor_data.neighbor_count*sizeof(uint8_t[6]));
	}
	/* release the lock */
	pthread_rwlock_unlock(&map1905if_info_rw_lock);	
	
	return status;
}

int platform_if_info_wireless_if_state_update(struct ubus_context *ctx, const char *interface, uint8_t *bssid)
{
	int status = 0; 
	int i;
	if_info_wireless_ssid_t ssid_data = {0};

	if((NULL == ctx ) || ('\0' == interface[0])) {
		platform_log(MAP_LIBRARY,LOG_ERR," %s Invalid i/p params\n", __FUNCTION__);
		status = -1;
		return status;
	}
	/* Get updated data */
	status = get_wireless_if_ssid_data(ctx, interface, &ssid_data);
	if(UBUS_STATUS_OK != status) {
		platform_log(MAP_LIBRARY,LOG_ERR, "%s Failed to get ssid data \n", __FUNCTION__);
		status = -1;
		return status;
	}
	memcpy(bssid,ssid_data.bssid,sizeof(ssid_data.bssid));

	pthread_rwlock_wrlock(&map1905if_info_rw_lock);		
	for(i = 0; i < MAX_INTERFACE_COUNT; i++) 
	{
		if(!strcmp(interface, map1905if_info_interfaces[i].if_name))
		{
			break;
		}		
	}

	if(i >= MAX_INTERFACE_COUNT)
	{
		pthread_rwlock_unlock(&map1905if_info_rw_lock);
		platform_log(MAP_LIBRARY,LOG_ERR, "%s Interface not found in the cache\n", __FUNCTION__);
		status = -1;
		return status;
	}	

	if((1 == ssid_data.admin_state) && (1 == ssid_data.oper_state)) {
		map1905if_info_interfaces[i].if_info.power_state = INTERFACE_POWER_STATE_ON;
	} else {
		map1905if_info_interfaces[i].if_info.power_state = INTERFACE_POWER_STATE_OFF;
	}
	strncpy(map1905if_info_interfaces[i].radio_name, ssid_data.radio_name, sizeof(map1905if_info_interfaces[i].radio_name));
	strncpy(map1905if_info_interfaces[i].if_info.interface_type_data.ieee80211.ssid,ssid_data.ssid, sizeof(map1905if_info_interfaces[i].if_info.interface_type_data.ieee80211.ssid));
	memcpy(map1905if_info_interfaces[i].if_info.interface_type_data.ieee80211.bssid,ssid_data.bssid, sizeof(ssid_data.bssid));
	memcpy(map1905if_info_interfaces[i].if_info.mac_address, ssid_data.mac_addr, sizeof(ssid_data.mac_addr));
	pthread_rwlock_unlock(&map1905if_info_rw_lock);	

        if(-1 == ifaceSocketUpdate(interface))
        {
            platform_log(MAP_LIBRARY,LOG_ERR,"%s [%d] Failed to update socket for interface %s\n",__FUNCTION__, __LINE__, interface);
            status = -1;
        }
	
	return status;
}

int platform_if_info_wired_if_state_update(struct ubus_context *ctx, const char *interface)
{
	int status = 0; 
	int i;
	struct interfaceInfo m = {0};

	if((NULL == ctx ) || ('\0' == interface[0])) {
		platform_log(MAP_LIBRARY,LOG_ERR," %s Invalid i/p params\n", __FUNCTION__);
		status = -1;
		return status;
	}

	/* get updated data */
	get_wired_interface_data(ctx, interface, &m);

	pthread_rwlock_wrlock(&map1905if_info_rw_lock);
	for(i = 0; i < MAX_INTERFACE_COUNT; i++) 
	{
		if(!strcmp(interface, map1905if_info_interfaces[i].if_name))
		{
			break;
		}		
	}
	if(i >= MAX_INTERFACE_COUNT)
	{
		pthread_rwlock_unlock(&map1905if_info_rw_lock);
		platform_log(MAP_LIBRARY,LOG_ERR, "%s Interface %s not found in the cache\n", __FUNCTION__,interface);
		status = -1;
		return status;
	}
	/* Update power state */
	map1905if_info_interfaces[i].if_info.power_state = m.power_state;

	pthread_rwlock_unlock(&map1905if_info_rw_lock);

        if(-1 == ifaceSocketUpdate(interface))
        {
            platform_log(MAP_LIBRARY,LOG_ERR,"%s [%d] Failed to update socket for interface %s\n",__FUNCTION__, __LINE__, interface);
            status = -1;
        }
	
	return status;
}

int platform_if_info_wds_if_info_update(struct ubus_context *ctx, const char *interface, int8_t *is_new_wds, char *if_state)
{   
    int status = 0; 
    int i;
    unsigned int id = 0;
    struct interfaceInfo m = {0};
    if_info_interface_pwr_state_t if_pwr_state_data = {0};

    if((NULL == ctx) || (NULL == interface)){
        platform_log(MAP_LIBRARY,LOG_ERR, "%s Invalid i/p\n", __FUNCTION__);
        return -1;
    }
    /* set it as existing interface, later update if new interface */
    if(NULL != is_new_wds) {
        *is_new_wds = 0;
    }

    pthread_rwlock_wrlock(&map1905if_info_rw_lock);
    /* if wds interface info cached, update power state */
    for(i = 0; i < MAX_INTERFACE_COUNT; i++) 
    {
        if(!strcmp(interface, map1905if_info_interfaces[i].if_name)) {

            if (if_state != NULL) {
                 if(0 == strcmp(if_state,"up")) {
                     map1905if_info_interfaces[i].if_info.power_state = INTERFACE_POWER_STATE_ON;
                 } else if(0 == strcmp(if_state ,"down")){
                     map1905if_info_interfaces[i].if_info.power_state = INTERFACE_POWER_STATE_OFF;
                 } else {
                     map1905if_info_interfaces[i].if_info.power_state = 0xff;
                 }
            }
            break;
        }
    }
    pthread_rwlock_unlock(&map1905if_info_rw_lock);
    
    /**
    * Note: expect new wds interface creation notified as link down then up event, 
    * cache data only for first link up.
    **/
    if(i >= MAX_INTERFACE_COUNT) {      
        /* if we are here, new wds interface is created, cache interface info for it */
        char ap_no[MAX_AP_NAME_LEN] = {0};
        char radio_name[MAX_RADIO_NAME_LEN] = {0};

        //Find underlying interface, assumption here is, it starts with "wl"
        char underlying_if[MAX_IFACE_NAME_LEN] = {'\0'};        
        platform_get_wds_underlying_if(interface, &underlying_if[0], sizeof(underlying_if));
        if('\0' == underlying_if[0]) {
            platform_log(MAP_LIBRARY,LOG_ERR, "%s Undelying interface name not found \n", __FUNCTION__);
            status = -1;
            return status;
        }
        
        platform_log(MAP_LIBRARY,LOG_DEBUG, "%s WDS Interface not in cache, create it, underlying if %s\n", __FUNCTION__, underlying_if);
        /*get data for underlying wifi interface */
        status = get_wireless_interface_data(ctx, underlying_if, &m, ap_no, radio_name);
        platform_log(MAP_LIBRARY,LOG_DEBUG, "%s power state %d \n", __FUNCTION__, m.power_state);

        pthread_rwlock_wrlock(&map1905if_info_rw_lock);
        for(i = 0; i <MAX_INTERFACE_COUNT; i++) {
            if(map1905if_info_interfaces[i].if_name[0] == '\0') {
                strncpy(map1905if_info_interfaces[i].ap_name, ap_no, sizeof(map1905if_info_interfaces[i].ap_name));
                strncpy(map1905if_info_interfaces[i].radio_name, radio_name, sizeof(map1905if_info_interfaces[i].radio_name));
                strncpy(map1905if_info_interfaces[i].if_name, interface, sizeof(map1905if_info_interfaces[i].if_name));
                map1905if_info_interfaces[i].is_new_interface = 1;
                memcpy(&map1905if_info_interfaces[i].if_info, &m, sizeof(m));                                       
                if(NULL != is_new_wds) {
                    *is_new_wds = 1;                                                
                }
                platform_log(MAP_LIBRARY,LOG_DEBUG, "%s successfully cached wds i/f data at %d\n", __FUNCTION__, i);
                break;  
            } else {
                platform_log(MAP_LIBRARY,LOG_DEBUG, "%s map1905if_info_interfaces[%d], ifname %s \n", __FUNCTION__, i, map1905if_info_interfaces[i].if_name);
            }
        }

        strncpy(if_pwr_state_data.if_name, interface, sizeof(if_pwr_state_data.if_name));

        /* call network.link status */
        if(UBUS_STATUS_OK != ubus_lookup_id(ctx, "network.link", &id)) {
                platform_log(MAP_LIBRARY,LOG_ERR, "%s Failed to get object id for %s\n", __FUNCTION__, "network.link");
                pthread_rwlock_unlock(&map1905if_info_rw_lock);
                status = -1;
                return status;
        }

        blob_buf_init(&b, 0);
        status = ubus_invoke(ctx, id, "status", b.head, get_if_info_power_stae_cb, &if_pwr_state_data, UBUS_TIMEOUT);
        if(UBUS_STATUS_OK != status) {
                platform_log(MAP_LIBRARY,LOG_ERR, "%s Failed to get network link state data \n", __FUNCTION__);
                status = -1;
        }
        blob_buf_free(&b);

        if(!status) {
            switch(if_pwr_state_data.powerstate)
            {
                case 0x01:
                {
                    map1905if_info_interfaces[i].if_info.power_state = INTERFACE_POWER_STATE_ON;
                    break;
                }
                case 0x02:
                {
                    map1905if_info_interfaces[i].if_info.power_state = INTERFACE_POWER_STATE_OFF;
                    break;
                }
                default:
                {
                    map1905if_info_interfaces[i].if_info.power_state =  0xff;
                    break;
                }
            }
        }

        pthread_rwlock_unlock(&map1905if_info_rw_lock);
    }

    if(-1 == ifaceSocketUpdate(interface))
    {
        platform_log(MAP_LIBRARY,LOG_ERR,"%s [%d] Failed to update socket for interface %s\n",__FUNCTION__, __LINE__, interface);
        status = -1;
    }

    /* 
     * Remove the interface from cache list, if ist state is down
     */
    pthread_rwlock_wrlock(&map1905if_info_rw_lock);
    if ((i < MAX_INTERFACE_COUNT) && 
       ((map1905if_info_interfaces[i].if_info.power_state == INTERFACE_POWER_STATE_OFF) || 
        (map1905if_info_interfaces[i].if_info.power_state ==  0xff))) {  
        int j = 0;
        int k = i;
    
        platform_log(MAP_LIBRARY,LOG_DEBUG, "%s:%d Removing interface %s of state %d\n", __FUNCTION__, __LINE__, map1905if_info_interfaces[i].if_name, map1905if_info_interfaces[i].if_info.power_state);
        for (j = k+1; j<MAX_INTERFACE_COUNT; j++, k++) {
            memcpy(&map1905if_info_interfaces[k], &map1905if_info_interfaces[j], sizeof(map1905if_info_interfaces[k]));
        }
    
        /* 
         * If last index of map1905if_info_interfaces[i], needs to be removed,
         */ 
        if (j >= MAX_INTERFACE_COUNT) {
            map1905if_info_interfaces[MAX_INTERFACE_COUNT-1].if_info.interface_index = -1;
            map1905if_info_interfaces[MAX_INTERFACE_COUNT-1].if_info.send_socket_1905_fd = -1;
            map1905if_info_interfaces[MAX_INTERFACE_COUNT-1].if_info.send_socket_lldp_fd = -1;
            map1905if_info_interfaces[MAX_INTERFACE_COUNT-1].is_new_interface = 0;
            map1905if_info_interfaces[MAX_INTERFACE_COUNT-1].if_name[0] = '\0';
        }
    }
    pthread_rwlock_unlock(&map1905if_info_rw_lock);

    if(i >= MAX_INTERFACE_COUNT) {  
        platform_log(MAP_LIBRARY,LOG_ERR, "%s No space to cache wds interface %s\n", __FUNCTION__, interface);
        status = -1;
    }
    
    return status;  
}


#define IS_INTERFACE_WIFI(interface) ((interface >= INTERFACE_TYPE_IEEE_802_11B_2_4_GHZ) && \
									(interface <= INTERFACE_TYPE_IEEE_802_11AF_GHZ ))


static void get_active_and_configured_ssids(ssid_info_list_t* list)
{
	list->count = 0;
	char* interfaces = map_agent_bsslist;

	if (interfaces)
	{
		pthread_rwlock_rdlock(&map1905if_info_rw_lock);	
		for(int i = 0; i < MAX_INTERFACE_COUNT; i++) 
		{
			map1905if_interface_info_t* ifinfo;
			if (map1905if_info_interfaces[i].if_name[0] == '\0')
				continue;
			ifinfo = &map1905if_info_interfaces[i];
			if (IS_INTERFACE_WIFI(ifinfo->if_info.interface_type)) {
				if (is_string_in_line(interfaces, ifinfo->if_name))
				{
					wireless_ssid_info_t *ssidinfo = &list->infolist[list->count];
					memset(ssidinfo, 0, sizeof(*ssidinfo));
					
					if (INTERFACE_POWER_STATE_ON == ifinfo->if_info.power_state)
					{
						get_mac_string(ifinfo->if_info.interface_type_data.ieee80211.bssid, 
										ssidinfo->bssid);

						strncpy(ssidinfo->radio_name, ifinfo->radio_name, RADIO_NAME_LEN);
						ssidinfo->radio_name[RADIO_NAME_LEN-1] = '\0';

						strncpy(ssidinfo->ap_name, ifinfo->ap_name, MAX_AP_NAME_LEN);
						ssidinfo->radio_name[MAX_AP_NAME_LEN - 1] = '\0';

						strncpy(ssidinfo->interface_name, ifinfo->if_name, MAX_IFACE_NAME_LEN);
						ssidinfo->interface_name[MAX_IFACE_NAME_LEN-1] = '\0';

						list->count++; // increment the index only if conditions met; else these will not be counted
					}
				}
			}
		}
		pthread_rwlock_unlock(&map1905if_info_rw_lock);
	}
	platform_log(MAP_LIBRARY,LOG_DEBUG, "get_active_and_configured_ssids: %d\n", list->count);
}


static void get_configured_ssids(void* ctx, ssid_list_t* list)
{
	list->count = 0;
	char* mapifaces = map_agent_bsslist;
	struct uci_package *wireless = NULL;
	struct blob_attr *ssidinfo = NULL;
	struct uci_context *uci = uci_alloc_context();

	if (uci) {
		if (uci_load(uci, "wireless", &wireless)) {
			platform_log(MAP_LIBRARY,LOG_ERR, "failed to get uci info\n");
			uci_free_context(uci);
			return;
		}
	}

	if (invoke_ubus_command(ctx, "wireless.ssid", "get", NULL, &ssidinfo)) {
		struct blob_attr *data1 = NULL, *c1 = NULL; // first level
		struct blob_attr *data2 = NULL, *c2 = NULL; // second level
		data1 = blobmsg_data(ssidinfo);
		int rem1 = blobmsg_data_len(ssidinfo);

		__blob_for_each_attr(c1, data1, rem1)
		{
			data2 = blobmsg_data(c1);
			int rem2 = blobmsg_data_len(c1);

			ssid_info_t* info = &list->infolist[list->count];
			memset(info, 0, sizeof(ssid_info_t));

			__blob_for_each_attr(c2, data2, rem2)
			{
				if(0 == strcmp(blobmsg_name(c2),"radio")) {
					strncpy(info->radio_name, blobmsg_get_string(c2), sizeof(info->radio_name));
					info->radio_name[RADIO_NAME_LEN-1] = '\0';
				}
				else if(0 == strcmp(blobmsg_name(c2),"bssid")) {
					strncpy(info->bssid, blobmsg_get_string(c2), sizeof(info->interface_name));
					info->bssid[MAX_MAC_STRING_LEN-1] = '\0';
				}
				else if(0 == strcmp(blobmsg_name(c2),"ssid")) {
					strncpy(info->ssid, blobmsg_get_string(c2), sizeof(info->ssid));
					info->bssid[MAX_MAC_STRING_LEN-1] = '\0';
				}
				else if(0 == strcmp(blobmsg_name(c2),"admin_state"))
					info->admin_state = blobmsg_get_u32(c2);
				else if(0 == strcmp(blobmsg_name(c2),"oper_state"))
					info->oper_state= blobmsg_get_u32(c2);
			}
			if (!is_string_in_line(mapifaces, (char*)blobmsg_name(c1))) // skip ssids not in map config
				continue;

			strncpy(info->interface_name, blobmsg_name(c1), sizeof(info->interface_name));

			// fill ap name using the wireless uci information
			struct uci_element *e;
			uci_foreach_element(&wireless->sections, e) {
				struct uci_section *s = uci_to_section(e);
				if (s) {
					const char *interface = uci_lookup_option_string(uci, s, "iface");
					if (interface && (strncmp(interface, info->interface_name, sizeof(info->interface_name)) == 0)) {
						strncpy(info->ap_name, e->name, sizeof(info->ap_name));
						info->ap_name[sizeof(info->ap_name) - 1] = '\0';
					}
				}
			}

			list->count++;
		}
		free(ssidinfo);
	}
	uci_unload(uci, wireless);
	uci_free_context(uci);

	platform_log(MAP_LIBRARY,LOG_DEBUG, "get_configured_ssids: %d\n", list->count);
}


static void get_station_info_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	inout_t* inout = (inout_t*)req->priv;
	if (inout) {
		ssid_info_list_t* list = (ssid_info_list_t*)inout->inptr;
		cum_stats_t* cum_sta = (cum_stats_t*)inout->outptr;
	map_sta_stats_t* sta_list = (map_sta_stats_t*)cum_sta->cum_stats;

		struct blob_attr *c1 = NULL;
		struct blob_attr *data1 = blobmsg_data(msg);
		int rem1 = blobmsg_len(msg);
		int mindex = 0;

		__blob_for_each_attr(c1, data1, rem1)
		{
			int infoindex = 0;
			
			while (infoindex < list->count) {
				// check whether ap name available in infolist; if not found skip
				if (strncmp((char*)blobmsg_name(c1), list->infolist[infoindex].ap_name, MAX_AP_NAME_LEN) == 0)
					break;
				infoindex++;
			}
			
			if (infoindex == list->count) // ap name is not avilable in infolist; find next
				continue;

			struct blob_attr *c2 = NULL;
			struct blob_attr *data2 = blobmsg_data(c1);
			int rem2 = blobmsg_data_len(c1);
			__blob_for_each_attr(c2, data2, rem2)
			{
				struct blob_attr *c3 = NULL;
				struct blob_attr *data3 = blobmsg_data(c2);
				int rem3 = blobmsg_len(c2);

				memset(&sta_list[mindex], 0, sizeof(sta_list[mindex]));
				
				__blob_for_each_attr(c3, data3, rem3)
				{
					if (strcmp(blobmsg_name(c3), "tx_packets") == 0)
						sta_list[mindex].metrics.traffic.txpkts = blobmsg_get_u64(c3);
					else if (strcmp(blobmsg_name(c3), "rx_packets") == 0)
						sta_list[mindex].metrics.traffic.rxpkts = blobmsg_get_u64(c3);
					else if (strcmp(blobmsg_name(c3), "tx_bytes") == 0)
						sta_list[mindex].metrics.traffic.txbytes= blobmsg_get_u64(c3);
					else if (strcmp(blobmsg_name(c3), "rx_bytes") == 0)
						sta_list[mindex].metrics.traffic.rxbytes= blobmsg_get_u64(c3);
					else if (strcmp(blobmsg_name(c3), "tx_phy_rate") == 0)
						sta_list[mindex].metrics.link.dl_mac_datarate = blobmsg_get_u32(c3)/1000;
					else if (strcmp(blobmsg_name(c3), "rx_phy_rate") == 0)
						sta_list[mindex].metrics.link.ul_mac_datarate = blobmsg_get_u32(c3)/1000;
					else if (strcmp(blobmsg_name(c3), "rssi") == 0) {
						int rssi = blobmsg_get_u32(c3);

						if (rssi <= -110)
							sta_list[mindex].metrics.link.rssi = 0;
						else if (rssi >= 0)
							sta_list[mindex].metrics.link.rssi = 220;
						else
							sta_list[mindex].metrics.link.rssi = 2 * (rssi + 110);
					}
				}
				sta_list[mindex].metrics.traffic.txpkterrors = 0;
				sta_list[mindex].metrics.traffic.rxpkterrors = 0;
				sta_list[mindex].metrics.traffic.retransmission_cnt = 0;
				platform_get_mac_from_string(list->infolist[infoindex].bssid, sta_list[mindex].bssid);
				platform_get_mac_from_string((char*)blobmsg_name(c2), sta_list[mindex].mac);

				mindex++;
			}
		}
		cum_sta->stats_count = mindex;
	}
}



int get_cumulative_sta_statistics(const char* subcmd, void* config, void *ctx)
{
	ssid_info_list_t list;
	cum_stats_t *cum_sta = (cum_stats_t*)config;
	cum_sta->stats_count = 0;
	inout_t inout;
	int status = -1;
    struct blob_buf  input_args = {0};
	(void)subcmd;
        
	get_active_and_configured_ssids(&list);
	if (list.count)
	{
        blob_buf_init(&input_args, 0);
        blobmsg_add_u32(&input_args, "short", 1);

		inout.inptr = &list;
		inout.outptr = cum_sta;
		if (invoke_ubus_command_ex(ctx, "wireless.accesspoint.station", "get", &input_args, NULL, get_station_info_cb, &inout))
		{
			status = 0;
		}
	}
	else
		platform_log(MAP_LIBRARY,LOG_DEBUG, "No active ssids!\n");

	return status;
}



static void get_channel_stats_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	inout_t *inout = (inout_t*)req->priv;
	ssid_info_list_t* list = (ssid_info_list_t*)inout->inptr;
	cum_stats_t *cum_bss = (cum_stats_t*)inout->outptr;
	map_bss_stats_t* cum_stats = (map_bss_stats_t*)cum_bss->cum_stats;
	unsigned int channel_utilization = 0;
	struct blob_attr *c1 = NULL;
	struct blob_attr *data1 = blobmsg_data(msg);
	int rem1 = blobmsg_data_len(msg);

	__blob_for_each_attr(c1, data1, rem1)
	{
		struct blob_attr *data2 = blobmsg_data(c1);
		struct blob_attr *c2 = NULL;
		int rem2 = blobmsg_data_len(c1);

		__blob_for_each_attr(c2, data2, rem2)
		{
			if (strcmp(blobmsg_name(c2), "medium_available") == 0) {
				channel_utilization = floor((100 - blobmsg_get_u32(c2)) * 2.55);
				break;
			}
		}

		// list and cum_stats follows the same index
		for (int listindex = 0; listindex < list->count; listindex++) {
			if (strncmp(list->infolist[listindex].radio_name, blobmsg_name(c1), 
						sizeof(list->infolist[listindex].radio_name)) == 0) {
				cum_stats[listindex].metrics.channel_utilization = channel_utilization;
			}
		}
	}
}


static void get_radio_stats_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	inout_t *inout = (inout_t*)req->priv;
	ssid_info_list_t* list = (ssid_info_list_t*)inout->inptr;
	cum_stats_t *cum_bss = (cum_stats_t*)inout->outptr;
	map_bss_stats_t* cum_stats = (map_bss_stats_t*)cum_bss->cum_stats;
	map_bss_stats_t* bss_node;

	struct blob_attr *data1 = blobmsg_data(msg);
	struct blob_attr *c1 = NULL;
	int rem1 = blobmsg_data_len(msg);

	__blob_for_each_attr(c1, data1, rem1)
	{
		for (int ssidindex = 0; ssidindex < list->count; ssidindex++) {
			if (strncmp(list->infolist[ssidindex].radio_name, blobmsg_name(c1), 
						sizeof(list->infolist[ssidindex].radio_name)) == 0)
			{
				bss_node = &cum_stats[ssidindex]; // cum_stats and list has same index
				bss_node->metrics.esp_present = (1<<(7 - WIFI_AC_BE));
#if ESP_AS_FRAME
				// todo: implement
#else
				int espindex = WIFI_AC_BE;
				bss_node->metrics.esp[espindex].esp_subelement |= set_esp_access_category(0x01);

				struct blob_attr *data2 = blobmsg_data(c1);
				struct blob_attr *c2 = NULL;
				int rem2 = blobmsg_data_len(c1);

				__blob_for_each_attr(c2, data2, rem2)
				{
					if (strcmp(blobmsg_name(c2), "amsdu") == 0) {
						if (blobmsg_get_u32(c2))
							bss_node->metrics.esp[espindex].esp_subelement |= set_esp_data_format(AMSDU);
					}
					else if (strcmp(blobmsg_name(c2), "ampdu") == 0) {
						if (blobmsg_get_u32(c2))
							bss_node->metrics.esp[espindex].esp_subelement |= set_esp_data_format(AMPDU);
					} 
					else if (strcmp(blobmsg_name(c2), "amsdu_in_ampdu") == 0) {
						if (blobmsg_get_u32(c2))
							bss_node->metrics.esp[espindex].esp_subelement |= set_esp_data_format(AMSDU_AMPDU);
					}
					else if (strcmp(blobmsg_name(c2), "phy_rate") == 0){
                                                unsigned int temp = blobmsg_get_u32(c2);
                                                if (temp == 0) {
                                                    bss_node->metrics.esp[espindex].ppdu_target_duration = 0;
                                                }
                                                else if (temp > 0) {
                                                    bss_node->metrics.esp[espindex].ppdu_target_duration = (uint8_t)(240000/temp);
                                                }
					}
					else if (strcmp(blobmsg_name(c2), "max_ba_window_size") == 0){
						uint8_t size_of_ba = (uint8_t)blobmsg_get_u32(c2);
						switch(size_of_ba) {
							case 2:
								bss_node->metrics.esp[espindex].esp_subelement |= set_esp_ba_window(BLK_ACK_TWO_BYTE_WNDOW_SIZE);
							break;
		
							case 4:
								bss_node->metrics.esp[espindex].esp_subelement |= set_esp_ba_window(BLK_ACK_FOUR_BYTE_WNDOW_SIZE);
							break;
		
							case 6:
								bss_node->metrics.esp[espindex].esp_subelement |= set_esp_ba_window(BLK_ACK_SIX_BYTE_WNDOW_SIZE);
							break;
		
							case 8:
								bss_node->metrics.esp[espindex].esp_subelement |= set_esp_ba_window(BLK_ACK_EIGHT_BYTE_WNDOW_SIZE);
							break;
		
							case 16:
								bss_node->metrics.esp[espindex].esp_subelement |= set_esp_ba_window(BLK_ACK_SIXTEEN_BYTE_WNDOW_SIZE);
							break;
		
							case 32:
								bss_node->metrics.esp[espindex].esp_subelement |= set_esp_ba_window(BLK_ACK_THIRTY_TWO_BYTE_WNDOW_SIZE);
							break;
		
							case 64:
								bss_node->metrics.esp[espindex].esp_subelement |= set_esp_ba_window(BLK_ACK_SIXTYFOUR_BYTE_WNDOW_SIZE);
							break;
		
							default:
								bss_node->metrics.esp[espindex].esp_subelement |= set_esp_ba_window(NO_BLOCK_ACK);
							break;
						}
					}
				}
				bss_node->metrics.esp[espindex].esp_subelement |= set_esp_ba_window(BLK_ACK_SIXTYFOUR_BYTE_WNDOW_SIZE); 
				bss_node->metrics.esp[espindex].estimated_air_time_fraction = 100 - bss_node->metrics.channel_utilization;
			}
		}
#endif
	}
}


int get_cumulative_bss_statistics(const char* subcmd, void* config, void *ctx)
{
	cum_stats_t *cum_bss = (cum_stats_t *)config; 
	ssid_info_list_t list;
	inout_t inout;
	map_bss_stats_t* cum_stats = (map_bss_stats_t*)cum_bss->cum_stats;
	(void)subcmd;
	int status = -1;

	if (config) {
		get_active_and_configured_ssids(&list);
		if (list.count) {
			platform_log(MAP_LIBRARY,LOG_DEBUG, "configured_ssids: %d\n", list.count);
			cum_bss->stats_count = 0;
			for (int listindex = 0; listindex < list.count; listindex++) {
				map_bss_stats_t* bss_node = &cum_stats[cum_bss->stats_count];
				memset(bss_node, 0, sizeof(*bss_node));
				platform_get_mac_from_string(list.infolist[listindex].bssid, bss_node->bssid);
				cum_bss->stats_count++;
			}

			inout.inptr = &list;
			inout.outptr = cum_bss;

			// update channel utilization
			if (invoke_ubus_command_ex(ctx, "wireless.radio.acs.channel_stats", "get",
										NULL, NULL, get_channel_stats_cb, &inout)) {
			
				// fill esp, pass the same input param
				if (invoke_ubus_command_ex(ctx, "wireless.radio", "get",
										NULL, NULL, get_radio_stats_cb, &inout))
					status = 0;
			}

			if (status != 0) {
				cum_bss->stats_count = 0; // invalidate the result if error
				platform_log(MAP_LIBRARY,LOG_ERR, "failed to get ubus params for bss stats!\n");
			}
		}
	}
	return status;
}


static void get_wireless_radio_state_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct blob_attr *data1 = NULL, *c1 = NULL; // first level
	struct blob_attr *data2 = NULL, *c2 = NULL; // second level
	uint8_t *radio_state = (uint8_t*)req->priv;
	int attr_to_check = 2;
	int admin_state = 0;
	int oper_state = 0;

	data1 = blobmsg_data(msg);
	int rem1 = blobmsg_data_len(msg);
	__blob_for_each_attr(c1, data1, rem1)
	{
		data2 = blobmsg_data(c1);
		int rem2 = blobmsg_data_len(c1);

		__blob_for_each_attr(c2, data2, rem2)
		{
			if(0 == strcmp(blobmsg_name(c2),"admin_state")) {
				admin_state = blobmsg_get_u32(c2);
				if (--attr_to_check == 0)
					break;
			}
			else if(0 == strcmp(blobmsg_name(c2),"oper_state")) {
				oper_state = blobmsg_get_u32(c2);
				if (--attr_to_check == 0)
					break;
			}
		}
	}

	*radio_state = (admin_state && oper_state);
}




// MAP_PLATFORM_GET_RADIO_BSS_STATE_INFO
int get_radio_and_bss_state_information(const char* interface_name, void* data, void *ctx)
{
	ssid_radio_state_t *state_info = (ssid_radio_state_t*)data;
	int status = -1;
	char radio_name[MAX_RADIO_NAME_LEN] = {0};

	if (interface_name && data)
	{
		int index;
		state_info->bss_state = 0;
		state_info->radio_state = 0;
		
		pthread_rwlock_rdlock(&map1905if_info_rw_lock); 
		for(index = 0; index < MAX_INTERFACE_COUNT; index++) {
			if (map1905if_info_interfaces[index].if_name[0] == '\0')
				continue;
			if (strncmp(interface_name, map1905if_info_interfaces[index].if_name, MAX_IFACE_NAME_LEN) == 0) {
				if (INTERFACE_POWER_STATE_ON == map1905if_info_interfaces[index].if_info.power_state)
					set_bss_state_on(&state_info->bss_state);
				strncpy(radio_name, map1905if_info_interfaces[index].radio_name, MAX_RADIO_NAME_LEN);
				break;
			}
		}
		pthread_rwlock_unlock(&map1905if_info_rw_lock);

		if (index < MAX_INTERFACE_COUNT) { // found the given interface
			if (invoke_ubus_command_ex(ctx, "wireless.radio", "get", NULL, radio_name, 
										get_wireless_radio_state_cb, &state_info->radio_state)) {
				status = 0;
			}
		}
	}

	return status;
}


static void get_wireless_radio_state_getapname_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct blob_attr *data1 = NULL, *c1 = NULL; // first level
	struct blob_attr *data2 = NULL, *c2 = NULL; // second level
	char *ssid = (char*)req->priv;

	data1 = blobmsg_data(msg);
	int rem1 = blobmsg_data_len(msg);
	__blob_for_each_attr(c1, data1, rem1)
	{
		data2 = blobmsg_data(c1);
		int rem2 = blobmsg_data_len(c1);

		__blob_for_each_attr(c2, data2, rem2)
		{
			if(0 == strcmp(blobmsg_name(c2),"ssid")) {
				if (strncmp(ssid, blobmsg_get_string(c2), MAX_IFACE_NAME_LEN) == 0)
				{
					strncpy(ssid, blobmsg_name(c1), MAX_IFACE_NAME_LEN);
				}
				break;
			}
		}
	}
}


// MAP_PLATFORM_GET_AP_FROM_BSSID
int get_apname_from_bssid(const char* bssid, void* data, void *ctx)
{
	int status = -1;
	int index;
	char if_name[MAX_IFACE_NAME_LEN];
	
	if (bssid && data) {
		pthread_rwlock_rdlock(&map1905if_info_rw_lock); 
		for(index = 0; index < MAX_INTERFACE_COUNT; index++) {
			if (map1905if_info_interfaces[index].if_name[0] == '\0')
				continue;
			if (IS_INTERFACE_WIFI(map1905if_info_interfaces[index].if_info.interface_type)) {
				char bssid_str[MAX_MAC_STRING_LEN];
				get_mac_string(map1905if_info_interfaces[index].if_info.interface_type_data.ieee80211.bssid, bssid_str);

				if (strncmp(bssid_str, bssid, MAX_MAC_STRING_LEN) == 0)
				{
					strncpy(if_name, map1905if_info_interfaces[index].if_name, MAX_IFACE_NAME_LEN);
					break;
				}
			}
		}
		pthread_rwlock_unlock(&map1905if_info_rw_lock);

		if (index < MAX_INTERFACE_COUNT) { // had found the interface
			if (invoke_ubus_command_ex(ctx, "wireless.accesspoint", "get", NULL, NULL, get_wireless_radio_state_getapname_cb, if_name)) {
				strcpy((char*)data, if_name);
				status = 0;
			}
		}
	}

	return status;
}


// MAP_PLATFORM_GET_MAP_MAC_ADDRESS
int get_map_interface_mac_address(const char* unused, void* data, void *ctx)
{
	(void)unused;
	int status = -1;

	if (data) {
		if (get_operating_role() == MULTIAP_CONTROLLER) {
			
			get_uci_config("multiap", "controller", "macaddress", data, MAX_MAC_STRING_LEN);
		}
		else if (get_operating_role() == MULTIAP_AGENT) {
			get_uci_config("multiap", "agent", "macaddress", data, MAX_MAC_STRING_LEN);
		}
		status = 0;
	}

	return status;
}
// MAP_PLATFORM_GET_VALID_FHBH_INTERFACE
int get_valid_interface(const char* interface, void* data, void *ctx)
{
	int status = -1;
	char interface_list[128];

	if (interface && data)
	{
		char *token, *saveptr = NULL;

		char* env = getenv("FRONTHAUL_LIST");
		if (env) {
			strncpy(interface_list, env, sizeof(interface_list));
			interface_list[sizeof(interface_list) - 1] = '\0';
			token = strtok_r(interface_list, ", ", &saveptr);
			if (token && (strncmp(token, interface, sizeof(interface_list)) == 0)) {
				strcpy((char*)data, "fronthaul");
				status = 0;
			}
		}

		if (0 != status) {
			char* env = getenv("BACKHAUL_LIST");
			if (env) {
				strncpy(interface_list, env, sizeof(interface_list));
				interface_list[sizeof(interface_list) - 1] = '\0';
				token = strtok_r(interface_list, ",", &saveptr);
				if (token && (strncmp(token, interface, sizeof(interface_list)) == 0)) {
					strcpy((char*)data, "backhaul");
					status = 0;
				}
			}
		}
	}

	return status;
}


// MAP_PLATFORM_GET_IEEE_INTERFACE_FROM_MAC
int get_if_from_macaddress(const char* key, void* data, void *ctx)
{
	int status = -1;
	int index;
	char macstring[MAX_MAC_STRING_LEN];

	if (key && data)
	{
		pthread_rwlock_rdlock(&map1905if_info_rw_lock); 
		for(index = 0; index < MAX_INTERFACE_COUNT; index++) {
			if (map1905if_info_interfaces[index].if_name[0] == '\0')
				continue;
			if (IS_INTERFACE_WIFI(map1905if_info_interfaces[index].if_info.interface_type)) {
				get_mac_string(map1905if_info_interfaces[index].if_info.interface_type_data.ieee80211.bssid, macstring);
				if (strncasecmp(key, macstring, MAX_MAC_STRING_LEN) == 0)
				{
					strcpy((char*)data, map1905if_info_interfaces[index].if_name);
					status = 0;
					break;
				}
			}
		}
		pthread_rwlock_unlock(&map1905if_info_rw_lock);
	}
	return status;
}


// MAP_PLATFORM_SET_IEEE_1905_WIFI_PARAMS
int set_wifi_parameters(void* data, void *ctx)
{
    int status = 0;
    char tfpath[128];
    char value[32];
    ssid_info_list_t list;
    int index;
    struct wifi_params *wp = (struct wifi_params*)data;
    wireless_ssid_info_t *info = NULL;
    char input_str[8];
    int change =0;

    if (wp) {
        sprintf(tfpath, "rpc.wireless.ssid.@%s.ssid", wp->interface);
        value[0]='\0';
        read_value_from_transformer(tfpath, value, sizeof(value));
        if (strncmp(value, wp->ssid, sizeof(value)) != 0) {
            if (write_value_to_transformer(tfpath, wp->ssid, false)) {
                platform_log(MAP_LIBRARY,LOG_DEBUG, "%s updated successfully\n", tfpath);
                change = 1;
            }
            else {
                status = -1;
                platform_log(MAP_LIBRARY,LOG_ERR, "failed to update %s\n", tfpath);
            }
        }
        else
            platform_log(MAP_LIBRARY,LOG_DEBUG, "No need to update ssid %s (same as existing)\n", wp->ssid);

        get_active_and_configured_ssids(&list);
        for (index = 0; index < list.count; index++) {
            if (strncmp(list.infolist[index].interface_name, wp->interface, sizeof(wp->interface)) == 0)
                break;
        }

        if (index < list.count)
            info = &list.infolist[index];
        else {
            platform_log(MAP_LIBRARY,LOG_DEBUG, "Unable to find given interface %s in ssid list; return\n", wp->interface);
            status = -1;
        }

    if (0 == status) { // skip trying to set the second param if first one fails
        sprintf(tfpath, "rpc.wireless.ap.@%s.security.wpa_psk_passphrase", info->ap_name);
        value[0]='\0';
        read_value_from_transformer(tfpath, value, sizeof(value));
        if (strncmp(value, wp->passwd, sizeof(value)) != 0) {
            if (write_value_to_transformer(tfpath, wp->passwd, false)) {
                platform_log(MAP_LIBRARY,LOG_DEBUG, "%s updated successfully\n", tfpath);
                change = 1;
            }
            else {
                platform_log(MAP_LIBRARY,LOG_ERR, "failed to update %s\n", tfpath);
                status = -1;
            }
        }
        else
            platform_log(MAP_LIBRARY,LOG_DEBUG, "No need to update password (same as existing)\n");
    }

    if (0 == status) {
        sprintf(tfpath, "rpc.wireless.ap.@%s.security.mode", info->ap_name);
        value[0]='\0';
        read_value_from_transformer(tfpath, value, sizeof(value));
        if (strncmp(value, wp->auth_type, sizeof(value)) != 0) {
            if (write_value_to_transformer(tfpath, wp->auth_type, false)) {
                platform_log(MAP_LIBRARY,LOG_DEBUG, "%s updated successfully\n", tfpath);
                change = 1;
            }
            else {
                platform_log(MAP_LIBRARY,LOG_ERR, "failed to update %s\n", tfpath);
                status = -1;
            }
        }
        else
            platform_log(MAP_LIBRARY,LOG_DEBUG, "No need to update security.mode (same as existing)\n");
    }

    if (0 == status) {
        sprintf(tfpath, "uci.wireless.wifi-iface.@%s.fronthaul", info->interface_name);
        value[0]='\0';
        read_value_from_transformer(tfpath, value, sizeof(value));
        if (wp->fronthaul_bit != atoi(value)) {
            snprintf(input_str, sizeof(input_str), "%d", wp->fronthaul_bit);
            if (write_value_to_transformer(tfpath, input_str, false)){
                platform_log(MAP_LIBRARY,LOG_DEBUG, "%s updated successfully\n", tfpath);
                change = 1;
            }
            else {
                status = -1;
                platform_log(MAP_LIBRARY,LOG_ERR, "failed to update %s\n", tfpath);
            }
        }
        else
            platform_log(MAP_LIBRARY,LOG_DEBUG, "No need to update fronthaul (same as existing)\n");
    }

    if (0 == status) {
        sprintf(tfpath, "uci.wireless.wifi-iface.@%s.backhaul", info->interface_name);
        value[0]='\0';
        read_value_from_transformer(tfpath, value, sizeof(value));
        if (wp->backhaul_bit != atoi(value)) {
            snprintf(input_str, sizeof(input_str), "%d", wp->backhaul_bit);
            if (write_value_to_transformer(tfpath, input_str, false)) {
                platform_log(MAP_LIBRARY,LOG_DEBUG, "%s updated successfully\n", tfpath);
                change = 1;
            }
            else {
                status = -1;
                platform_log(MAP_LIBRARY,LOG_ERR, "failed to update %s\n", tfpath);
            }
        }
        else
            platform_log(MAP_LIBRARY,LOG_DEBUG, "No need to update backhaul (same as existing)\n");
    }

    if (0 == status && (1 == wp->backhaul_bit) && (0 == wp->fronthaul_bit)) {
        sprintf(tfpath, "uci.wireless.wifi-ap.@%s.wps_state", info->ap_name);
        value[0]='\0';
        read_value_from_transformer(tfpath, value, sizeof(value));
        platform_log(MAP_LIBRARY,LOG_DEBUG, "%s apname is %s and value is %d\n", tfpath, info->ap_name, atoi(value));
        if (1 == atoi(value)) {
            if (write_value_to_transformer(tfpath, "0", false)) {
                platform_log(MAP_LIBRARY,LOG_DEBUG, "%s updated successfully \n", tfpath);
                change = 1;
            }
            else {
                status = -1;
               platform_log(MAP_LIBRARY,LOG_ERR, "failed to update %s\n", tfpath);
            }
        }
        else
            platform_log(MAP_LIBRARY,LOG_DEBUG, "No need to update wps for backhaul\n");
    }

    if (0 == status) {
        sprintf(tfpath, "uci.wireless.wifi-ap.@%s.public", info->ap_name);
        value[0]='\0';
        read_value_from_transformer(tfpath, value, sizeof(value));
        platform_log(MAP_LIBRARY,LOG_DEBUG, "%s apname is %s and hidden ssid value is %d\n", tfpath, info->ap_name, atoi(value));

        if (0 == atoi(value) && (1 == wp->fronthaul_bit)) {
            if (write_value_to_transformer(tfpath, "1", false)) {
                platform_log(MAP_LIBRARY,LOG_DEBUG, "%s updated successfully \n", tfpath);
                change = 1;
            }
            else {
                status = -1;
                platform_log(MAP_LIBRARY,LOG_ERR, "failed to update %s\n", tfpath);
            }
        }
        else if ((1 == wp->backhaul_bit) && (0 == wp->fronthaul_bit)) {
            if (1 == atoi(map_agent_env_hidden_backhaul) && (1 == atoi(value))) {
                if (write_value_to_transformer(tfpath, "0", false)) {
                    platform_log(MAP_LIBRARY,LOG_DEBUG, "%s updated successfully \n", tfpath);
                    change = 1;
                }
                else {
                    status = -1;
                    platform_log(MAP_LIBRARY,LOG_ERR, "failed to update %s\n", tfpath);
                }
            }
            else if ((0 == atoi(map_agent_env_hidden_backhaul)) && (0 == atoi(value))) {
                if (write_value_to_transformer(tfpath, "1", false)) {
                    platform_log(MAP_LIBRARY,LOG_DEBUG, "%s updated successfully \n", tfpath);
                    change = 1;
                }
                else {
                    status = -1;
                    platform_log(MAP_LIBRARY,LOG_ERR, "failed to update %s\n", tfpath);
                }
            }
        }
    }

    if(change == 1)
    {
        write_loaded_values_to_transformer();
    }

    }

    else 
        status = -1;

    return status;
}


static void map_btm_sta_steer_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	platform_log(MAP_LIBRARY,LOG_DEBUG, "inside map_btm_sta_steer_cb\n");
}



// MAP_PLATFORM_BTM_STA_STEER
int map_btm_sta_steer_set(void* data, void *ctx)
{
	struct sta_steer_params *btm_sta_steer = (struct sta_steer_params*) data;
	char   sta_mac_str[MAX_MAC_STRING_LEN] = {0};
	char   bssid_str[MAX_MAC_STRING_LEN] = {0};
	struct blob_buf inputbuf = {};
	int status = -1;

	if (data) {
		blob_buf_init(&inputbuf, 0);
		blobmsg_add_string(&inputbuf, "name", btm_sta_steer->ap_name);
		get_mac_string(btm_sta_steer->sta_info[0].sta_mac, sta_mac_str);
		blobmsg_add_string(&inputbuf, "macaddr", sta_mac_str);

		void  *array = blobmsg_open_array(&inputbuf, "target_bss_list");
		void *table = blobmsg_open_table(&inputbuf, NULL);
		get_mac_string(btm_sta_steer->sta_info[0].bssid, bssid_str);
		blobmsg_add_string(&inputbuf, "bssid", bssid_str);
		blobmsg_add_u32(&inputbuf, "channel", btm_sta_steer->sta_info[0].channel);
		blobmsg_close_table(&inputbuf, table);
		blobmsg_close_array(&inputbuf, array);
		print_blob_info(inputbuf.head, 0, 0);
		blobmsg_add_u32(&inputbuf, "disassoc_timer", btm_sta_steer->disassociation_timer);
		blobmsg_add_u32(&inputbuf, "abridged", btm_sta_steer->abridged_mode);
		if (invoke_ubus_command_ex(ctx, "wireless.accesspoint.station", "send_bss_transition_request", 
									&inputbuf, NULL, map_btm_sta_steer_cb, NULL) == true) {
			platform_log(MAP_LIBRARY,LOG_DEBUG, "btm_sta_steer initiated\n");
			status = 0;
		}
		else
			platform_log(MAP_LIBRARY,LOG_ERR, "btm_sta_steer failed\n");
	}

	return status;
}

#define MAX_AL_UCI_RESULT_LEN 128

int get_ieee1905_configuration(const char* key, void* data, void *ctx)
{
	int status = -1;	
	char **if_data = (char**)data;
	
	if(NULL != if_data) {
		status = 0;
		/* acquire lock and do the look up */
		pthread_rwlock_rdlock(&map1905if_info_rw_lock);
		for(int i = 0; i < MAX_INTERFACE_COUNT; i++) {	
			strcpy(if_data[i], map1905if_info_interfaces[i].if_name);
		}
		pthread_rwlock_unlock(&map1905if_info_rw_lock);	
	}
	return status;
}


static void network_interface_state_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct blob_attr *c1 = NULL;
	struct blob_attr *data1 = blobmsg_data(msg);
	int rem1 = blobmsg_data_len(msg);
	inout_t* inout = (inout_t*)req->priv;

	__blob_for_each_attr(c1, data1, rem1)
	{
		struct blob_attr *c2 = NULL;
		struct blob_attr *data2 = blobmsg_data(c1);
		int rem2 = blobmsg_data_len(c1);
	
		__blob_for_each_attr(c2, data2, rem2) 
		{
			struct blob_attr *c3 = NULL;
			struct blob_attr *data3 = blobmsg_data(c2);
			int rem3 = blobmsg_data_len(c2);
			char interface[MAX_IFACE_NAME_LEN] = {0};
			char action[MAX_IFACE_NAME_LEN] = {0};

			__blob_for_each_attr(c3, data3, rem3) 
			{
				if (strcmp(blobmsg_name(c3), "interface") == 0) {
					strncpy(interface, blobmsg_get_string(c3), sizeof(interface));
					interface[sizeof(interface) - 1] ='\0';
				}else if (strcmp(blobmsg_name(c3), "action") == 0) {
					strncpy(action, blobmsg_get_string(c3), sizeof(action));
					action[sizeof(action) - 1] ='\0';
				}
			}
	
			if (strcmp(interface, inout->inptr) == 0) {
				strcpy((char*)inout->outptr, action);
				break;
			}
		}
		break;
	}
}
//MAP_PLATFORM_GET_INTERFACE_STATE
int get_network_interface_state(const char* ifname, void* data, void *ctx)
{
	int status = -1;

	if (ifname && data)
	{
		if (strcmp(ifname, "lo") == 0) {
			strcpy((char*)data, "up");
			status = 0;
		}
		else
		{
			inout_t inout;
			inout.inptr = (void*)ifname;
			inout.outptr = data;

			if (invoke_ubus_command_ex(ctx, "network.link", "status", NULL, NULL, network_interface_state_cb, &inout))
				status = 0;
		}
	}

	return status;
}


// MAP_PLATFORM_GET_SSID
int get_map_ssid(const char* iftype, void* data, void *ctx)
{
	int status = -1;
	char result[128]; // fix this

	if (iftype && data) {
		bool ucistatus = false;

		if (strcmp(iftype, "fronthaul") == 0)
			ucistatus = get_uci_config("multiap", "fronthaul", "interface", result, sizeof(result));
		else if (strcmp(iftype, "backhaul") == 0)
			ucistatus = get_uci_config("multiap", "backhaul", "interface", result, sizeof(result));

		if (ucistatus) {
			char *token, *saveptr = NULL;

			token = strtok_r(result, ", ", &saveptr);
			if (token) {
				ucistatus = get_uci_config("wireless", result, "ssid", result, sizeof(result));
				if (ucistatus) {
					strcpy((char*)data, result);
					status = 0;
				}
			}
		}
	}

	return status;
}


// MAP_PLATFORM_GET_WPA_PSK
int get_ap_psk(const char* iftype, void* data, void *ctx)
{
	int status = -1;
	char result[128]; // fix this
	char* ifname = NULL;
	char* saveptr = NULL;

	if (iftype && data) {
		bool ucistatus = false;

		if (strcmp(iftype, "fronthaul") == 0)
			ucistatus = get_uci_config("multiap", "fronthaul", "interface", result, sizeof(result));
		else if (strcmp(iftype, "backhaul") == 0)
			ucistatus = get_uci_config("multiap", "backhaul", "interface", result, sizeof(result));

		if (ucistatus)
			ifname = strtok_r(result, ", ", &saveptr);

		if (ifname) {
			struct uci_context *ctx = uci_alloc_context();
			struct uci_package *package;
			uci_load(ctx, "wireless", &package);
			package = uci_lookup_package(ctx, "wireless");
			if (package) {
				struct uci_element *sectionelement, *sectiontemp;

				uci_foreach_element_safe(&package->sections, sectiontemp, sectionelement)
				{
					struct uci_section *s = uci_to_section(sectionelement);
					struct uci_element *optionelement, *optiontemp;

					uci_foreach_element_safe(&s->options, optiontemp, optionelement)
					{
						struct uci_option *option = uci_to_option(optionelement);
						if (option && (strcmp(option->v.string, ifname) == 0)) {
							if (get_uci_config("wireless", sectionelement->name, "wpa_psk_key", result, sizeof(result))) {
								strcpy((char*)data, result);
								status = 0;
								break;
							}
						}
					}
					if (status == 0)
						break;
				}
			}
			else
				platform_log(MAP_LIBRARY,LOG_ERR, "uci_lookup_package for wireless failed\n");
			uci_free_context(ctx);
		}
	}

	return status;
}


// MAP_PLATFORM_LEGACY_STA_STEER
int set_legacy_sta_steer(void* data, void *ctx)
{
	struct sta_steer_params *legacy_sta_steer = (struct sta_steer_params*)data;
	char sta_mac_str[MAX_MAC_STRING_LEN] = {0};
	char bssid[MAX_MAC_STRING_LEN] = {0};
	ssid_info_list_t ssidlist;
	int ssidindex, clientindex;
	struct blob_buf inputbuf={0};
	int status = -1;

	if (data)
	{
		get_mac_string(legacy_sta_steer->source_bssid, bssid);
		get_active_and_configured_ssids(&ssidlist);

		for (ssidindex = 0; ssidindex < ssidlist.count; ssidindex++) {
			if (strncmp(ssidlist.infolist[ssidindex].bssid, bssid, MAX_MAC_STRING_LEN) == 0)
				break;
		}

		if (ssidindex < ssidlist.count) {
			for (clientindex = 0; clientindex < legacy_sta_steer->sta_count; clientindex++) {
				blob_buf_init(&inputbuf, 0);
				blobmsg_add_string(&inputbuf, "name", ssidlist.infolist[ssidindex].ap_name);
				get_mac_string(legacy_sta_steer->sta_info[clientindex].sta_mac, sta_mac_str);
				blobmsg_add_string(&inputbuf, "macaddr", sta_mac_str);
				blobmsg_add_u32(&inputbuf, "reason", 2); //2?

				if (invoke_ubus_command_ex(ctx, "wireless.accesspoint.station", "deauth", &inputbuf, NULL, map_btm_sta_steer_cb, NULL))
					status = 0;
			}
		}
	}

	return status;
}


//MAP_PLATFORM_GET_MULTIAP_CONFIG
int get_multiap_configuration(const char* key, void* data, void *ctx)
{
	int status = -1;

	if (key && data)
	{
		char* sectname = NULL;
		char* optname = NULL;
		char *saveptr = NULL;

		char* temp = strdup(key);
		sectname = strtok_r(temp, ". ", &saveptr);
		if (sectname) {
			optname = strtok_r(NULL, ". ", &saveptr);

			struct	uci_context *uci_ctx = uci_alloc_context();
			if (uci_ctx)
			{
				struct  uci_ptr ptr;

				memset(&ptr, 0, sizeof(ptr));
				ptr.package = "multiap";
				ptr.section = sectname;
				ptr.option = optname;

				if (uci_lookup_ptr(uci_ctx, &ptr, NULL, true) == UCI_OK) {
					if (optname) {
						if (ptr.o && ptr.o->v.string) {
							strcpy((char*)data, ptr.o->v.string);
	 						status = 0;
						}
						else
							platform_log(MAP_LIBRARY,LOG_ERR, "failed to get option info for: %s\n", key);
					}
					else { 
						if (ptr.s && ptr.s->type) {
							strcpy((char*)data, ptr.s->type);
	 						status = 0;
						}
						else
							platform_log(MAP_LIBRARY,LOG_ERR, "failed to get section info for: %s\n", key);
					}
					
				}
				else 
					platform_log(MAP_LIBRARY,LOG_ERR, "uci lookup failed for %s\n", key);
				uci_free_context(uci_ctx);
			}
			free(temp);
		}
		else
			platform_log(MAP_LIBRARY,LOG_ERR, "failed to get sectname from key: %s\n", key);
	}

	return status;
}


static bool get_wps_info(struct blob_attr *wpsinfo, char* ap_name)
{
	int admin_state = 0;
	int oper_state = 0;
	struct blob_attr *c1 = NULL;
	struct blob_attr *data1 = blobmsg_data(wpsinfo);
	int rem1 = blobmsg_len(wpsinfo);

	__blob_for_each_attr(c1, data1, rem1)
	{
		if (strcmp(blobmsg_name(c1), ap_name) != 0)
			continue;

		struct blob_attr *c2 = NULL;
		struct blob_attr *data2 = blobmsg_data(c1);
		int rem2 = blobmsg_data_len(c1);
		int attr_to_check = 2;
		__blob_for_each_attr(c2, data2, rem2)
		{
			if(0 == strcmp(blobmsg_name(c2),"admin_state")) {
				admin_state = blobmsg_get_u32(c2);
				if (--attr_to_check == 0)
					break;
			}
			else if(0 == strcmp(blobmsg_name(c2),"oper_state")) {
				oper_state = blobmsg_get_u32(c2);
				if (--attr_to_check == 0)
					break;
			}
		}
		break;
	}

	return (admin_state && oper_state);
}


static void get_secmode_supported(struct blob_attr *securityinfo, char* ap_name, map_bss_info_t *bss_node)
{
	struct blob_attr *c1 = NULL;
	struct blob_attr *data1 = blobmsg_data(securityinfo);
	int rem1 = blobmsg_len(securityinfo);

	bss_node->supported_sec_modes = NULL;
	__blob_for_each_attr(c1, data1, rem1)
	{
		if (strcmp(blobmsg_name(c1), ap_name) != 0)
			continue;
		
		struct blob_attr *c2 = NULL;
		struct blob_attr *data2 = blobmsg_data(c1);
		int rem2 = blobmsg_data_len(c1);
		
		__blob_for_each_attr(c2, data2, rem2)
		{
			if (strcmp(blobmsg_name(c2), "supported_modes") == 0) {
				bss_node->supported_sec_modes = strdup(blobmsg_get_string(c2));
				break;
			}
		}
		break;
	}
}


static void update_station_info(struct blob_attr *stationinfo, map_bss_info_t *bss_node, char* ap_name, uint8_t* bss_id)
{
	struct blob_attr *c1 = NULL;
	struct blob_attr *data1 = blobmsg_data(stationinfo);
	int rem1 = blobmsg_len(stationinfo);
	
	__blob_for_each_attr(c1, data1, rem1)
	{
		if (strcmp(blobmsg_name(c1), ap_name) != 0)
			continue;
		
		struct blob_attr *c2 = NULL;
		struct blob_attr *data2 = blobmsg_data(c1);
		int rem2 = blobmsg_data_len(c1);

		__blob_for_each_attr(c2, data2, rem2)
		{
			struct blob_attr *c3 = NULL;
			struct blob_attr *data3 = blobmsg_data(c2);
			int rem3 = blobmsg_data_len(c2);
			bool connected = false;
			time_t assoc_time = 0;
			uint16_t assoc_frame_len = 0;
			uint8_t *assoc_frame = NULL;

			__blob_for_each_attr(c3, data3, rem3)
			{
				if (strcmp(blobmsg_name(c3), "state") == 0) {
					if (strstr(blobmsg_get_string(c3), "Associated") == NULL)
						break;
					else
						connected = true;
				}
				else if (strcmp(blobmsg_name(c3), "last_assoc_timestamp") == 0) {
					struct tm time_c;
					strptime(blobmsg_get_string(c3), "%H:%M:%S-%d/%m/%Y", &time_c);
					assoc_time = mktime(&time_c);
				}
				else if (strcmp(blobmsg_name(c3), "assoc_frame") == 0) {
					hexstream_to_bytestream((char*)blobmsg_get_string(c3), &assoc_frame, &assoc_frame_len);
				}
			}

			if (connected) {
				map_sta_metrics_t *sta_metrics = NULL;
				map_sta_info_t *sta_node = NULL;
				uint8_t sta_id[MAC_ADDR_LEN] = {0};
				
				platform_get_mac_from_string((char*)blobmsg_name(c2), sta_id);
				sta_node  = create_sta(sta_id, bss_id);
				if(sta_node){
					if(list_get_size(sta_node->metrics) == 0) {
						sta_metrics = (map_sta_metrics_t*)calloc(1, sizeof(map_sta_metrics_t));
						if(sta_metrics != NULL) {
							insert_last_object(sta_node->metrics, (void *)sta_metrics);
						}
					}
					/* Allocate only if sta supports beacon metrics reporting */ 
					sta_node->beacon_metrics = (beacon_metrics_query_t *)calloc(1, sizeof(beacon_metrics_query_t) + 
									  (MAX_AP_REPORT_CHANNELS * sizeof(struct ap_channel_report))); 
					if(sta_node->beacon_metrics == NULL)
						platform_log(MAP_LIBRARY,LOG_ERR, "allco failed while allocating for beacon_metrics\n");

					sta_node->assoc_time = assoc_time;
					sta_node->assoc_frame = assoc_frame;
					sta_node->assoc_frame_len = assoc_frame_len;
				}
				else
					platform_log(MAP_LIBRARY,LOG_ERR, "Failed creating/updating the station %s.\n", sta_id);
			}
			else {
				platform_log(MAP_LIBRARY,LOG_DEBUG, "station is not connected; not adding to autoconfig\n");
				if (assoc_frame)
					free(assoc_frame);
			}
		}
		break;
	}
}



static void update_bss_and_station_info(ssid_list_t *list, map_radio_info_t *radio, char* radioname, 
								struct blob_attr *securityinfo, struct blob_attr *wpsinfo, struct blob_attr *stationinfo)
{
	for (int bssindex = 0; bssindex < list->count; bssindex++) {
		ssid_info_t *info = &list->infolist[bssindex];
		if (strcmp(info->radio_name, radioname) == 0) {
			uint8_t bss_id[MAC_ADDR_LEN] = {0};
			platform_get_mac_from_string(info->bssid, bss_id);
			map_bss_info_t *bss_node = create_bss(bss_id, radio->radio_id);
			if(bss_node) {
				strncpy(bss_node->iface_name, info->interface_name, MAX_IFACE_NAME_LEN);
				bss_node->iface_name[MAX_IFACE_NAME_LEN-1] = '\0';
				
				strncpy((char*)bss_node->ssid, info->ssid, MAX_WIFI_SSID_LEN);
				bss_node->ssid[MAX_WIFI_SSID_LEN-1] = '\0';
				platform_get_mac_from_string(info->bssid, bss_node->bssid);
				get_secmode_supported(securityinfo, info->ap_name, bss_node);

				if (info->admin_state && info->oper_state)
					set_bss_state_on(&bss_node->state);

				if (get_wps_info(wpsinfo, info->ap_name))
					set_bss_state_wps_supported(&bss_node->state);

				update_station_info(stationinfo, bss_node, info->ap_name, bss_id);
				radio->num_bss++;
			}
			else
				platform_log(MAP_LIBRARY,LOG_ERR, "Failed creating BSS node %s in Radio node %s .\n", bss_id, radio->radio_id);
		}
	}
}


static void update_radio_info(struct blob_attr *radiodata, map_radio_info_t *radio)
{
	uint8_t current_bw = 0;
	uint8_t current_fq = 0;
	wifi_channel_set current_ch;
	char regulatory_domain[20] = {0};
	wifi_channel_set non_op_ch;
	wifi_op_class_array op_class;

    wifi_op_class_array cur_opclass;
    wifi_channel_set channel;

	struct blob_attr *data2 = blobmsg_data(radiodata);
	int rem2 = blobmsg_data_len(radiodata);
	struct blob_attr *c2 = NULL; // second level

	radio->state = 0x0000;
	radio->num_bss = 0;
	int admin_state = 0;
	int oper_state = 0;
	
	__blob_for_each_attr(c2, data2, rem2)
	{
		if(0 == strcmp(blobmsg_name(c2),"admin_state"))
			admin_state = blobmsg_get_u32(c2);
		else if(0 == strcmp(blobmsg_name(c2),"oper_state"))
			oper_state = blobmsg_get_u32(c2);
		else if(0 == strcmp(blobmsg_name(c2),"band")) {
			if (strcmp(blobmsg_get_string(c2), "2.4GHz") == 0) {
				radio->radio_caps.type = IEEE80211_FREQUENCY_BAND_2_4_GHZ;
				radio->supported_freq=IEEE80211_FREQUENCY_BAND_2_4_GHZ;
			}
			else if (strcmp(blobmsg_get_string(c2), "5GHz") == 0) {
				radio->radio_caps.type = IEEE80211_FREQUENCY_BAND_5_GHZ;
				radio->supported_freq=IEEE80211_FREQUENCY_BAND_5_GHZ;
			}
			current_fq = radio->radio_caps.type +1;
		}
		else if(0 == strcmp(blobmsg_name(c2),"channel_width")) {
			current_bw = atoi(blobmsg_get_string(c2));
            radio->current_bw = current_bw;
		}
		else if(0 == strcmp(blobmsg_name(c2),"capabilities")) {
			char *str = strdup(blobmsg_get_string(c2));
			char *saveptr = NULL;
			char* type = NULL;
			char* width = NULL;

			char* cap = strtok_r(str, " ", &saveptr);
			if (cap) {
				if (strcmp(cap, "802.11b") == 0)
				   radio->radio_caps.supported_standard = STD_80211_B;
				else if(strcmp(cap, "802.11g") == 0)
				   radio->radio_caps.supported_standard = STD_80211_G;
				else if(strcmp(cap, "802.11a") == 0)
				   radio->radio_caps.supported_standard = STD_80211_A;
				else if((strcmp(cap, "802.11n") == 0) || (strcmp(cap, "802.11bgn") == 0))
				   radio->radio_caps.supported_standard = STD_80211_N;
				else if(strcmp(cap, "802.11ac") == 0)
				   radio->radio_caps.supported_standard = STD_80211_AC;
				else if(strcmp(cap, "802.11an") == 0)
				   radio->radio_caps.supported_standard = STD_80211_AN;
				else if(strcmp(cap, "802.11anac") == 0)
				   radio->radio_caps.supported_standard = STD_80211_ANAC;
				else if(strcmp(cap, "802.11ax") == 0)
				   radio->radio_caps.supported_standard = STD_80211_AX;
				else
					platform_log(MAP_LIBRARY,LOG_ERR,"Unsupported standard");
				
				type = strtok_r(NULL, " ", &saveptr);
				if (type) {
					char *in, *out;
					width = strtok_r(NULL, " ", &saveptr);
					if (width)
						radio->radio_caps.max_bandwidth = atoi(width);
					
					in = strtok_r(type, "x", &saveptr);
					if (in) {
						radio->radio_caps.max_rx_spatial_streams = atoi(in);
						out = strtok_r(NULL, "x", &saveptr);
						if (out)
							radio->radio_caps.max_tx_spatial_streams = atoi(out);
					}
				}
			}
			free(str);
		}
                else if(0 == strcmp(blobmsg_name(c2),"max_target_power_adjusted")) {
                    int pwr = atoi(blobmsg_get_string(c2));
                    radio->current_tx_pwr = (pwr < 0) ? 0 : pwr;
                    platform_log(MAP_LIBRARY,LOG_DEBUG,"%s %d, init_fn current_tx_pwr %d\n",__func__ ,__LINE__, radio->current_tx_pwr);
		}
		else if(0 == strcmp(blobmsg_name(c2),"sgi")) {
			radio->radio_caps.sgi_support = blobmsg_get_u32(c2);
		}
		else if(0 == strcmp(blobmsg_name(c2),"txbf")) {
			if ((strcmp(blobmsg_get_string(c2), "auto") == 0) ||
				(strcmp(blobmsg_get_string(c2), "on") == 0))
				radio->radio_caps.su_beamformer_capable = 1;
			else// if ((strcmp(blobmsg_get_string(c2), "off") == 0))
				radio->radio_caps.su_beamformer_capable = 0;
		}
		else if(0 == strcmp(blobmsg_name(c2),"mumimo")) {
			if ((strcmp(blobmsg_get_string(c2), "auto") == 0) ||
				(strcmp(blobmsg_get_string(c2), "on") == 0))
				radio->radio_caps.mu_beamformer_capable = 1;
			else// if ((strcmp(blobmsg_get_string(c2), "off") == 0))
				radio->radio_caps.mu_beamformer_capable = 0;
		}
		else if(0 == strcmp(blobmsg_name(c2),"channel")) {
			radio->current_op_channel = blobmsg_get_u32(c2);
		}
		else if(0 == strcmp(blobmsg_name(c2),"allowed_channels")) {
			char *token = NULL;
			char *saveptr = NULL;
			
			char *str = strdup(blobmsg_get_string(c2));
			token = strtok_r(str, " ", &saveptr);
			for(int j = 0; j < MAX_CHANNEL_SET; j++) {
				if (token)
					current_ch.ch[j] = atoi(token); 
				else {
					current_ch.length = j;
					break;
				}
				token = strtok_r(NULL, " ", &saveptr);
			}
			free(str);
		}
		else if(0 == strcmp(blobmsg_name(c2),"country")) {
			strncpy(regulatory_domain, blobmsg_get_string(c2), sizeof(regulatory_domain));
		}
	}

	if ((1 == admin_state) && (1 == oper_state))
		set_radio_state_on(&radio->state);

	memset (&op_class, 0, sizeof(op_class));

    get_operating_class (&current_ch, 0, (char*)regulatory_domain, &op_class);

    channel.ch[0] = radio->current_op_channel;
    channel.length = 1;
    memset (&cur_opclass, 0, sizeof(cur_opclass));
    get_operating_class(&channel, current_bw, (char*)regulatory_domain, &cur_opclass);
    radio->current_op_class = cur_opclass.array[0];

	/* allocate memory for op_class_list. This MUST be freed when the radio is removed */
	radio->op_class_count = op_class.length;
	radio->op_class_list = (map_op_class_t *)calloc(op_class.length, sizeof(map_op_class_t));
	if(radio->op_class_list != NULL)
	{
		for(int j = 0; j<op_class.length; j++) 
			radio->op_class_list[j].op_class = op_class.array[j];

		memset (&non_op_ch, 0, sizeof(non_op_ch));
		for (int j=0; j<op_class.length; j++) {
			get_non_operating_ch(op_class.array[j], &non_op_ch, &current_ch);

			//##copy non operating_channels to global multiap structure
			if (non_op_ch.length >0) {
				if(non_op_ch.length > MAX_CHANNEL_IN_OPERATING_CLASS)
					non_op_ch.length = MAX_CHANNEL_IN_OPERATING_CLASS;
				radio->op_class_list[j].static_non_operable_count = non_op_ch.length;
				memcpy( radio->op_class_list[j].static_non_operable_channel, non_op_ch.ch, non_op_ch.length );
			}
			else
				radio->op_class_list[j].static_non_operable_count = 0;

			radio->op_class_list[j].eirp = get_eirp(op_class.array[j], (char*)regulatory_domain);
			memset(&non_op_ch, 0, sizeof(non_op_ch));
		}

		memset(&op_class, 0, sizeof(op_class));
	}

}

// This is having hardcoded values as in the original code; may have to change
static void get_radio_and_if_info(ssid_list_t *list, char* radioname, char* ifname, uint8_t* radio_id)
{
	for (int index = 0; index < list->count; index++) {
		ssid_info_t* info = &list->infolist[index];
		if (strcmp(info->radio_name, radioname) == 0) {
			strcpy(ifname, info->interface_name);
			platform_get_mac_from_string(info->bssid, radio_id);
			break;
		}
	}
}



int get_map_ap_autoconfig(const char *unused, void *data, void *ctx)
{
	ssid_list_t list;
	int status = -1;
	map_ale_info_t *agent_node = (map_ale_info_t*)data;

	if (data)
	{
		get_configured_ssids(ctx, &list);
		struct blob_attr *radioinfo = NULL;
		struct blob_attr *securityinfo = NULL;
		struct blob_attr *wpsinfo = NULL;
		struct blob_attr *stationinfo = NULL;

		invoke_ubus_command(ctx, "wireless.radio", "get", NULL, &radioinfo);
		invoke_ubus_command(ctx, "wireless.accesspoint.security", "get", NULL, &securityinfo);
		invoke_ubus_command(ctx, "wireless.accesspoint.wps", "get", NULL, &wpsinfo);
		struct blob_buf stationquery = {0};
		blob_buf_init(&stationquery, 0);
		blobmsg_add_u32(&stationquery, "report_assoc_frame", 1);
		invoke_ubus_command(ctx, "wireless.accesspoint.station", "get", &stationquery, &stationinfo);

		if (radioinfo && securityinfo && wpsinfo && stationinfo)
		{
			struct blob_attr *data1 = NULL, *c1 = NULL; // first level
			map_radio_info_t *radio = NULL;
			data1 = blobmsg_data(radioinfo);
			int rem1 = blobmsg_data_len(radioinfo);
			
			__blob_for_each_attr(c1, data1, rem1)
			{
				char ifname[MAX_IFACE_NAME_LEN];
				uint8_t radio_id[MAC_ADDR_LEN] = {0};
				
				ifname[0] = '\0';
				get_radio_and_if_info(&list, (char*)blobmsg_name(c1), ifname, radio_id);
				if ('\0' == ifname[0]) {
					platform_log(MAP_LIBRARY,LOG_ERR, "radio %s has no map interfaces configured; skip\n", blobmsg_name(c1));
					continue;
				}

				radio = create_radio(radio_id, agent_node->al_mac);
				strcpy(radio->radio_name,blobmsg_name(c1) );
				strcpy(radio->iface_name, ifname);
				update_radio_info(c1, radio);
				update_bss_and_station_info(&list, radio, (char*)blobmsg_name(c1), securityinfo, wpsinfo, stationinfo);
                                strcpy(radio->radio_name,blobmsg_name(c1) );
			}
			status = 0; // assume everything is fine if all the ubus apis returns data
		}
		else
			platform_log(MAP_LIBRARY,LOG_ERR, "failed to get ubus data; error in autoconfig api\n");

                /* Leak detectio Fix */
                blob_buf_free(&stationquery);

		if (radioinfo)
			free(radioinfo);

		if (securityinfo)
			free(securityinfo);
		
		if (wpsinfo)
			free(wpsinfo);

		if (stationinfo)
			free(stationinfo);
	}

	return status;
}


static void map_get_sta_status_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	inout_t* inout = (inout_t*)req->priv;
	struct blob_buf *beacon_query = (struct blob_buf*)inout->outptr;
	char* sta_mac = (char*)inout->inptr;
	struct blob_attr *c1 = NULL;
	struct blob_attr *data1 = blobmsg_data(msg);
	int rem1 = blobmsg_len(msg);

	__blob_for_each_attr(c1, data1, rem1)
	{
		struct blob_attr *c2 = NULL;
		struct blob_attr *data2 = blobmsg_data(c1);
		int rem2 = blobmsg_data_len(c1);
		__blob_for_each_attr(c2, data2, rem2)
		{
			if (strncmp(blobmsg_name(c2), sta_mac, MAX_MAC_STRING_LEN) != 0)
				continue;

			blobmsg_add_string(beacon_query, "name", blobmsg_name(c1));
			break;
		}
	}
}


void process_beacon_report(struct blob_attr *beacon_response, cum_measurement_report_t **beacon_report_ptr)
{
	struct blob_attr *c1 = NULL;
	struct blob_attr *data1 = blobmsg_data(beacon_response);
	int rem1 = blobmsg_len(beacon_response);
	int count = 0;
	
	// find the number of reports to be allocated
	__blob_for_each_attr(c1, data1, rem1)
	{
		count++;
	}
	platform_log(MAP_LIBRARY,LOG_DEBUG, "beacon_report created; size: %d\n", count);

	c1 = NULL;
	data1 = blobmsg_data(beacon_response);
	rem1 = blobmsg_len(beacon_response);

	cum_measurement_report_t *beacon_report =  NULL;
	map_beacon_report_element_t *report_elem = NULL;
	*beacon_report_ptr = (cum_measurement_report_t*)calloc(1, sizeof(cum_measurement_report_t)+
															(count * sizeof(map_beacon_report_element_t)));
	beacon_report = *beacon_report_ptr;
	if (beacon_report) {
		int index = 0;

		__blob_for_each_attr(c1, data1, rem1)
		{
			int age;
			report_elem = &beacon_report->beacon_report[index];

			report_elem->elementId = MEASUREMENT_REPORT_ELEMENTID;
			report_elem->measurement_type = MEASUREMENT_SUBTYPE_BEACON_REPORT;
			report_elem->length = BEACON_REPORT_ELEMENT_SIZE - BEACON_REPORT_ELEMENT_HDR_SIZE;
			
			/* FRV: Until NG-178572 is implemented - after advice of Nicolas Letor, use 0 as measurement time */
			memset(report_elem->measurement_time, 0, BEACON_REPORT_START_TIME_SIZE); 

			platform_get_mac_from_string((char*)blobmsg_name(c1), report_elem->bssid);
		
			struct blob_attr *c2 = NULL;
			struct blob_attr *data2 = blobmsg_data(c1);
			int rem2 = blobmsg_len(c1);
			
			age = 0;
			__blob_for_each_attr(c2, data2, rem2)
			{
				if (strcmp("channel", blobmsg_name(c2)) == 0) {
					report_elem->channel = blobmsg_get_u32(c2);
					report_elem->operating_class = (uint8_t)get_operating_class_basic(report_elem->channel);
				}
				else if (strcmp("rcpi", blobmsg_name(c2)) == 0)
					report_elem->rcpi= blobmsg_get_u32(c2);
				else if (strcmp("rsni", blobmsg_name(c2)) == 0)
					report_elem->rsni = blobmsg_get_u32(c2);
				else if (strcmp("antenna_id", blobmsg_name(c2)) == 0)
					report_elem->antenna_id = blobmsg_get_u32(c2);
				else if (strcmp("duration", blobmsg_name(c2)) == 0) 
                {
                    /* Framing in little endian because the Wifi sniffer capture of radio measurement \
                     * report is in same format; Note: Wifi hostapd changes from little endian to host \
                     * byte order, so this is needed if host is not little endian */
                    report_elem->measurement_duration = host_to_le16(blobmsg_get_u32(c2));

//					report_elem->measurement_duration = htons(blobmsg_get_u32(c2)); /* If needed to frame in network byte order (big endian format) */

                }
                else if (strcmp("age", blobmsg_name(c2)) == 0)
					age = blobmsg_get_u32(c2);
			}

			// FRV: Until NG-178572 is done - filter out too old entries.
			// Request timeout is set to 1 second. Older entries are not from this request
			if (age <= 2)
				index++;
		}
		beacon_report->num_of_reports = index; 
		platform_log(MAP_LIBRARY,LOG_DEBUG, "Number of beacon report records: %d\n", beacon_report->num_of_reports);
	}
	else
		platform_log(MAP_LIBRARY,LOG_ERR, "failed to allocate for map_beacon_report_element\n");
}




static void map_get_sta_status_query_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	inout_t* inout = (inout_t*)req->priv;
	cum_measurement_report_t **beacon_report_ptr = (cum_measurement_report_t **)inout->outptr;

	struct blob_attr *c1 = NULL;
	struct blob_attr *data1 = blobmsg_data(msg);
	int rem1 = blobmsg_len(msg);

	__blob_for_each_attr(c1, data1, rem1)
	{
		struct blob_attr *c2 = NULL;
		struct blob_attr *data2 = blobmsg_data(c1);
		int rem2 = blobmsg_data_len(c1);
		__blob_for_each_attr(c2, data2, rem2)
		{
			struct blob_attr *c3 = NULL;
			struct blob_attr *data3 = blobmsg_data(c2);
			int rem3 = blobmsg_len(c2);

			__blob_for_each_attr(c3, data3, rem3)
			{
				if (strcmp(blobmsg_name(c3), "beacon_report") == 0) {
					process_beacon_report(c3, beacon_report_ptr);
					return;
				}
			}
		}
	}
}


int get_beacon_metrics_response (const char* input, void* data, void *ctx)
{
	cum_measurement_report_t **beacon_report_ptr = (cum_measurement_report_t **)data;
	struct blob_buf beacon_query = {0};
	char target_bssid[MAX_MAC_STRING_LEN] = {0};
	char sta_mac[MAX_MAC_STRING_LEN] = {0};
	json_error_t error;
	inout_t inout;
	int status = -1;

	if (input && data)
	{
		json_t *root = json_loads(input, 0, &error);
		if (root) {
			char* value = NULL;

			if (json_unpack(root, "{s:s}", "sta_mac", &value) == 0){
				strncpy(sta_mac, value, MAX_MAC_STRING_LEN);
				sta_mac[MAX_MAC_STRING_LEN-1] = '\0';
			}

			if (json_unpack(root, "{s:s}", "bssid", &value) == 0) {
				strncpy(target_bssid, value, MAX_MAC_STRING_LEN);
				target_bssid[MAX_MAC_STRING_LEN-1] = '\0';
			}
		}

		blob_buf_init(&beacon_query, 0);
		blobmsg_add_string(&beacon_query, "macaddr", sta_mac);

		inout.inptr = sta_mac;
		inout.outptr = &beacon_query;

		struct blob_buf first_query = {0};
		blob_buf_init(&first_query, 0);
		blobmsg_add_u32(&first_query, "short", 1);

		if (invoke_ubus_command_ex(ctx, "wireless.accesspoint.station", "get", &first_query, NULL, 
									map_get_sta_status_cb, &inout)) {
			blobmsg_add_u32(&beacon_query, "short", 100);
			blobmsg_add_u32(&beacon_query, "beacon_report", 1);

			inout.inptr = NULL;
			inout.outptr = beacon_report_ptr;

			if (invoke_ubus_command_ex(ctx, "wireless.accesspoint.station", "get", &beacon_query, NULL, 
										map_get_sta_status_query_cb, &inout)) {
				status = 0;
			}
			else {
				platform_log(MAP_LIBRARY,LOG_ERR, "ignore the error as it could be due the detail not available\n");
				status = 0;
			}
		}
	}
	return status;
}

uint8_t get_wps_state(char *ap_name,void *ctx)
{
    uint8_t state = -1;
    struct blob_attr *wpsinfo = NULL;
    invoke_ubus_command(ctx, "wireless.accesspoint.wps", "get", NULL, &wpsinfo);
    if(wpsinfo)
    {
        state=get_wps_info(wpsinfo, ap_name);
        free(wpsinfo);
    }
    return state;
}

int get_radio_name_from_if(char* if_name, char* radio_name, void* context)
{
	int status = -1;
        struct blob_buf  input_args = {0};
	if_info_wireless_ssid_t ssid_data = {0};

	strncpy(ssid_data.if_name, if_name, sizeof(ssid_data.if_name));
        blob_buf_init(&input_args, 0);
        blobmsg_add_string(&input_args, "name", if_name);
	if (invoke_ubus_command_ex(context, GET_SSID_DATA, "get", &input_args, NULL, get_if_info_wireless_ssid_cb, &ssid_data))
	{
		status = 0;
	}

	strncpy(radio_name, ssid_data.radio_name, MAX_WIFI_RADIO_NAME_LEN);

	return status;
}

int switch_off_bss(void* data, void *ctx)
{
	int status = 0;
	char tfpath[128];
        char if_name[MAX_IFACE_NAME_LEN];

	memcpy(if_name, data, MAX_IFACE_NAME_LEN);

	sprintf(tfpath, "uci.wireless.wifi-iface.@%s.state", if_name);
	if (write_value_to_transformer(tfpath, "0", true)) {
		platform_log(MAP_LIBRARY,LOG_DEBUG, "%s updated successfully\n", tfpath);
	}
	else {
		platform_log(MAP_LIBRARY,LOG_ERR, "failed to update %s\n", tfpath);
		status = -1;
	}
	return status;	
}

int switch_off_radio(void* data, void *ctx)
{
    int status = 0, flag =0;
    char tfpath[128];
    char radio_name[MAX_WIFI_RADIO_NAME_LEN];
    char if_name[MAX_IFACE_NAME_LEN];
    char result[MAX_WIFI_RADIO_NAME_LEN];
    char *temp = NULL, *token = NULL, *rest = NULL;

    memcpy(if_name, data, MAX_IFACE_NAME_LEN);


    platform_log(MAP_LIBRARY,LOG_DEBUG, "if_name %s \n", if_name);
    if(-1 == get_radio_name_from_if(if_name, radio_name, ctx)) {
        platform_log(MAP_LIBRARY,LOG_ERR,"%s [%d] Failed to get radio name from if name\n", __FUNCTION__, __LINE__);
        return -1;
    }
    platform_log(MAP_LIBRARY,LOG_DEBUG, "radio_name %s \n", radio_name);
    temp = strdup(map_agent_bsslist);
    if (NULL == temp) {
        platform_log(MAP_LIBRARY,LOG_ERR,"%s: %d, memory allocation failed for temp\n", __func__, __LINE__);
        status = -1;
    }
    token = strtok_r(temp, BSS_LIST_DELIMIT, &rest);
    while ( token != NULL) {
        if(!(get_uci_config("wireless",token,"device",result,MAX_WIFI_RADIO_NAME_LEN)))
        {
            platform_log(MAP_LIBRARY,LOG_ERR,"%s: %d, Failed to get wireless data from UCI\n", __func__, __LINE__);
            status = -1;
        }
        if(strncmp(result,radio_name,MAX_WIFI_RADIO_NAME_LEN) == 0)
        {
            sprintf(tfpath, "uci.wireless.wifi-iface.@%s.state", token);
            if (write_value_to_transformer(tfpath, "0", false)) {
                platform_log(MAP_LIBRARY,LOG_DEBUG, "%s updated successfully\n", tfpath);
                flag = 1;
            }
            else {
                platform_log(MAP_LIBRARY,LOG_ERR, "failed to update %s\n", tfpath);
                status = -1;
            }
        }
        token = strtok_r(NULL, BSS_LIST_DELIMIT, &rest);
    }
    if(flag)
        write_loaded_values_to_transformer();
    free(temp);
    return status;
}


int platform_get_outofBand_measurement_support(const char *subcmd, void* data, void *ctx)
{
	struct blob_attr *msg = NULL;
        char * radio_name = (char *)subcmd;
        uint16_t *radio_state = (uint16_t *)data;

        platform_log(MAP_LIBRARY,LOG_DEBUG, "wireless.radio.monitor.station\n");

        invoke_ubus_command(ctx, WIRELESS_UNASSOC_METRICS_OBJ_STR, "get", NULL, &msg);

        if (msg) {

            struct blob_attr *c1 = NULL;
            struct blob_attr *data1 = blobmsg_data(msg);
            int rem1 = blobmsg_data_len(msg);
 
            platform_log(MAP_LIBRARY,LOG_DEBUG, "wireless.radio.monitor success\n");
            __blob_for_each_attr(c1, data1, rem1)  
            {
                if (strncmp(blobmsg_name(c1), radio_name, RADIO_NAME_LEN) == 0) {  
                    struct blob_attr *data2 = blobmsg_data(c1);  
                    struct blob_attr *c2 = NULL;  
                    int rem2 = blobmsg_data_len(c1);  
          
                    __blob_for_each_attr(c2, data2, rem2)  
                    {  
                        if (strcmp(blobmsg_name(c2), "oper_state") == 0) {  
          
                            if(blobmsg_get_u32(c2) > 0) {  
                                set_unassoc_measurement_supported(radio_state);  
                            }  
                            break;  
           	     }
                   }
              }
           }
           /* Leak detection Fix */
           free(msg);
        }
        return 0;
}

int platform_req_unassoc_measurement(void* data, void *ctx)
{
    struct unassoc_platform_cmd *unassoc_data = (struct unassoc_platform_cmd *) data;
    char   sta_mac_str[MAX_MAC_STRING_LEN] = {0};
    struct blob_buf inputbuf       = {};
    struct blob_buf inputbuf_flush = {};
    int    i                       = 0;

    if (NULL == unassoc_data)
    {
         platform_log(MAP_LIBRARY,LOG_ERR,"%s: unassoc_data is NULL",__func__);
         return -1;
    }

    blob_buf_init(&inputbuf_flush, 0);
    blobmsg_add_string(&inputbuf_flush, "name", unassoc_data->radio_name);

    if (invoke_ubus_command_ex(ctx, WIRELESS_UNASSOC_METRICS_OBJ_STR, "flush",
                               &inputbuf_flush, NULL, NULL, NULL) == true)
    {
        platform_log(MAP_LIBRARY,LOG_DEBUG, "unassoc_measurement flush \n");
    }

    if (unassoc_data->cnt > 0)
    {
        for(i = 0; i < unassoc_data->cnt; i++)
        {
            struct measurement_list *unassoc_measurement = (struct measurement_list *) &unassoc_data->list[i];
            if (NULL == unassoc_measurement)
            {
                platform_log(MAP_LIBRARY,LOG_ERR,"%s: List entry is NULL",__func__);
                return -1;
            }

            blob_buf_init(&inputbuf, 0);
            blobmsg_add_string(&inputbuf, "name", unassoc_data->radio_name);
            get_mac_string(unassoc_measurement->mac, sta_mac_str);
            blobmsg_add_string(&inputbuf, "macaddr", sta_mac_str);
            blobmsg_add_u32(&inputbuf, "channel", unassoc_measurement->channel);
            blobmsg_add_u32(&inputbuf, "channel_width", unassoc_data->bw);

            if (invoke_ubus_command_ex(ctx, WIRELESS_UNASSOC_METRICS_OBJ_STR, "add",
                                       &inputbuf, NULL, NULL, NULL) != true)
            {
                platform_log(MAP_LIBRARY,LOG_ERR, "unassoc_measurement failed\n");
                return -1;
            }
        }
    }

    return 0;
}

int platform_flush_unassoc_measurement(void* data, void *ctx)
{
    char *radio_name = (char *) data;
    struct blob_buf inputbuf_flush = {};

    if (NULL == radio_name)
    {
         platform_log(MAP_LIBRARY,LOG_ERR,"%s: radio_name is NULL",__func__);
         return -1;
    }

    blob_buf_init(&inputbuf_flush, 0);
    blobmsg_add_string(&inputbuf_flush, "name", radio_name);

    if (invoke_ubus_command_ex(ctx, WIRELESS_UNASSOC_METRICS_OBJ_STR, "flush",
                               &inputbuf_flush, NULL, NULL, NULL) == true)
    {
        platform_log(MAP_LIBRARY,LOG_DEBUG, "unassoc_measurement flush \n");
    }

    return 0;
}

static void get_unassoc_report_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
    inout_t* inout = (inout_t*)req->priv;
    struct unassoc_response **unassoc_response_ptr = NULL;
    struct unassoc_response *unassoc_response      =  NULL;
        char * radio_name = NULL;

    if (inout) {
        radio_name = (char *)inout->inptr;
        unassoc_response_ptr = (struct unassoc_response **)inout->outptr;

        struct blob_attr *c1 = NULL;
        struct blob_attr *data1 = blobmsg_data(msg);
        int rem1 = blobmsg_data_len(msg);

         __blob_for_each_attr(c1, data1, rem1)
        {
            if (strncmp(blobmsg_name(c1), radio_name, RADIO_NAME_LEN) == 0) {
                struct blob_attr *data2 = blobmsg_data(c1);
                struct blob_attr *c2 = NULL;
                int rem2 = blobmsg_data_len(c1);

                __blob_for_each_attr(c2, data2, rem2)
                {
                    if (strcmp(blobmsg_name(c2), "measurements") == 0) {
                        int sta_cnt = 0;
                        struct blob_attr *data3 = blobmsg_data(c2);
                        struct blob_attr *c3 = NULL;
                        int rem3 = blobmsg_data_len(c2);
                        int  index = 0;

                        sta_cnt = blobmsg_check_array(c2, BLOBMSG_TYPE_TABLE);
                        unassoc_response = (struct unassoc_response *)malloc(sizeof(struct unassoc_response) + (sizeof(struct unassoc_report_list) * sta_cnt));
                        if(unassoc_response == NULL) {
                            goto Failure;
                        }

                        strncpy(unassoc_response->radio_name, radio_name, MAX_RADIO_NAME_LEN);

                        __blob_for_each_attr(c3, data3, rem3)
                        {
                            struct blob_attr *data4 = blobmsg_data(c3);
                            struct blob_attr *c4 = NULL;
                            int rem4 = blobmsg_data_len(c3);

                            if(!platform_get_mac_from_string((char *)blobmsg_name(c3), unassoc_response->list[index].sta_mac)) {
                                platform_log(MAP_LIBRARY,LOG_ERR, "%s %d, ubus failure to decode sta_mac in unassoc sta metrics \n",__func__, __LINE__);
                                goto Failure;
                            }

                            __blob_for_each_attr(c4, data4, rem4)
                            {
                                if (strcmp(blobmsg_name(c4), "age") == 0) {
                                    unassoc_response->list[index].age = blobmsg_get_u32(c4);
                                } else if (strcmp(blobmsg_name(c4), "channel") == 0) {
                                    unassoc_response->list[index].channel = (uint8_t)blobmsg_get_u32(c4);
                                } else if (strcmp(blobmsg_name(c4), "rssi") == 0) {
                                    int rssi = (int)blobmsg_get_u32(c4);

                                    if (rssi <= -110)
                                        unassoc_response->list[index].ulrcpi = 0;
                                    else if (rssi >= 0)
                                        unassoc_response->list[index].ulrcpi = 220;
                                    else
                                        unassoc_response->list[index].ulrcpi = 2 * (rssi + 110);

                                } else if (strcmp(blobmsg_name(c4), "event") == 0) {
                                    if (strcmp((char *)blobmsg_get_string(c4), "timeout") != 0) {
                                       index++;
                                    }
                                    else {
                                       platform_log(MAP_LIBRARY,LOG_DEBUG,"%s:Ignoring timeout event",__func__);
                                    }
                                }
                            }
                        }
                        unassoc_response->sta_cnt = index;
                        platform_log(MAP_LIBRARY,LOG_DEBUG,"Number of reports : %d\n", unassoc_response->sta_cnt);
                        break;
                    }
                }
                break;
            }
        }

        *unassoc_response_ptr = unassoc_response;
    }
    return;

Failure:
    *unassoc_response_ptr = NULL;
    free(unassoc_response);
    return;
}

int platform_get_unassoc_report(const char* subcmd, void* config, void *ctx)  
{  
	inout_t inout;  
	struct blob_buf inputbuf = {};  
        char * radio_name = (char *)subcmd;  
  
        platform_log(MAP_LIBRARY,LOG_DEBUG, "wireless.radio.monitor.station\n");  
  
        inout.inptr = radio_name;  
        inout.outptr = config;  
  
    	blob_buf_init(&inputbuf, 0);  
    	blobmsg_add_string(&inputbuf, "name", radio_name);  
        if (invoke_ubus_command_ex(ctx, WIRELESS_UNASSOC_METRICS_OBJ_STR, "get", &inputbuf, NULL, get_unassoc_report_cb, &inout)) {  
            platform_log(MAP_LIBRARY,LOG_DEBUG, "wireless.radio.monitor success\n");  
  
        }  
        blob_buf_free(&inputbuf);  
	  
        return 0;  
}

int platform_set_channel(void* data, void *ctx)
{
    platform_cmd_channel_set_t *channel_info = (platform_cmd_channel_set_t*) data;
    struct blob_buf inputbuf={0};
    int status = -1;
    struct ubus_context* ubusctx = (struct ubus_context*)ctx;
    uint32_t id = 0;
    if (data) {
        blob_buf_init(&inputbuf, 0);
        platform_log(MAP_LIBRARY,LOG_DEBUG, "set channel %s- %s %d\n",__func__, channel_info->radio_name, channel_info->channel);
        blobmsg_add_string(&inputbuf, "name", channel_info->radio_name);
        blobmsg_add_u32(&inputbuf, "channel", channel_info->channel);

        if(ubus_lookup_id(ubusctx, "wireless.radio.acs", &id) == UBUS_STATUS_OK) {
            if (ubus_invoke(ubusctx, id, "forced_acs_channel", inputbuf.head, NULL, 0, 5000) == UBUS_STATUS_OK) {
                platform_log(MAP_LIBRARY,LOG_DEBUG, "%s %d channel change success\n",__func__, __LINE__);
                status = 0;
            } else {
                platform_log(MAP_LIBRARY,LOG_DEBUG, "%s %d channel change Failure\n",__func__, __LINE__);
            }
        }
	    blob_buf_free(&inputbuf);
    }

    return status;
}

static void get_neighbour_tx_link_met_wifi (struct ubus_request *req, int type, struct blob_attr *msg) {

    struct _txLinkMetricEntries *tx_link_met = (struct _txLinkMetricEntries *)req->priv;

    if(tx_link_met == NULL)
        return;

    struct blob_attr *c1 = NULL;
    struct blob_attr *data1 = blobmsg_data(msg);
    int rem1 = blobmsg_len(msg);
    __blob_for_each_attr(c1, data1, rem1)
    {
            struct blob_attr *c2 = NULL;
            struct blob_attr *data2 = blobmsg_data(c1);
            int rem2 = blobmsg_data_len(c1);
            __blob_for_each_attr(c2, data2, rem2)
            {
                    struct blob_attr *c3 = NULL;
                    struct blob_attr *data3 = blobmsg_data(c2);
                    int rem3 = blobmsg_len(c2);

                    __blob_for_each_attr(c3, data3, rem3)
                    {

                        if (strcmp (blobmsg_name(c3), "tx_packets") == 0) {
                            tx_link_met->transmitted_packets = (uint32_t)blobmsg_get_u64(c3);
                        }
                        if (strcmp (blobmsg_name(c3),"tx_phy_rate") == 0) {

                             tx_link_met->phy_rate = (uint16_t)(blobmsg_get_u32(c3)/1000);   /* refer in terms of Mbps */
                            tx_link_met->mac_throughput_capacity = tx_link_met->phy_rate * 80 / 100;
                        }
                    }
            }
    }
    return;
}

static void get_neighbour_rx_link_met_wifi (struct ubus_request *req, int type, struct blob_attr *msg) {

    struct _rxLinkMetricEntries *rx_link_met = (struct _rxLinkMetricEntries *)req->priv;

    if(rx_link_met == NULL)
        return;

    struct blob_attr *c1 = NULL;
    struct blob_attr *data1 = blobmsg_data(msg);
    int rem1 = blobmsg_len(msg);
    __blob_for_each_attr(c1, data1, rem1)
    {
            struct blob_attr *c2 = NULL;
            struct blob_attr *data2 = blobmsg_data(c1);
            int rem2 = blobmsg_data_len(c1);
            __blob_for_each_attr(c2, data2, rem2)
            {
                    struct blob_attr *c3 = NULL;
                    struct blob_attr *data3 = blobmsg_data(c2);
                    int rem3 = blobmsg_len(c2);
                    __blob_for_each_attr(c3, data3, rem3)
                    {
                        if (strcmp (blobmsg_name(c3), "rssi") == 0) {
                            rx_link_met->rssi = (uint16_t)blobmsg_get_u32(c3);
                        }
                        if (strcmp (blobmsg_name(c3), "rx_packets") == 0) {
                             rx_link_met->packets_received = (uint32_t)blobmsg_get_u64(c3);    
                        }
                    }
            }
    }
    return;
}

int get_bssid_from_iface_name (void *ctx, char* iface_name, uint8_t *bssid) {

        struct blob_attr *msg = NULL;
        struct blob_buf  input_args = {0};

        if(iface_name == NULL) return -EINVAL;

        blob_buf_init(&input_args, 0);

        blobmsg_add_string(&input_args, "name", iface_name);
        invoke_ubus_command(ctx, "wireless.ssid", "get", &input_args, &msg);


        if(msg) {
            struct blob_attr *c1    = NULL; // first level
            struct blob_attr *data1 = blobmsg_data(msg);
            int rem1 = blobmsg_data_len(msg);
		
           __blob_for_each_attr(c1, data1, rem1)
           { 
                struct blob_attr *c2    = NULL; // first level
                struct blob_attr *data2 = blobmsg_data(c1);
                int rem2 = blobmsg_data_len(c1);

                if(0 == strcmp(blobmsg_name(c1), iface_name)) {
                   __blob_for_each_attr(c2, data2, rem2)
                   { 

                        if(0 == strcmp(blobmsg_name(c2),"bssid")) {
                            platform_get_mac_from_string(blobmsg_get_string(c2), bssid);
                            /* Leak Detection Fix */
                            free(msg);
                            blob_buf_free(&input_args);
                            return 0;
                        }
                   }
               }
           }
           /* Leak Detection Fix */
           free(msg);
        }
        /* Leak detectio Fix */
        blob_buf_free(&input_args);

        return -EINVAL;
}


int get_radio_name_from_bssid (void *ctx, uint8_t *bssid, char *radio_name) {

        struct blob_attr *msg = NULL;
	uint8_t ubus_bssid[6] = {0};
	uint8_t bssid_found   = 0;

        invoke_ubus_command(ctx, "wireless.ssid", "get", NULL, &msg);

        if(msg) {
            struct blob_attr *c1    = NULL; // first level
            struct blob_attr *data1 = blobmsg_data(msg);
            int rem1 = blobmsg_data_len(msg);
		
           __blob_for_each_attr(c1, data1, rem1)
           { 
                struct blob_attr *c2    = NULL; // first level
                struct blob_attr *data2 = blobmsg_data(c1);
                int rem2 = blobmsg_data_len(c1);

               __blob_for_each_attr(c2, data2, rem2)
               { 
                    if(0 == strcmp(blobmsg_name(c2),"radio")) {
                        strncpy(radio_name, blobmsg_get_string(c2), 32);
                    } else if(0 == strcmp(blobmsg_name(c2),"bssid")) {
                        platform_get_mac_from_string(blobmsg_get_string(c2), ubus_bssid);
                        if(memcmp(ubus_bssid, bssid, 6) == 0) {
                            bssid_found = 1;
                            break;
                        }
                    }
               }

               if(bssid_found == 1) {
                   free(msg);
                   return 0;
               }
           }
           /* Leak Detection Fix */
           free(msg);
        }
        return -EINVAL;
}


int get_radio_type_from_name (void *ctx, uint16_t *mediatype, char *radio_name) {

        struct blob_attr *msg = NULL;
        int ret = -EINVAL;
        char *saveptr = NULL;
        struct blob_buf  input_args = {0};

        if(radio_name == NULL || mediatype == NULL)
            return ret;


        blob_buf_init(&input_args, 0);
        blobmsg_add_string(&input_args, "name", radio_name);
        invoke_ubus_command(ctx, "wireless.radio", "get", &input_args, &msg);

        if (msg) {
            struct blob_attr *c1    = NULL; // first level
            int rem1                = 0;
		
            blobmsg_for_each_attr(c1, blobmsg_data(msg), rem1)
            {
                if(0 == strcmp(blobmsg_name(c1),"capabilities")) {
                        char *str = strdup(blobmsg_get_string(c1));

                        char* cap = strtok_r(str, " ", &saveptr);
                        if (cap) {
                                if (strcmp(cap, "802.11b") == 0) {
                                   *mediatype = MEDIA_IEEE_802_11B_2_4_GHZ;
                                    ret = 0;
                                } else if(strcmp(cap, "802.11g") == 0) {
                                   *mediatype = MEDIA_IEEE_802_11G_2_4_GHZ;
                                    ret = 0;
                                } else if(strcmp(cap, "802.11a") == 0) {
                                   *mediatype = MEDIA_IEEE_802_11A_5_GHZ;
                                    ret = 0;
                                } else if(strcmp(cap, "802.11n") == 0) {
                                   *mediatype = MEDIA_IEEE_802_11N_2_4_GHZ;
                                   ret = 0;
                                } else if(strcmp(cap, "802.11bgn") == 0) {
                                   *mediatype = MEDIA_IEEE_802_11N_2_4_GHZ;
                                   ret = 0;
                                } else if(strcmp(cap, "802.11ac") == 0) {
                                   *mediatype = MEDIA_IEEE_802_11AC_5_GHZ;
                                   ret = 0;
                                } else if(strcmp(cap, "802.11an") == 0) {
                                   *mediatype = MEDIA_IEEE_802_11N_5_GHZ;
                                   ret = 0;
                                } else if(strcmp(cap, "802.11anac") == 0) {
                                   *mediatype = MEDIA_IEEE_802_11N_5_GHZ;
                                   ret = 0;
                                } else {
                                   platform_log(MAP_LIBRARY,LOG_ERR, "Unsupported Media type");
                                   *mediatype = 0;
                                }
                        }
                        /* Leak Detection Fix */
                        blob_buf_free(&input_args);
                        free(msg);
                        free(str);
                        return ret;
                }
            }
            /* Leak Detection Fix */
            free(msg);
        }

        /* Leak Detection Fix */
        blob_buf_free(&input_args);

        return ret;
}



static void get_neighbour_rx_link_met_eth (struct ubus_request *req, int type, struct blob_attr *msg) {

    struct  _rxLinkMetricEntries *rx_link_met = (struct  _rxLinkMetricEntries *)req->priv;

    if(rx_link_met == NULL)
        return;

    struct blob_attr *c1 = NULL;
    struct blob_attr *data1 = blobmsg_data(msg);
    int rem1 = blobmsg_len(msg);
    __blob_for_each_attr(c1, data1, rem1)
    {
            struct blob_attr *c2 = NULL;
            struct blob_attr *data2 = blobmsg_data(c1);
            int rem2 = blobmsg_data_len(c1);

            if (strcmp (blobmsg_name(c1), "macaddr") == 0)
                platform_get_mac_from_string(blobmsg_get_string(c1), rx_link_met->local_interface_address);

            if (strcmp (blobmsg_name(c1), "statistics") == 0) {
                __blob_for_each_attr(c2, data2, rem2)
                {
                    if (strcmp (blobmsg_name(c2), "rx_packets") == 0) {
                        rx_link_met->packets_received = (uint32_t)blobmsg_get_u64(c2);
                    }

                    if (strcmp (blobmsg_name(c2),"rx_errors") == 0) {
                        rx_link_met->packet_errors = blobmsg_get_u64(c2);
                    }
                }
            }
    }
    return;
}


static void get_neighbour_tx_link_met_eth (struct ubus_request *req, int type, struct blob_attr *msg) {

    struct _txLinkMetricEntries *tx_link_met = (struct  _txLinkMetricEntries *)req->priv;

    if(tx_link_met == NULL)
        return;

    struct blob_attr *c1 = NULL;
    struct blob_attr *data1 = blobmsg_data(msg);
    int rem1 = blobmsg_len(msg);
    __blob_for_each_attr(c1, data1, rem1)
    {
            struct blob_attr *c2 = NULL;
            struct blob_attr *data2 = blobmsg_data(c1);
            int rem2 = blobmsg_data_len(c1);

            if (strcmp (blobmsg_name(c1), "macaddr") == 0)
                platform_get_mac_from_string(blobmsg_get_string(c1), tx_link_met->local_interface_address);

            if (strcmp (blobmsg_name(c1), "statistics") == 0) {
                __blob_for_each_attr(c2, data2, rem2)
                {
                    if (strcmp (blobmsg_name(c2), "tx_packets") == 0) {
                        tx_link_met->transmitted_packets = blobmsg_get_u64(c2);
                    }

                    if (strcmp (blobmsg_name(c2),"tx_errors") == 0) {
                        tx_link_met->packet_errors = blobmsg_get_u64(c2);
                    }

                }
            }
    }
    return;
}


static void get_neighbour_tx_link_avail_wifi(struct ubus_request *req, int type, struct blob_attr *msg)
{
    struct _txLinkMetricEntries *tx_link_met = (struct _txLinkMetricEntries *)req->priv;

    if(tx_link_met == NULL)
        return;

    struct blob_attr *c1 = NULL;
    struct blob_attr *data1 = blobmsg_data(msg);
    int rem1 = blobmsg_data_len(msg);

    __blob_for_each_attr(c1, data1, rem1)
    {
            struct blob_attr *data2 = blobmsg_data(c1);
            struct blob_attr *c2 = NULL;
            int rem2 = blobmsg_data_len(c1);

            __blob_for_each_attr(c2, data2, rem2)
            {
                    if (strcmp(blobmsg_name(c2), "medium_available") == 0) {
                        tx_link_met->link_availability = blobmsg_get_u32(c2);
                        break;
                    }
            }
    }
}


int fill_tx_met_tlv (void *ctx, struct txLinkMetricTLV *tx_tlv, struct neighbour_entry*   neighbour_dev)
{
    int status = -EINVAL;

    if(tx_tlv == NULL || neighbour_dev == NULL)
	    return -EINVAL;

    tx_tlv->tlv_type      =  TLV_TRANSMITTER_LINK_METRIC;
    memcpy(tx_tlv->local_al_address, neighbour_dev->local_almac, MAC_ADDR_LEN);
    memcpy(tx_tlv->neighbor_al_address, neighbour_dev->neighbour_almac, MAC_ADDR_LEN);
	
    tx_tlv->transmitter_link_metrics = (struct _txLinkMetricEntries *)calloc(1, sizeof(struct _txLinkMetricEntries));
    if(tx_tlv->transmitter_link_metrics == NULL) {
	    return -EINVAL;
    }

    tx_tlv->transmitter_link_metrics_nr = 1;


    memcpy(tx_tlv->transmitter_link_metrics[0].neighbor_interface_address, neighbour_dev->neighbour_iface_mac, MAC_ADDR_LEN);

    if ((NULL != strstr(neighbour_dev->interface_name, "eth")) || (NULL != strstr(neighbour_dev->interface_name, "lo"))) {
        if (invoke_ubus_command_ex(ctx, "network.device", "status", NULL, neighbour_dev->interface_name, get_neighbour_tx_link_met_eth, &tx_tlv->transmitter_link_metrics[0]))
        {
            tx_tlv->transmitter_link_metrics[0].bridge_flag = 0;
            tx_tlv->transmitter_link_metrics[0].mac_throughput_capacity = ONE_Gbps;
            tx_tlv->transmitter_link_metrics[0].link_availability = 100;
            tx_tlv->transmitter_link_metrics[0].phy_rate = ONE_Gbps;
            tx_tlv->transmitter_link_metrics[0].intf_type = MEDIA_IEEE_802_3AB_GIGABIT_ETHERNET;
            status = 0;
        } else {
            /* Free the tx_tlv->transmitter_link_metrics here */
            free(tx_tlv->transmitter_link_metrics);
            tx_tlv->transmitter_link_metrics = NULL;
        }

    } else if ((NULL != strstr(neighbour_dev->interface_name, "wds")) || 
            (NULL != strstr(neighbour_dev->interface_name, "wl"))) {

        struct blob_buf  input_args = {0};
        char   mac_addr_str[MAX_MAC_STRING_LEN] = {0};
	
        blob_buf_init(&input_args, 0);
        blobmsg_add_u32(&input_args, "short", 1);

        get_mac_as_str(neighbour_dev->neighbour_iface_mac, (int8_t *)mac_addr_str, MAX_MAC_STRING_LEN);

        blobmsg_add_string(&input_args, "macaddr", mac_addr_str);

        if (invoke_ubus_command_ex(ctx, "wireless.accesspoint.station", "get", &input_args, NULL, get_neighbour_tx_link_met_wifi, &tx_tlv->transmitter_link_metrics[0]))
        {
            char radio_name[MAX_WIFI_RADIO_NAME_LEN] = {0};
            char underlying_if[MAX_IFACE_NAME_LEN] = {'\0'};

            if (NULL != strstr(neighbour_dev->interface_name, "wds")) {
                //Find underlying interface, assumption here is, it starts with "wl"
                platform_get_wds_underlying_if(neighbour_dev->interface_name, underlying_if, sizeof(underlying_if));
                if('\0' == underlying_if[0]) {
                    platform_log(MAP_LIBRARY,LOG_ERR, "%s Undelying interface name not found \n", __FUNCTION__);
                    /* Now Free the tx_link_met */
                    free(tx_tlv->transmitter_link_metrics);
                    tx_tlv->transmitter_link_metrics = NULL;
                    return -EINVAL;
                }

                strncpy(neighbour_dev->interface_name, underlying_if, sizeof(neighbour_dev->interface_name));
            }
            
            if (get_radio_name_from_if(neighbour_dev->interface_name, radio_name, ctx) < 0) {
                /* Now Free the tx_link_met */
                free(tx_tlv->transmitter_link_metrics);
                tx_tlv->transmitter_link_metrics = NULL;
                return -EINVAL;
            }

            if (get_radio_type_from_name(ctx, &tx_tlv->transmitter_link_metrics[0].intf_type, radio_name) < 0) {
                /* Now Free the tx_link_met */
                platform_log(MAP_LIBRARY,LOG_ERR, "%s %d, Failure to get radio type for %s\n",__func__, __LINE__, neighbour_dev->interface_name);
                free(tx_tlv->transmitter_link_metrics);
                tx_tlv->transmitter_link_metrics = NULL;
                return -EINVAL;
            }

            if(get_bssid_from_iface_name(ctx, neighbour_dev->interface_name,
             tx_tlv->transmitter_link_metrics[0].local_interface_address) < 0) {
                /* Now Free the tx_link_met */
                platform_log(MAP_LIBRARY,LOG_ERR, "%s %d, Failure to get bssid %s\n",__func__, __LINE__, neighbour_dev->interface_name);
                free(tx_tlv->transmitter_link_metrics);
                tx_tlv->transmitter_link_metrics = NULL;
                return -EINVAL;
            }

            // Get Link availability
            if (invoke_ubus_command_ex(ctx, "wireless.radio.acs.channel_stats", "get", NULL, radio_name, get_neighbour_tx_link_avail_wifi, &tx_tlv->transmitter_link_metrics[0])) {
                status  = 0;       
            } else {
                /* Free the tx_tlv->transmitter_link_metrics here */
                platform_log(MAP_LIBRARY,LOG_ERR, "%s %d, Failure to get medium availability for %s\n",__func__, __LINE__, neighbour_dev->interface_name);
                free(tx_tlv->transmitter_link_metrics);
                tx_tlv->transmitter_link_metrics = NULL;
            }
        }
    }
    return status;
}

int platform_neighbour_tx_link(const char* neighbour_dev_ptr, void* tx_met, void *ctx)
{

    struct neighbour_entry*   neighbour_dev = (struct neighbour_entry*)neighbour_dev_ptr;

    if(neighbour_dev == NULL) 
       return -EINVAL;

    struct txLinkMetricTLV **tx_tlv_ptr = (struct txLinkMetricTLV **)tx_met;
    if(tx_tlv_ptr == NULL)
        return -EINVAL;

    *tx_tlv_ptr = NULL;
    struct txLinkMetricTLV *tx_tlv = (struct txLinkMetricTLV *)calloc(1, sizeof(struct txLinkMetricTLV));
    if(tx_tlv == NULL) 
        return -EINVAL;

    if(fill_tx_met_tlv(ctx, tx_tlv, neighbour_dev) < 0) {
         free(tx_tlv);
         return -EINVAL;
    }

    /* Fill the return pointer */
    *tx_tlv_ptr = tx_tlv;

    return 0;
}


int fill_rx_met_tlv (void *ctx, struct rxLinkMetricTLV *rx_tlv, struct neighbour_entry*   neighbour_dev)
{

    int status = -EINVAL;

    if(rx_tlv == NULL || neighbour_dev == NULL)
         return -EINVAL;

    rx_tlv->tlv_type      =  TLV_RECEIVER_LINK_METRIC;

    memcpy(rx_tlv->local_al_address, neighbour_dev->local_almac, MAC_ADDR_LEN);
    memcpy(rx_tlv->neighbor_al_address, neighbour_dev->neighbour_almac, MAC_ADDR_LEN);

    rx_tlv->receiver_link_metrics = (struct  _rxLinkMetricEntries *)calloc(1, sizeof(struct  _rxLinkMetricEntries));
    if(rx_tlv->receiver_link_metrics == NULL) {
        return -EINVAL;
    }

    rx_tlv->receiver_link_metrics_nr = 1;

    memcpy(rx_tlv->receiver_link_metrics[0].neighbor_interface_address, neighbour_dev->neighbour_iface_mac, MAC_ADDR_LEN);


    if ((NULL != strstr(neighbour_dev->interface_name, "eth")) || (NULL != strstr(neighbour_dev->interface_name, "lo"))) {

        if (invoke_ubus_command_ex(ctx, "network.device", "status", NULL, neighbour_dev->interface_name, get_neighbour_rx_link_met_eth, &rx_tlv->receiver_link_metrics[0]))
        {
            status = 0;
            rx_tlv->receiver_link_metrics[0].intf_type = MEDIA_IEEE_802_3AB_GIGABIT_ETHERNET;
            rx_tlv->receiver_link_metrics[0].rssi = 0xff;
        } else {
            /* For the failure case just free, the recv_link_metrics */
            free(rx_tlv->receiver_link_metrics);
            rx_tlv->receiver_link_metrics = NULL;
        }

    } else if ((NULL != strstr(neighbour_dev->interface_name, "wds")) || 
            (NULL != strstr(neighbour_dev->interface_name, "wl"))) {
         char radio_name[MAX_WIFI_RADIO_NAME_LEN] = {0};
         struct blob_buf  input_args = {0};
         char   mac_addr_str[MAX_MAC_STRING_LEN] = {0};
         char underlying_if[MAX_IFACE_NAME_LEN] = {'\0'};

         blob_buf_init(&input_args, 0);
         blobmsg_add_u32(&input_args, "short", 1);

         get_mac_as_str(neighbour_dev->neighbour_iface_mac, (int8_t *)mac_addr_str, MAX_MAC_STRING_LEN);

        blobmsg_add_string(&input_args, "macaddr", mac_addr_str);

        if (NULL != strstr(neighbour_dev->interface_name, "wds")) {
            //Find underlying interface, assumption here is, it starts with "wl"
            platform_get_wds_underlying_if(neighbour_dev->interface_name, underlying_if, sizeof(underlying_if));
            if('\0' == underlying_if[0]) {
                platform_log(MAP_LIBRARY,LOG_ERR, "%s Undelying interface name not found \n", __FUNCTION__);
                /* For the failure case just free, the recv_link_metrics */
                free(rx_tlv->receiver_link_metrics);
                rx_tlv->receiver_link_metrics = NULL;
                return -EINVAL;
            }

            strncpy(neighbour_dev->interface_name, underlying_if, sizeof(neighbour_dev->interface_name));
        }

        if (get_radio_name_from_if(neighbour_dev->interface_name, radio_name, ctx) < 0) {
            /* For the failure case just free, the recv_link_metrics */
            free(rx_tlv->receiver_link_metrics);
            rx_tlv->receiver_link_metrics = NULL;
            return -EINVAL;
        }

        if (get_radio_type_from_name(ctx, &rx_tlv->receiver_link_metrics[0].intf_type, radio_name) < 0) {
            /* For the failure case just free, the recv_link_metrics */
            platform_log(MAP_LIBRARY,LOG_ERR, "%s %d, Failure to get radio type for %s\n",__func__, __LINE__, neighbour_dev->interface_name);
            free(rx_tlv->receiver_link_metrics);
            rx_tlv->receiver_link_metrics = NULL;
            return -EINVAL;
        }

        if(get_bssid_from_iface_name(ctx, neighbour_dev->interface_name,
             rx_tlv->receiver_link_metrics[0].local_interface_address) < 0) {
            platform_log(MAP_LIBRARY,LOG_ERR, "%s %d, Failure to get bssid %s\n",__func__, __LINE__, neighbour_dev->interface_name);
            /* For the failure case just free, the recv_link_metrics */
            free(rx_tlv->receiver_link_metrics);
            rx_tlv->receiver_link_metrics = NULL;
            return -EINVAL;
        }


        if (invoke_ubus_command_ex(ctx, "wireless.accesspoint.station", "get", &input_args, NULL, get_neighbour_rx_link_met_wifi, &rx_tlv->receiver_link_metrics[0]))
        {
            status = 0;
        } else {
            platform_log(MAP_LIBRARY,LOG_ERR, "%s %d, Failure to get wireless.accesspoint.station for %s\n",__func__, __LINE__, neighbour_dev->interface_name);
            /* For the failure case just free, the recv_link_metrics */
            free(rx_tlv->receiver_link_metrics);
            rx_tlv->receiver_link_metrics = NULL;
        }
    }

    return status;
}



int platform_neighbour_rx_link(const char* neighbour_dev_ptr, void* rx_met, void *ctx)
{

    struct neighbour_entry*   neighbour_dev = (struct neighbour_entry*)neighbour_dev_ptr;

    if(neighbour_dev == NULL) 
        return -EINVAL;

    struct rxLinkMetricTLV **rx_tlv_ptr = (struct rxLinkMetricTLV **)rx_met;
    if(rx_tlv_ptr == NULL)
        return -EINVAL;

    *rx_tlv_ptr = NULL;
    struct rxLinkMetricTLV *rx_tlv = (struct rxLinkMetricTLV *)calloc(1, sizeof(struct rxLinkMetricTLV));
    if(rx_tlv == NULL) 
        return -EINVAL;

    if(fill_rx_met_tlv(ctx, rx_tlv, neighbour_dev) < 0) {
        free(rx_tlv);
        return -EINVAL;
    }

    /* Fill the return pointer */
    *rx_tlv_ptr = rx_tlv;
    return 0;
}

int platform_send_stn_evt(void* data, void *ctx)
{
    int status = 0;
    stn_event_platform_cmd_t *stn_evt = (stn_event_platform_cmd_t*) data;
    struct blob_buf inputbuf = {};  

    if(NULL != stn_evt) {
        blob_buf_init(&inputbuf, 0);
        blobmsg_add_string(&inputbuf, "event", stn_evt->event ? "connect" : "disconnect");
        blobmsg_add_string(&inputbuf, "station", (const char*)stn_evt->sta); 
        blobmsg_add_string(&inputbuf, "bssid", (const char*)stn_evt->bssid);

        ubus_send_event(ctx, "map_controller.ess_station", inputbuf.head);
        blob_buf_free(&inputbuf);
    }
    
    return status;
}

int platform_set_tx_pwr(void* data, void *ctx)
{
    platform_cmd_tx_pwr_set_t  *tx_pwr_info = (platform_cmd_tx_pwr_set_t*)data;
    int status = 0;
    int tx_power_adjust = 0;
    char tfpath[128]     = {0};
    char input_str[32]   = {0};
    
    if (data) {
        /* Get max target power of the radio for current operating class */        
        struct blob_attr *msgptr = NULL;
        struct blob_buf inputbuf = {};  
        float max_targetpwr = 0.0;
      
        blob_buf_init(&inputbuf, 0);  
        blobmsg_add_string(&inputbuf, "name", tx_pwr_info->radio_name); 
        invoke_ubus_command(ctx, WIRELESS_RADIO_EVENT_STR, "get", &inputbuf, &msgptr); 
        if (msgptr) {
            platform_log(MAP_LIBRARY,LOG_DEBUG, "wireless.radio  success\n"); 
            
            struct blob_attr *data1 = NULL, *c1 = NULL; // first level
            data1 = blobmsg_data(msgptr);
            int rem1 = blobmsg_data_len(msgptr);
      
            __blob_for_each_attr(c1, data1, rem1) { 
               if( strcmp(blobmsg_name(c1), tx_pwr_info->radio_name) == 0) {
                   struct blob_attr *data2 = blobmsg_data(c1);
                   int rem2 = blobmsg_data_len(c1);
                   struct blob_attr *c2 = NULL; // second level
                   
                   __blob_for_each_attr(c2, data2, rem2) {  
                      if(strcmp("max_target_power",blobmsg_name(c2)) == 0) {
                          max_targetpwr = atof(blobmsg_get_string(c2));
                          platform_log(MAP_LIBRARY,LOG_DEBUG,"%s current max_target_power = %f\n",__FUNCTION__, max_targetpwr);      
                          break;
                      }
                  } 
                  break;
               }
            }
            free(msgptr);
        }         
        blob_buf_free(&inputbuf);

        if(max_targetpwr) {
            sprintf(tfpath, "uci.wireless.wifi-device.@%s.tx_power_adjust", tx_pwr_info->radio_name);
            if(max_targetpwr > tx_pwr_info->new_tx_pwr) {
                tx_power_adjust = tx_pwr_info->new_tx_pwr - max_targetpwr;
                platform_log(MAP_LIBRARY,LOG_ERR, "%s radio %s : requested power %d is within limit of max power %f\n", __FUNCTION__, 
                             tx_pwr_info->radio_name, tx_pwr_info->new_tx_pwr, max_targetpwr);
            }

            snprintf(input_str, sizeof(input_str), "%d", tx_power_adjust);      
            platform_log(MAP_LIBRARY,LOG_DEBUG, "%s Tx power to be adjusted  %s\n", __FUNCTION__,input_str); 

            if (write_value_to_transformer(tfpath, input_str, true)) {
                platform_log(MAP_LIBRARY,LOG_DEBUG, "%s updated successfully\n", tfpath);
            } else {
                status = -1;
                platform_log(MAP_LIBRARY,LOG_ERR, "%s failed to update %s\n", __FUNCTION__,tfpath);
            }   

        }else {
            platform_log(MAP_LIBRARY,LOG_ERR, "%s Max target power %f \n", __FUNCTION__,max_targetpwr);
        }
    }
    
    return status;
}


int platform_get_tx_pwr(const char* subcmd, void* tx_pwr, void *ctx)  
{  
	struct blob_attr *msgptr = NULL;
	struct blob_buf inputbuf = {};
    char * radio_name = (char *)subcmd;
    uint8_t *current_tx_pwr = (uint8_t *)tx_pwr;

    platform_log(MAP_LIBRARY,LOG_DEBUG, "wireless.radio get\n");  
	blob_buf_init(&inputbuf, 0);  
	blobmsg_add_string(&inputbuf, "name", radio_name);  
    invoke_ubus_command(ctx, WIRELESS_RADIO_EVENT_STR, "get", &inputbuf, &msgptr); 
    if (msgptr) {
        platform_log(MAP_LIBRARY,LOG_DEBUG, "wireless.radio  success\n"); 
        
        struct blob_attr *data1 = NULL, *c1 = NULL; // first level
        data1 = blobmsg_data(msgptr);
        int rem1 = blobmsg_data_len(msgptr);

        __blob_for_each_attr(c1, data1, rem1) { 
           if( strcmp(blobmsg_name(c1), radio_name) == 0) {
               struct blob_attr *data2 = blobmsg_data(c1);
               int rem2 = blobmsg_data_len(c1);
               struct blob_attr *c2 = NULL; // second level
               
           __blob_for_each_attr(c2, data2, rem2) {

                  if(strcmp("max_target_power_adjusted",blobmsg_name(c2)) == 0) {
                      int pwr = atoi(blobmsg_get_string(c2));
                      *current_tx_pwr = (pwr < 0) ? 0 : pwr;
                      platform_log(MAP_LIBRARY,LOG_DEBUG,"current tx_pwr = %d\n",*current_tx_pwr);

                      free(msgptr);
                      blob_buf_free(&inputbuf);
                      return 0;
                  }
              } 
              break;
           }
        } 
    } 
    free(msgptr);
    blob_buf_free(&inputbuf);
    return 0;  
}
