/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

#include <uv.h>
#include <libubox/blob.h>
#include <libubox/blobmsg.h>
#include <libubox/uloop.h>
#include "monitor_task.h"
#include "map_events.h"
#include "map_ipc_event_publisher.h"
#include "platform_utils.h"
#include "platform_map.h"
#include "mon_platform.h"
#include "1905_platform.h"
#include "errno.h"


#define BACKHAUL_METRICS_COLLECTION			(0x01 << 0)
#define AP_METRICS_COLLECTION				(0x01 << 1)
#define STATION_LINK_METRICS_COLLECTION		(0x01 << 2)

#define RSSI_THRESHOLD_MONITOR				(0x01 << 0)
#define CAHNNEL_UTIL_THRESHOLD_MONITOR		(0x01 << 1)

#define DATA_COLLECTION_TIMEOUT_MSEC		(1000)

/* Monitor instance structure */
typedef struct _map_monitor_ctx_t {
	uint8_t data_collection_mask;
	uint8_t threshold_mask;
	bool is_controller;
	uint32_t timeout;
	void *platform_ctx;
	void *rpc_ctx;
	uv_mutex_t monitor_start_mtx;
	uv_cond_t monitor_start_cond;
	uv_thread_t monitor_thread_id;
	void *monitor_uv_event;
	struct uloop_timeout data_collection_timer;	
	struct uloop_fd uloop_sock;
	monitor_q_handle_t monitor_q_hdle;
	pthread_mutex_t  cumulative_stats_lock;
	cum_stats_t      cum_stats[MAX_AVAIL_CUM_STATS];
	map_bss_stats_t  cum_bss_nodes[MAX_CUM_BSS_STATS][MAX_NODES_PER_CUMLATIVE_STATS];
	map_sta_stats_t  cum_sta_nodes[MAX_CUM_STA_STATS][MAX_NODES_PER_CUMLATIVE_STATS];
} map_monitor_ctx_t;

typedef struct _monitor_cli_map_t {
	map_monitor_subcmd subcmd;
	const char *name;
} monitor_cli_map_t;

typedef struct _monitor_event_map_t {
	map_monitor_subcmd subcmd;
	const char *name;
} monitor_event_map_t;

/* static data types */
static map_monitor_ctx_t monitor_ctx;

void map_monitor_thread_fn(void *arg);


/* static function declaration */
static void _map_monitor_thread_started();
static void _map_monitor_ubus_thread_socket_cb(struct uloop_fd *sock, unsigned int events);
static int _map_monitor_register_events(map_monitor_cmd_t cmd);
static int _map_monitor_publish_services(map_monitor_cmd_t cmd);
static int _map_monitor_watch_threshold(map_monitor_cmd_t cmd);
static int _map_monitor_start_data_collection(map_monitor_cmd_t cmd);
static int _map_monitor_stop_data_collection(map_monitor_cmd_t cmd);
static int _map_monitor_process_command(map_monitor_cmd_t cmd);
static int _map_monitor_send_ubus_data(map_monitor_cmd_t cmd);

/* call back functions */
static void map_monitor_timer_callback(struct uloop_timeout *timeout);

/* Bus event command map table */
static monitor_event_map_t event_map_table[] = {
	{ MAP_MONITOR_STATION_EVENTS_SUBCMD, WIRELESS_STA_EVENT_STR },
	{ MAP_MONITOR_WIRELESS_SSID_EVENTS_SUBCMD, WIRELESS_SSID_EVENT_STR },
	{ MAP_MONITOR_CREDENTIAL_EVENTS_SUBCMD, MULTIAP_CREDENTIAL_EVENT_STR },
	{ MAP_MONITOR_WIRELESS_RADIO_EVENTS_SUBCMD, WIRELESS_RADIO_EVENT_STR },
	{ MAP_MONITOR_NETWORK_LINK_EVENTS_SUBCMD, NETWORK_LINK_EVENT_STR },
	{ MAP_MONITOR_CLIENT_BEACON_METRICS_METHOD_SUBCMD, WIRELESS_BEACON_METRICS_EVENT },
	{ MAP_MONITOR_UNASSOC_MEASUREMENT_REQ_METHOD_SUBCMD, WIRELESS_UNASSOC_METRICS_OBJ_STR },
	{ MAP_MONITOR_UNASSOC_MEASUREMENT_FLUSH_METHOD_SUBCMD, WIRELESS_UNASSOC_METRICS_OBJ_STR },
	{ MAP_MONITOR_UNASSOC_MEASUREMENT_RESPONSE_METHOD_SUBCMD, WIRELESS_UNASSOC_METRICS_OBJ_STR },
	{ MAP_MONITOR_BTM_REPORT_EVENTS_SUBCMD, WIRELESS_BTM_REPORT_EVENT_STR },
};

/* Bus object method callback map table */	
static monitor_cli_map_t cli_map_table[] = {
	{ MAP_MONITOR_TOPOLOGY_QUERY_METHOD_SUBCMD, SEND_TOPOLOGY_QUERY_METHOD_STR },
	{ MAP_MONITOR_STATION_STEER_METHOD_SUBCMD,  SEND_STA_STEER_METHOD_STR },
	{ MAP_MONITOR_AP_CAPABILITY_QUERY_METHOD_SUBCMD, SEND_CAPABILITY_QUERY_METHOD_STR },
	{ MAP_MONITOR_CHANNEL_PREFERENCE_QUERY_METHOD_SUBCMD, SEND_CHANNEL_PREF_QURY_METHOD_STR },
	{ MAP_MONITOR_CHANNEL_SELECTION_REQUEST_METHOD_SUBCMD, SEND_CHANNEL_SEL_REQ_METHOD_STR },
	{ MAP_MONITOR_CHANNEL_SELECTION_REQUEST_DETAIL_SUBCMD, SEND_CHANNEL_SEL_REQ_METHOD_DETAIL_STR },
	{ MAP_MONITOR_DUMP_CONTROLLER_INFO_SUBCMD, SEND_DUMP_CTRL_INFO_METHOD_STR },
	{ MAP_MONITOR_SEND_POLICY_CONFIG_METHOD_SUBCMD, SEND_POLICY_CONFIG_METHOD_STR },
	{ MAP_MONITOR_CLIENT_CAPABILITY_QUERY_METHOD_SUBCMD, SEND_CLNT_CAPABILITY_QUERY_METHOD_STR },
	{ MAP_MONITOR_DEBUG_AGENT_INFO_SUBCMD, SEND_DEBUG_AGENT_INFO_METHOD_STR },
	{ MAP_MONITOR_CLIENT_ACL_REQUEST_METHOD_SUBCMD, SEND_CLIENT_ACL_REQUEST_METHOD_STR },
	{ MAP_MONITOR_ASSOC_STA_METRIC_QUERY_SUBCMD, SEND_ASSOC_STA_METRIC_QUERY_METHOD_STR },
	{ MAP_MONITOR_UNASSOC_STA_METRIC_QUERY_SUBCMD, SEND_UNASSOC_STA_METRIC_QUERY_METHOD_STR },
	{ MAP_MONITOR_SEND_CHANNEL_PREF_REPORT_METHOD_SUBCMD, SEND_CHANNEL_PREF_REPORT_METHOD_STR },
	{ MAP_MONITOR_SEND_AUTOCONFIG_RENEW_SUBCMD, SEND_AUTOCONFIG_RENEW_METHOD_STR },
	{ MAP_MONITOR_BEACON_METRIC_QUERY_SUBCMD, SEND_BEACON_METRIC_QUERY_METHOD_STR },
	{ MAP_MONITOR_LINK_METRIC_QUERY_METHOD_SUBCMD, SEND_LINK_METRIC_QUERY_METHOD_STR },
	{ MAP_MONITOR_SEND_HIGHERLAYER_DATA_MSG_SUBCMD, SEND_HIGHLAYER_DATA_MSG_METHOD_STR },
	{ MAP_MONITOR_SEND_STEERING_POLICY_CONFIG_METHOD_SUBCMD, SEND_STEER_POLICY_CONFIG_METHOD_STR },
	{ MAP_MONITOR_AP_METRIC_QUERY_METHOD_SUBCMD, SEND_AP_METRIC_QUERY_METHOD_STR },
	{ MAP_MONITOR_COMBINED_INFRA_METRIC_QUERY_METHOD_SUBCMD, SEND_COMBINED_INFRA_METRIC_QUERY_METHOD_STR },
	{ MAP_MONITOR_GET_TOPO_TREE_METHOD_SUBCMD, DUMP_TOPO_TREE_METHOD_STR },
};

static int _map_monitor_register_events(map_monitor_cmd_t cmd)
{
	int ret = 0;
	
	if(cmd.subcmd > ARRAY_SIZE(event_map_table)) {
		ret = -EINVAL;
	}
	for(int i = 0; i < ARRAY_SIZE(event_map_table); i++) {
		if(event_map_table[i].subcmd == cmd.subcmd) {
			/* Invoke platform API to register for call back */
			ret = mon_platform_register_event(monitor_ctx.platform_ctx, event_map_table[i].name);
			platform_log(MAP_LIBRARY,LOG_DEBUG, "%s registered event %s return %d\n", __FUNCTION__, event_map_table[i].name, ret);
			if(0 != ret) {
				platform_log(MAP_LIBRARY,LOG_ERR, "%s event %s register failed\n", __FUNCTION__, event_map_table[i].name);
			}
			break;
		}
	}

	return ret;
}

static int _map_monitor_watch_threshold(map_monitor_cmd_t cmd)
{
	int ret = 0;

	if(MAP_MONITOR_RSSI_THRESHOLD_EVENTS_SUBCMD == cmd.subcmd) {
		monitor_ctx.threshold_mask |= RSSI_THRESHOLD_MONITOR;		
	} else if(MAP_MONITOR_CHANNEL_UTILIZATION_EVENTS_SUBCMD == cmd.subcmd) {
		monitor_ctx.threshold_mask |= CAHNNEL_UTIL_THRESHOLD_MONITOR;
	} else {
	}

	return ret;
}

static int _map_monitor_publish_services(map_monitor_cmd_t cmd)
{
	int ret = 0;
	
	if(cmd.subcmd > ARRAY_SIZE(cli_map_table)) {
		ret = -EINVAL;
	}
	for(int i = 0; i < ARRAY_SIZE(cli_map_table); i++) {
		if(cli_map_table[i].subcmd == cmd.subcmd) {
			/* platform API to register method */
			ret = mon_platform_register_method(monitor_ctx.platform_ctx, cli_map_table[i].name);
			platform_log(MAP_LIBRARY,LOG_DEBUG, "%s registered method %s return %d\n", __FUNCTION__, cli_map_table[i].name, ret);
			if(0 != ret) {
				platform_log(MAP_LIBRARY,LOG_ERR, "%s method %s register failed\n", __FUNCTION__, cli_map_table[i].name);
			}
			break;
		}
	}
	return ret;
}

cum_stats_t *find_unused_cum_stats_entry(map_monitor_event event)
{
    cum_stats_t  *ret      = NULL;
    int          cnt       = 0;
    int          i         = 0;
    int start_index        = 0;

    if(event == MAP_MONITOR_CUMULATIVE_STA_STATS) {
        start_index = MAX_CUM_BSS_STATS;
    }

    i = start_index;
    pthread_mutex_lock(&monitor_ctx.cumulative_stats_lock);
    for(cnt = 0; cnt < 3; cnt++) {
       if(monitor_ctx.cum_stats[i].inuse == 0) {
            ret = &monitor_ctx.cum_stats[i];
            monitor_ctx.cum_stats[i].inuse = 1;
            break;
        }
        i++;
    }
    pthread_mutex_unlock(&monitor_ctx.cumulative_stats_lock);
    return ret;
}

static void map_monitor_timer_callback(struct uloop_timeout *timeout)
{	
       /* First update timeout, then do the work to keep correct timer period */
       uloop_timeout_set(timeout, monitor_ctx.timeout);

	/* Collect data and update buffers */	
	if(monitor_ctx.data_collection_mask & BACKHAUL_METRICS_COLLECTION) {
		//Invoke platform APIs to collect data

	}

        /* Station Stats is pushed into the queue before AP Metrics because, Station Stats
           need to be sent as part of AP Metrics, If AP metrics get pushed into the queue first,
           then already cached old data will be sent as part of AP Metrics instead of the
           nwly obtained data*/

	if(monitor_ctx.data_collection_mask & STATION_LINK_METRICS_COLLECTION) {
            //Invoke platform APIs to collect data
            cum_stats_t *cum_sta_stats = NULL;

             cum_sta_stats = find_unused_cum_stats_entry(MAP_MONITOR_CUMULATIVE_STA_STATS);
             if(cum_sta_stats != NULL) {
                //Invoke platform APIs to collect data
                platform_get(MAP_PLATFORM_GET_CUMULATIVE_STA_STATS, NULL, cum_sta_stats);

                cum_sta_stats->obj_type = MAP_MONITOR_CUMULATIVE_STA_STATS;
                cum_sta_stats->measurement_time = get_current_time();

		if(event_notify_main_thread(&monitor_ctx.monitor_q_hdle,(void*)cum_sta_stats)) {
                       platform_log(MAP_LIBRARY,LOG_ERR,"%s event notification failed for cumulative AP metrics\n", __FUNCTION__);
                }
            }
	}

        if(monitor_ctx.data_collection_mask & AP_METRICS_COLLECTION) {
                //Invoke platform APIs to collect data
            cum_stats_t *cum_bss_stats = NULL;

            cum_bss_stats = find_unused_cum_stats_entry(MAP_MONITOR_CUMULATIVE_BSS_STATS);
            if(cum_bss_stats != NULL) {
                //Invoke platform APIs to collect data
                platform_get(MAP_PLATFORM_GET_CUMULATIVE_BSS_STATS, NULL, cum_bss_stats);

                cum_bss_stats->obj_type = MAP_MONITOR_CUMULATIVE_BSS_STATS;
                cum_bss_stats->measurement_time = get_current_time();

                if(event_notify_main_thread(&monitor_ctx.monitor_q_hdle,(void*)cum_bss_stats)) {
                       platform_log(MAP_LIBRARY,LOG_ERR,"%s event notification failed for cumulative AP metrics\n", __FUNCTION__);
                }
            }
        }

	/* Monitor the commanded parameters */
	if(monitor_ctx.threshold_mask & RSSI_THRESHOLD_MONITOR) {
		/* Check for delta with RSSI threshold and invoke callback */
		map_monitor_evt_t *monitor_evt = NULL;

		platform_log(MAP_LIBRARY,LOG_DEBUG,"%s event call back for MAP_MONITOR_RSSI_THRESHOLD_EVT \n", __FUNCTION__);
		
		monitor_evt = (map_monitor_evt_t*) malloc(sizeof(map_monitor_evt_t));		

		if(NULL != monitor_evt) {
			memset(monitor_evt, 0, sizeof(map_monitor_evt_t));
			monitor_evt->evt = MAP_MONITOR_RSSI_THRESHOLD_EVT;
			monitor_evt->evt_data = NULL;
			
			/* Notify event to main thread */
			if(event_notify_main_thread(&monitor_ctx.monitor_q_hdle, (void*)monitor_evt)) 
			{
				free(monitor_evt);
				platform_log(MAP_LIBRARY,LOG_ERR,"%s event notification failed \n", __FUNCTION__);
			}
		} else {
			platform_log(MAP_LIBRARY,LOG_ERR,"%s memory allocation failed \n", __FUNCTION__);
		}
	}
	
	if(monitor_ctx.threshold_mask & CAHNNEL_UTIL_THRESHOLD_MONITOR) {
		/* Check for delta with channel utilization threshold and invoke callback */
		map_monitor_evt_t *monitor_evt = NULL;

		platform_log(MAP_LIBRARY,LOG_DEBUG,"%s event call back for MAP_MONITOR_CHANNEL_UTL_THRESHOLD_EVT \n", __FUNCTION__);
		

		monitor_evt = (map_monitor_evt_t*) malloc(sizeof(map_monitor_evt_t));		

		if(NULL != monitor_evt) {
			memset(monitor_evt, 0, sizeof(map_monitor_evt_t));
			monitor_evt->evt = MAP_MONITOR_CHANNEL_UTL_THRESHOLD_EVT;
			monitor_evt->evt_data = NULL;
			
			/* Notify event to main thread */
			if(event_notify_main_thread(&monitor_ctx.monitor_q_hdle,(void*)monitor_evt)) 
			{
				free(monitor_evt);
				platform_log(MAP_LIBRARY,LOG_ERR,"%s event notification failed \n", __FUNCTION__);
			}
		} else {
			platform_log(MAP_LIBRARY,LOG_ERR,"%s memory allocation failed \n", __FUNCTION__);
		}
	}
}

static int _map_monitor_start_data_collection(map_monitor_cmd_t cmd)
{
	int ret = 0;

	platform_log(MAP_LIBRARY,LOG_DEBUG, "%s the subcmd is %d\n", __FUNCTION__, cmd.subcmd);

	if(MAP_MONITOR_BACKHAUL_METRICS_COLLECTION_SUBCMD == cmd.subcmd) {
		monitor_ctx.data_collection_mask |= BACKHAUL_METRICS_COLLECTION;		
	} else if(MAP_MONITOR_AP_METRICS_COLLECTION_SUBCMD == cmd.subcmd) {
		monitor_ctx.data_collection_mask |= AP_METRICS_COLLECTION;
	} else if(MAP_MONITOR_STATION_LINK_METRICS_COLLECTION_SUBCMD == cmd.subcmd) {
		monitor_ctx.data_collection_mask |= STATION_LINK_METRICS_COLLECTION;
	} else {
	}
	
	if(0 == monitor_ctx.timeout) {
		monitor_ctx.timeout = DATA_COLLECTION_TIMEOUT_MSEC;
		uloop_timeout_set(&monitor_ctx.data_collection_timer , monitor_ctx.timeout);
	}
	return ret;
}

static int _map_monitor_stop_data_collection(map_monitor_cmd_t cmd)
{
	int ret = 0;

	monitor_ctx.data_collection_mask &= 0x00;
	monitor_ctx.timeout = 0;
	uloop_timeout_cancel(&monitor_ctx.data_collection_timer);
	return ret;
}
/***********************************************************************
*               Un-associated station link metrics utils
*
***********************************************************************/

static inline array_list_t* get_unassoc_sta_metrics_radio_list() {
    static array_list_t* unassoc_radio_info = NULL;

    // Create a new array list if it does not exist.
    if(unassoc_radio_info == NULL ){
        unassoc_radio_info = (array_list_t*)new_array_list(eListTypeDefault);
        if(unassoc_radio_info == NULL )
            platform_log(MAP_LIBRARY, LOG_ERR, "%s Failed to create unassoc_sta_metrics_collecting_radio_list", __func__);
    }
    return unassoc_radio_info;
}

int compare_radio_name(void* radio_info, void* radio_name) {
    if(radio_info && radio_name) {
        if(strncmp(((struct unassoc_radio_info*)radio_info)->radio_name, (char*)radio_name, MAX_RADIO_NAME_LEN) == 0)
            return 1;
        }
    return 0;
}

static inline struct unassoc_radio_info * get_unassoc_radio_info(char *radio_name) {
    return find_object(get_unassoc_sta_metrics_radio_list(),\
                        radio_name, compare_radio_name);
}

uint8_t add_unassoc_radio_info(char *radio_name, uint16_t sta_cnt) {
    if (NULL == radio_name) {
        platform_log(MAP_LIBRARY,LOG_ERR,"%s:radio_name is NULL",__func__);
        return -1;
    }

    struct unassoc_radio_info *radio_info = get_unassoc_radio_info (radio_name);

    if(radio_info == NULL && (list_get_size(get_unassoc_sta_metrics_radio_list()) < MAX_RADIOS_PER_AGENT)) {

        radio_info = (struct unassoc_radio_info*) calloc(1, sizeof(struct unassoc_radio_info));
        if(radio_info == NULL) {
            platform_log(MAP_LIBRARY,LOG_ERR,"%s: Calloc failed for radio_info",__func__);
            return -1;
        }

        // Update the radio name
        strcpy(radio_info->radio_name, radio_name);

        // Insert the object to unassoc cache
        insert_last_object(get_unassoc_sta_metrics_radio_list(), radio_info);
    }

    // Update the radio count
    if(radio_info)
	    radio_info->pending_count = sta_cnt;

    return 0;
}

int clear_unassoc_pending_report(char *radio_name) {

    struct unassoc_radio_info *radio_info = get_unassoc_radio_info (radio_name);
    if(radio_info == NULL) {
        platform_log(MAP_LIBRARY,LOG_ERR,"%s: radio info is NULL",__func__);
        return -1;
    }

    radio_info->pending_count = 0;
    return 0;
}

uint8_t decr_unassoc_pending_cnt(char *radio_name) {

    struct unassoc_radio_info *radio_info = get_unassoc_radio_info (radio_name);
    if(radio_info == NULL) {
        platform_log(MAP_LIBRARY,LOG_ERR,"%s: radio info is NULL",__func__);
        return 0;
    }
    
    if(radio_info->pending_count > 0) {
        radio_info->pending_count--;
    }

    return radio_info->pending_count;
}
/***********************************************************************
            End of Un-associated station link metrics utils
***********************************************************************/

static int _map_monitor_send_ubus_data(map_monitor_cmd_t cmd)
{
       int ret = 0;

       switch (cmd.subcmd) {
           case MAP_MONITOR_CLIENT_ACL_REQUEST_METHOD_SUBCMD:
           {
               client_acl_data_t *acl_data = NULL;

               acl_data = (client_acl_data_t *)cmd.param;
               if (NULL != acl_data) {
                   if (-1 == platform_set_context(MAP_PLATFORM_APPLY_ACL, (void *)acl_data, monitor_ctx.rpc_ctx)) {
                       platform_log(MAP_LIBRARY,LOG_ERR, "%s : Platform Set failed for ACL \n", __FUNCTION__);
                       ret = -EINVAL;
                   }
                   free(acl_data);
               }
               else {
                   platform_log(MAP_LIBRARY,LOG_ERR, "%s : ACL data is empty \n", __FUNCTION__);
                   ret = -EINVAL;
               }
               break;
           }

           case MAP_MONITOR_CLIENT_BEACON_METRICS_METHOD_SUBCMD:
           {
               beacon_metrics_query_t  *query = (beacon_metrics_query_t  *)cmd.param;
               uint8_t                  i     = 0;
               if (NULL != cmd.param) {
                  if(add_sta_to_bcon_pend_list(query->sta_mac) <0) {
                      ret = -EINVAL;
                      free(cmd.param);
                      break;
                  }

                  if(query->element_id_count > 0) {
                      for(i = 0; i< query->element_id_count; i++) {
                          if (query->elementIds[i] == MEASUREMENT_REQUEST_ELEMENTID) {
                              if (-1 == platform_set_context (MAP_PLATFORM_QUERY_BEACON_METRICS, (void *)cmd.param, monitor_ctx.rpc_ctx)) {
                                       platform_log(MAP_LIBRARY,LOG_ERR, "%s : Platform Set failed for  \n", __FUNCTION__);
                                       ret = -EINVAL;
                               }
                           }
                       }
                   } else {
                       if (-1 == platform_set_context (MAP_PLATFORM_QUERY_BEACON_METRICS, (void *)cmd.param, monitor_ctx.rpc_ctx)) {
                               platform_log(MAP_LIBRARY,LOG_ERR, "%s : Platform Set failed for  \n", __FUNCTION__);
                               ret = -EINVAL;
                       }
                   }
                   
                   free(cmd.param);
               }
               else {
                   platform_log(MAP_LIBRARY,LOG_ERR, "%s : beacon metrics parameters for query is empty \n", __FUNCTION__);
                   ret = -EINVAL;
               }
               break;
           }

           case MAP_MONITOR_LEGACY_STEERING_SUB_CMD:
           {

               if (NULL != cmd.param) {
                  if (-1 == platform_set_context (MAP_PLATFORM_LEGACY_STA_STEER, (void *)cmd.param, monitor_ctx.rpc_ctx)) {
                           platform_log(MAP_LIBRARY,LOG_ERR, "%s : Platform Set failed for  \n", __FUNCTION__);
                           ret = -EINVAL;
                   }
                   free(cmd.param);
               }
               else {
                   platform_log(MAP_LIBRARY,LOG_ERR, "%s : beacon metrics parameters for query is empty \n", __FUNCTION__);
                   ret = -EINVAL;
               }
               break;


           }

           case MAP_MONITOR_BTM_STEERING_SUB_CMD:
           {

               if (NULL != cmd.param) {
                  struct sta_steer_params sta_steer = {0};
                  int                          i    =  0;
                  char   bssid_str[MAX_MAC_STRING_LEN] = {0};
                  struct sta_steer_params *btm_sta_steer = (struct sta_steer_params *)cmd.param;


                  snprintf(bssid_str, MAX_MAC_STRING_LEN, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
                     btm_sta_steer->source_bssid[0], btm_sta_steer->source_bssid[1],
                     btm_sta_steer->source_bssid[2], btm_sta_steer->source_bssid[3],
                     btm_sta_steer->source_bssid[4], btm_sta_steer->source_bssid[5]);

                  platform_log(MAP_LIBRARY,LOG_DEBUG,"MAP_MONITOR_BTM_STEERING_SUB_CMD bssid %s \n",bssid_str);
                  platform_get_context(MAP_PLATFORM_GET_AP_FROM_BSSID, bssid_str, sta_steer.ap_name, monitor_ctx.rpc_ctx);

                  platform_log(MAP_LIBRARY,LOG_DEBUG,"MAP_MONITOR_BTM_STEERING_SUB_CMD %s\n",sta_steer.ap_name);
                  for (i = 0; i < btm_sta_steer->sta_count; i++) {
                      sta_steer.disassociation_timer = btm_sta_steer->disassociation_timer;
                      sta_steer.abridged_mode        = btm_sta_steer->abridged_mode;
                      sta_steer.sta_count            = 1;
                      memcpy(&sta_steer.sta_info[0], &btm_sta_steer->sta_info[i], sizeof(struct sta_params));
					  platform_log(MAP_LIBRARY,LOG_DEBUG,"MAP_MONITOR_BTM_STEERING_SUB_CMD disassoc_timer %x, abridged_mode %x stacnt %x\n",sta_steer.disassociation_timer,
					  				sta_steer.abridged_mode, sta_steer.sta_count);

                      if (-1 == platform_set_context (MAP_PLATFORM_BTM_STA_STEER, (void *)&sta_steer, monitor_ctx.rpc_ctx)) {
                               platform_log(MAP_LIBRARY,LOG_ERR, "%s : Platform Set failed for  \n", __FUNCTION__);
                               ret = -EINVAL;
                       }
                  }
                  free(cmd.param);
               }
               else {
                   platform_log(MAP_LIBRARY,LOG_ERR, "%s : beacon metrics parameters for query is empty \n", __FUNCTION__);
                   ret = -EINVAL;
               }
               break;
           }

           case MAP_MONITOR_OFF_BSS_SUB_CMD:
           {
               if (NULL != cmd.param) {
                   if (-1 == platform_set_context (MAP_PLATFORM_SET_IEEE_1905_OFF_BSS, (void *)cmd.param, monitor_ctx.rpc_ctx)) {
                       platform_log(MAP_LIBRARY,LOG_ERR, "%s : Platform Set failed for  \n", __FUNCTION__);
                       ret = -EINVAL;
                   }
               }
               else {
                   platform_log(MAP_LIBRARY,LOG_ERR, "%s :  parameters passed are empty \n", __FUNCTION__);
                   ret = -EINVAL;
               }
               break;
           }

           case MAP_MONITOR_OFF_RADIO_SUB_CMD:
           {
               if (NULL != cmd.param) {
                   if (-1 == platform_set_context (MAP_PLATFORM_SET_IEEE_1905_OFF_RADIO, (void *)cmd.param, monitor_ctx.rpc_ctx)) {
                       platform_log(MAP_LIBRARY,LOG_ERR, "%s : Platform Set failed for  \n", __FUNCTION__);
                       ret = -EINVAL;
                   }
               }
               else {
                   platform_log(MAP_LIBRARY,LOG_ERR, "%s :  parameters passed are empty \n", __FUNCTION__);
                   ret = -EINVAL;
               }
               break;
           }

           case MAP_MONITOR_UNASSOC_MEASUREMENT_REQ_METHOD_SUBCMD:
           {
                struct unassoc_platform_cmd *platform_cmd = (struct unassoc_platform_cmd *)cmd.param;
                if(platform_cmd) {
                    if(NULL == get_unassoc_sta_metrics_radio_list()) {
                        free(platform_cmd);
                        ret = -EINVAL;
                        break;
                    }

                    /* Cache the radio info for future reference */
                    add_unassoc_radio_info(platform_cmd->radio_name, platform_cmd->cnt);

                    /* Initiate the un-associated sta metrics collection */
                    if (-1 == platform_set_context(MAP_PLATFORM_REQ_UNASSOC_MEASUREMENT, (void *) platform_cmd, monitor_ctx.rpc_ctx)) {
                        platform_log(MAP_LIBRARY,LOG_ERR, "%s : Platform Set failed for MAP_PLATFORM_REQ_UNASSOC_MEASUREMENT \n", __FUNCTION__);
                        ret = -EINVAL;
                    }
                    free(platform_cmd);
                }
                else {
                    platform_log(MAP_LIBRARY,LOG_ERR, "%s : unassoc measurement req parameters is empty \n", __FUNCTION__);
                    ret = -EINVAL;
                }
                break;
           }

           case MAP_MONITOR_UNASSOC_MEASUREMENT_FLUSH_METHOD_SUBCMD:
           {
               char *radio_name = (char *)cmd.param;

               if (NULL != radio_name) {
                   clear_unassoc_pending_report(radio_name);

                   if (-1 == platform_set_context(MAP_PLATFORM_FLUSH_UNASSOC_MEASUREMENT, (void *)radio_name, monitor_ctx.rpc_ctx)) {
                       platform_log(MAP_LIBRARY,LOG_ERR, "%s : Platform Set failed for MAP_PLATFORM_FLUSH_UNASSOC_MEASUREMENT \n", __FUNCTION__);
                       ret = -EINVAL;
                   }
                   free(radio_name);
               }
               else {
                   platform_log(MAP_LIBRARY,LOG_ERR, "%s : unassoc measurement flush parameters is NULL \n", __FUNCTION__);
                   ret = -EINVAL;
               }
               break;
           }

           case MAP_MONITOR_RESPONSE_TO_CLI_SUBCMD:
           {
              if (NULL != cmd.param) {

                  map_cli_async_resp_t *resp = (map_cli_async_resp_t *)cmd.param;
                  map_async_cli_completion_cb (monitor_ctx.rpc_ctx, resp);
                  free(cmd.param);
              }
              else {
                   platform_log(MAP_LIBRARY,LOG_ERR, "%s :  parameters passed are empty \n", __FUNCTION__);
                   ret = -EINVAL;
              }
              break;

           }

           case MAP_MONITOR_SET_CHANNEL_METHOD_SUBCMD:
           {
              if (NULL != cmd.param) {
                   if (-1 == platform_set_context (MAP_PLATFORM_SET_CHANNEL, (void *)cmd.param, monitor_ctx.rpc_ctx)) {
                       platform_log(MAP_LIBRARY,LOG_ERR, "%s : Platform Set failed for  \n", __FUNCTION__);
                       ret = -EINVAL;
                   }
                   free(cmd.param);
               }
               else {
                   platform_log(MAP_LIBRARY,LOG_ERR, "%s :  parameters passed are empty \n", __FUNCTION__);
                   ret = -EINVAL;
               }
               break;


           }

           case MAP_MONITOR_GET_NEIGHBOUR_LINK_MET_METHOD_SUBCMD:
           {

               uint16_t tlvs_cnt = 0;
               neighbour_link_met_platform_cmd_t *platform_cmd   = (neighbour_link_met_platform_cmd_t *)cmd.param;
               struct neighbour_link_met_response *link_met_resp = NULL;

               if(platform_cmd == NULL)
                   break;

               int tlvs_per_neighbour = (platform_cmd->request_type == BOTH_TX_AND_RX_LINK_METRICS) ? 2 : 1 ;

               link_met_resp = (struct neighbour_link_met_response *)calloc(1, 
                      (platform_cmd->neighbour_entry_nr * tlvs_per_neighbour * sizeof(uint8_t *)) + sizeof(struct neighbour_link_met_response));
               if(link_met_resp == NULL) {
                   free(platform_cmd);
                   break;
               }
      
               link_met_resp->type = MAP_MONITOR_LINK_METRICS_REPORT;
               link_met_resp->mid  = platform_cmd->mid;

               memcpy (link_met_resp->dst_mac, platform_cmd->dst_mac, MAC_ADDR_LEN);
               strncpy (link_met_resp->dst_iface_name, platform_cmd->dst_iface_name, sizeof(link_met_resp->dst_iface_name));
               link_met_resp->dst_iface_name[sizeof(link_met_resp->dst_iface_name)-1] = '\0';
 

               for (int i = 0; i<platform_cmd->neighbour_entry_nr; i++) {
                   if(platform_cmd->request_type == TX_LINK_METRICS_ONLY || 
                      platform_cmd->request_type == BOTH_TX_AND_RX_LINK_METRICS) {
                       platform_get_context(MAP_PLATFORM_GET_TX_LINK_METRICS, 
                        (char *)&platform_cmd->neighbour_list[i], &link_met_resp->list_of_tlvs[tlvs_cnt], monitor_ctx.rpc_ctx);
                       if(link_met_resp->list_of_tlvs[tlvs_cnt] != NULL)
                           ++tlvs_cnt;
                   }

                   if(platform_cmd->request_type == RX_LINK_METRICS_ONLY || platform_cmd->request_type == BOTH_TX_AND_RX_LINK_METRICS) {
                       platform_get_context(MAP_PLATFORM_GET_RX_LINK_METRICS,
                         (char *) &platform_cmd->neighbour_list[i], &link_met_resp->list_of_tlvs[tlvs_cnt], monitor_ctx.rpc_ctx);
                       if(link_met_resp->list_of_tlvs[tlvs_cnt] != NULL)
                           ++tlvs_cnt;
                   }
               }

               link_met_resp->tlvs_cnt = tlvs_cnt;

	       platform_log(MAP_LIBRARY,LOG_DEBUG,"%s event call back for MAP_MONITOR_LINK_METRICS_REPORT \n", __FUNCTION__);
               /* Notify event to main thread */
               if(event_notify_main_thread(&monitor_ctx.monitor_q_hdle, (void*)link_met_resp)) 
               {
                   free(link_met_resp);
                   platform_log(MAP_LIBRARY,LOG_ERR,"%s event notification failed \n", __FUNCTION__);
               }
               free(platform_cmd);
               break;
           }

           case MAP_MONITOR_SET_TX_PWR_METHOD_SUBCMD:
           {
               if (NULL != cmd.param) {
                   if (-1 == platform_set_context (MAP_PLATFORM_SET_TX_PWR, (void *)cmd.param, monitor_ctx.rpc_ctx)) {
                       platform_log(MAP_LIBRARY,LOG_ERR, "%s : Platform Set failed for  \n", __FUNCTION__);
                       ret = -EINVAL;
                   }
                   free(cmd.param);
                } else {
                   platform_log(MAP_LIBRARY,LOG_ERR, "%s :  parameters passed are empty \n", __FUNCTION__);
                }

                break; 
            }

            case MAP_MONITOR_GET_TX_PWR_METHOD_SUBCMD:
            {
               platform_cmd_tx_pwr_set_t *tx_pwr_report = NULL;
               uint8_t                   tx_pwr         = 0;

               if (NULL != cmd.param) {
                   tx_pwr_report = (platform_cmd_tx_pwr_set_t *)cmd.param;
                   platform_get_context (MAP_PLATFORM_GET_TX_PWR, tx_pwr_report->radio_name, (void *)&tx_pwr, monitor_ctx.rpc_ctx);

                   tx_pwr_report->type = MAP_MONITOR_TX_PWR_CHANGE_REPORT;
                   tx_pwr_report->current_tx_pwr = tx_pwr;
                   if (event_notify_main_thread(&monitor_ctx.monitor_q_hdle, (void*)tx_pwr_report)) 
                   {
                       free(tx_pwr_report);
                       platform_log(MAP_LIBRARY,LOG_ERR,"%s event notification failed \n", __FUNCTION__);
                   }
               } else {
                   platform_log(MAP_LIBRARY,LOG_ERR, "%s :  parameters passed are empty \n", __FUNCTION__);
               }
               break; 
           }

           case MAP_MONITOR_GET_CHANNEL_PREF_SUBCMD:
           {
               if(cmd.param) {

                   platform_channel_pref_cmd_t *platform_cmd = (platform_channel_pref_cmd_t *)cmd.param;

                   for(int j=0; j< platform_cmd->op_class_count; j++)
                   {
                       if ( platform_cmd->radio_type == IEEE80211_FREQUENCY_BAND_2_4_GHZ) {
                           platform_get_context (MAP_PLATFORM_GET_2G_CHANNEL_PREF, platform_cmd->radio_name, &platform_cmd->op_class_list[j], monitor_ctx.rpc_ctx);
                       } else {
                           platform_get_context (MAP_PLATFORM_GET_5G_CHANNEL_PREF, platform_cmd->radio_name, &platform_cmd->op_class_list[j], monitor_ctx.rpc_ctx);
                       }
           
                   }
                   
                   platform_cmd->event_type =  MAP_MONITOR_SEND_CHANNEL_PREF;
			
                   /* Notify event to main thread */
                   if (event_notify_main_thread(&monitor_ctx.monitor_q_hdle, (void*)platform_cmd)) 
                   {
                       free(platform_cmd);
                       platform_log(MAP_LIBRARY,LOG_ERR,"%s event notification failed \n", __FUNCTION__);
                   }
               }
               break;
           }
           case MAP_MONITOR_SEND_STN_EVENT_SUBCMD:
           {
               stn_event_platform_cmd_t *platform_cmd = (stn_event_platform_cmd_t*)cmd.param;
               if(NULL != platform_cmd) {
                   if (-1 == platform_set_context (MAP_PLATFORM_SEND_STN_EVT, (void *)cmd.param, monitor_ctx.rpc_ctx)) {
                       platform_log(MAP_LIBRARY,LOG_ERR, "%s : Platform Set failed for MAP_PLATFORM_SEND_STN_EVT\n", __FUNCTION__);
                       ret = -EINVAL;
                   }
                   free(cmd.param);                                
               }
               break;
           }
           case MAP_MONITOR_SEND_TOPO_TREE_DATA:
           {
               map_send_async_ubus_response(monitor_ctx.rpc_ctx, cmd.param);
               break;
           }
           default:
           {
               platform_log(MAP_LIBRARY,LOG_ERR, "%s Invalid subcommand %d\n", __FUNCTION__, cmd.subcmd);
               ret = -EINVAL;
               break;
           }
       }
       return ret;
}

static int _map_monitor_process_command(map_monitor_cmd_t cmd)
{
	int ret = 0;

	switch (cmd.cmd) {
		case MAP_MONITOR_INIT_DATA_COLLECTION_CMD:
		{
			_map_monitor_start_data_collection(cmd);
			break;
		}
		case MAP_MONITOR_STOP_DATA_COLLECTION_CMD:
		{
			_map_monitor_stop_data_collection(cmd);
			break;
		}
		case MAP_MONITOR_PUBLISH_SERVICES_CMD:
		{
			_map_monitor_publish_services(cmd);
			break;
		}
		case MAP_MONITOR_REGISTER_EVENTS_CMD:
		{
			_map_monitor_register_events(cmd);
			break;
		}
		case MAP_MONITOR_MONITOR_THRESHOLD_CMD:
		{
			_map_monitor_watch_threshold(cmd);
			break;
		}
                case MAP_MONITOR_SEND_UBUS_DATA_CMD:
                {
                        _map_monitor_send_ubus_data(cmd);
                        break;
                }
		case MAP_MONITOR_ADD_OBJ_CMD:
		{
			platform_log(MAP_LIBRARY,LOG_DEBUG, "%s MAP_MONITOR_ADD_OBJ_CMD is obsolete %d\n", __FUNCTION__,__LINE__);
			break;
		}
		default:
		{
			platform_log(MAP_LIBRARY,LOG_ERR, "%s Invalid command %d\n", __FUNCTION__, cmd.cmd);
			ret = -EINVAL;
			break;
		}
	}

	return ret;
}

static void _map_monitor_ubus_thread_socket_cb(struct uloop_fd *sock, unsigned int events)
{
	int ret = 0;
	map_monitor_cmd_t cmd;

	if(NULL != sock) {
		ret = recv(sock->fd, &cmd, sizeof(cmd), MSG_DONTWAIT);
		if(ret > 0) {
			if((cmd.cmd > MAP_MONITOR_MIN_CMD) && (cmd.cmd < MAP_MONITOR_MAX_CMD) && 
					((cmd.subcmd > MAP_MONITOR_MIN_SUBCMD) && (cmd.subcmd < MAP_MONITOR_MAX_SUBCMD))) {
				platform_log(MAP_LIBRARY,LOG_DEBUG, "%s command is %x, sub command %x \n", __FUNCTION__, cmd.cmd, cmd.subcmd);
				if(0 != _map_monitor_process_command(cmd)) {
					platform_log(MAP_LIBRARY,LOG_ERR, "%s cmd processing failed\n", __FUNCTION__);
				}
			}			
		} else if(ret < 0) {
			platform_log(MAP_LIBRARY,LOG_ERR, "%s recieve failed %s\n", __FUNCTION__, strerror(errno));
		} else {
			platform_log(MAP_LIBRARY,LOG_ERR, "%s No data recieved\n", __FUNCTION__);
		}
	} else {
		platform_log(MAP_LIBRARY,LOG_ERR, "%s Invalid uloop fd\n", __FUNCTION__);
	}
}

void map_monitor_thread_fn(void *arg)
{
	uloop_init();

	/* Connect with mechanism to collect data */
	monitor_ctx.platform_ctx = mon_platform_connect(NULL, &monitor_ctx.monitor_q_hdle, monitor_ctx.is_controller, &monitor_ctx.rpc_ctx);
        if((NULL == monitor_ctx.platform_ctx) || (NULL == monitor_ctx.rpc_ctx)) {
            platform_log(MAP_LIBRARY,LOG_ERR, "%s Failed to connect to ubus", __FUNCTION__);
            return;
    }

	/* Create socket pair for IPC */
	if(map_init_ipc_event_notifier() < 0) 
	{
		platform_log(MAP_LIBRARY, LOG_ERR, "%s Failed to intialize monitor thread event notifier", __FUNCTION__);
		uloop_done();
		return;
	}

	monitor_ctx.uloop_sock.cb = _map_monitor_ubus_thread_socket_cb;
	monitor_ctx.uloop_sock.fd = map_get_monitor_thread_sockfd();
	uloop_fd_add(&monitor_ctx.uloop_sock, ULOOP_READ);

	/* signal main thread to synchronize*/
	_map_monitor_thread_started();
	platform_log(MAP_LIBRARY,LOG_DEBUG, " %s started!!\n", __FUNCTION__);
	
	uloop_run();

	uloop_fd_delete(&monitor_ctx.uloop_sock);

	map_cleanup_ipc_event_notifier();

	if(NULL != monitor_ctx.platform_ctx) {
		mon_platform_shutdown(monitor_ctx.platform_ctx);
	}

	uloop_done();
}


void* platform_get_mon_context(void)
{
	return monitor_ctx.rpc_ctx;
}

static void _map_monitor_thread_started()
{
	uv_mutex_lock(&monitor_ctx.monitor_start_mtx);
	uv_cond_signal(&monitor_ctx.monitor_start_cond);
	uv_mutex_unlock(&monitor_ctx.monitor_start_mtx);
}

static int init_monitor_queue (monitor_q_handle_t *mon_q_hdle) 
{
    int             i      = 0;
    int             j      = 0;
    int             cnt    = 0;
    cum_stats_t *cum_stats = NULL;
    
    /*
     * Init monitor queue static buffers
     */
    cum_stats = monitor_ctx.cum_stats;
    for(j = 0; j<2; j++) {
        for(i = 0 ; i<MAX_CUM_BSS_STATS ; i++) {
            if(j%2)
                cum_stats[cnt].cum_stats = &monitor_ctx.cum_sta_nodes[i][0];
            else
                cum_stats[cnt].cum_stats = &monitor_ctx.cum_bss_nodes[i][0];
            cnt++;
        }
    }

    // TODO: This is added as a temporary fix.
    // Once API "event_notify_main_thread" is replaced with
    // map_notify_main_thread, this can be removed.
    mon_q_hdle->list_handle = map_get_main_thread_event_queue();
    if(NULL == mon_q_hdle->list_handle){
        return -1;
    }

    // Add it to the monitor context
    monitor_ctx.monitor_q_hdle.list_handle = mon_q_hdle->list_handle;
    
    return 0;
}

/** @brief This is an API to create the monitor thread
 *
 *  This API will be called by agent and controller to communicate 
 *	through the bus
 *
 *  @param mon_q_hdle its a o/p variable - handle struct for queue logic
 *  @param is_controller wheather invoking controller.
 *  @return int 
 */
int map_monitor_thread_init(void *mon_q_hdle, bool is_controller)
{
	int ret = 0;

	if(NULL != mon_q_hdle) {
		uv_mutex_init(&monitor_ctx.monitor_start_mtx);
		uv_cond_init(&monitor_ctx.monitor_start_cond);
		uv_mutex_lock(&monitor_ctx.monitor_start_mtx);
                /* Init monitor queue */
                if(init_monitor_queue (mon_q_hdle) <0)
                    return -EINVAL;

		monitor_ctx.is_controller = is_controller;
		monitor_ctx.data_collection_timer.cb = map_monitor_timer_callback;
		
		monitor_ctx.monitor_thread_id = uv_thread_create(&monitor_ctx.monitor_thread_id, map_monitor_thread_fn, NULL);				

		uv_cond_wait(&monitor_ctx.monitor_start_cond, &monitor_ctx.monitor_start_mtx);		
		uv_mutex_unlock(&monitor_ctx.monitor_start_mtx);
	} else {
		platform_log(MAP_LIBRARY,LOG_ERR,"%s failed, callback invalid\n", __FUNCTION__);	
		ret = -EINVAL;
	}

	return ret;
}

/** @brief This is an API to join the monitor thread
 *
 *  This API will be called by agent and controller to clean up after 
 *	monitor thread terminates
 *
 *  @return int 
 */
int map_monitor_thread_cleanup()
{
	int ret = 0;
	
	ret = uv_thread_join(&monitor_ctx.monitor_thread_id);
	memset(&monitor_ctx, 0, sizeof(monitor_ctx));
	return ret;
}

/** @brief This is an API used by MAP agent/controller to free the dynamic mem allocated for event
 *
 *  This API will be called by agent and controller to free up dynamic memory,
 *	allocated for the vent structure and its satellite structures
 *
 *  @param monitor_evt pointer to the monitor event structure
 *
 */
void map_monitor_free_evt_mem(void *data_ptr)
{
        uint8_t *p = (uint8_t *)data_ptr;
	if(NULL != p) {
            switch(p[0]) {
                case MAP_MONITOR_CUMULATIVE_STA_STATS:
                case MAP_MONITOR_CUMULATIVE_BSS_STATS:
                {
                    cum_stats_t *cum_stats = (cum_stats_t *)data_ptr;
                    pthread_mutex_lock(&monitor_ctx.cumulative_stats_lock);
                    cum_stats->inuse = 0;
                    pthread_mutex_unlock(&monitor_ctx.cumulative_stats_lock);
                    break;
                }
                case MAP_MONITOR_SEND_CHANNEL_PREF_REPORT:
                case MAP_MONITOR_SEND_CHANNEL_SEL_REQ_DETAIL:
                case MAP_MONITOR_SEND_UNASSOC_STA_METRICS_QUERY:
                case MAP_MONITOR_TX_PWR_CHANGE_REPORT:	
                case MAP_MONITOR_SEND_CHANNEL_PREF:
                {
                    free(data_ptr);
                    break;
                }

                case MAP_MONITOR_SEND_STEER_POLICY_CONFIG_CALL:
                {
                    map_monitor_evt_t *monitor_evt = (map_monitor_evt_t *)data_ptr;
                    if(NULL != monitor_evt->evt_data) {
                        map_steering_policy_config_cmd_t *policy_config = NULL;
	                policy_config = (map_steering_policy_config_cmd_t*)monitor_evt->evt_data;
                        free(policy_config->btm_disalllowed_sta_list);
                        free(policy_config->local_disallowed_sta_list);
                        free(monitor_evt->evt_data);
                    }
                    free(monitor_evt);
                    break;
                }

                case MAP_MONITOR_LINK_METRICS_REPORT:
                {
                    struct neighbour_link_met_response *link_met_resp = (struct neighbour_link_met_response *)data_ptr;
                    int i = 0;
                    uint8_t *p = NULL;

                    for (i = 0; i < link_met_resp->tlvs_cnt; i++) {
                        p = link_met_resp->list_of_tlvs[i];
                        switch(*p) {
                        case TLV_TRANSMITTER_LINK_METRIC:
                        {
                            struct txLinkMetricTLV *tx_tlv = (struct txLinkMetricTLV *) p;
                            free(tx_tlv->transmitter_link_metrics);
                            free(tx_tlv);
                            break;
                        }
                        case TLV_RECEIVER_LINK_METRIC: 
                        {
                            struct rxLinkMetricTLV *rx_tlv = (struct rxLinkMetricTLV *) p;
                            free(rx_tlv->receiver_link_metrics);
                            free(rx_tlv);
                            break;
                        }

                        }
                    }

                    free(data_ptr);
                    break;
                }

                case MAP_MONITOR_BEACON_METRICS_REPORT_EVT:
                {
                    bcn_rprt_timeout_data_t *cum_beacon_report = (bcn_rprt_timeout_data_t *)data_ptr;
                    array_list_t            *bcon_rprt_list    = NULL;
                
                
                    if(cum_beacon_report != NULL) {

                        bcon_rprt_list = cum_beacon_report->bcon_rprt_list;

                        if (bcon_rprt_list != NULL) {
                            while (list_get_size(bcon_rprt_list))
                                free(remove_last_object(bcon_rprt_list));
                    
                            delete_array_list(bcon_rprt_list);
                        }

                        free(cum_beacon_report);
                    }
                    break;
                }

                default:
                {
                    map_monitor_evt_t *monitor_evt = (map_monitor_evt_t *)data_ptr;
                    if(NULL != monitor_evt->evt_data) {
                        free(monitor_evt->evt_data);
                    }
                    free(monitor_evt);
                }
            }
	}
}

