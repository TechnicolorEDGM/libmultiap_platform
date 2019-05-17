/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

#include "1905_platform.h"
#include "platform_lib_capi_util.h"
#include "platform_lib_test.h"

void print_api_result(int cmd, const char* cmdstr, const char* subcmd, void* capi, void* output, int status)
{
	switch (cmd)
	{
		case MAP_PLATFORM_GET_MULTIAP_CONFIG:
			print_get_config(cmd, cmdstr, subcmd, capi, output, status);
		break;

		case MAP_PLATFORM_GET_IEEE1905_CONFIG:
			print_get_config(cmd, cmdstr, subcmd, capi, output, status);
		break;

		case MAP_PLATFORM_GET_INTERFACE_INFO:

		break;

		case MAP_PLATFORM_GET_AP_AUTOCONFIG:
			print_autoconfig_result(output);
		break;

		case MAP_PLATFORM_SET_IEEE_1905_WIFI_PARAMS:
			print_set_ieee_wifi_params(cmd, cmdstr, subcmd, capi, output, status);
		break;

		case MAP_PLATFORM_GET_MAP_MAC_ADDRESS:
			print_get_config(cmd, cmdstr, subcmd, capi, output, status);
		break;

		case MAP_PLATFORM_GET_IEEE_INTERFACE_FROM_MAC:
			print_get_config(cmd, cmdstr, subcmd, capi, output, status);
		break;

		case MAP_PLATFORM_GET_INTERFACE_STATE:
			print_get_config(cmd, cmdstr, subcmd, capi, output, status);
		break;

		case MAP_PLATFORM_GET_SSID:
			print_get_config(cmd, cmdstr, subcmd, capi, output, status);
		break;

		case MAP_PLATFORM_GET_WPA_PSK:
			print_get_config(cmd, cmdstr, subcmd, capi, output, status);
		break;

		case MAP_PLATFORM_GET_FREQUENCY_BAND:

		break;

		case MAP_PLATFORM_GET_VALID_FHBH_INTERFACE:
			print_get_config(cmd, cmdstr, subcmd, capi, output, status);
		break;

		case MAP_PLATFORM_GET_AGENT_BSSID:
			print_get_config(cmd, cmdstr, subcmd, capi, output, status);
		break;

		case MAP_PLATFORM_GET_BRIDGE_INFO:

		break;

		case MAP_PLATFORM_GET_CONTROLLER_POLICY_CONFIG:

		break;

		case MAP_PLATFORM_SET_CONTROLLER_INTERFACE_LINK:

		break;

		case MAP_PLATFORM_GET_RADIO_INFO:

		break;

		case MAP_PLATFORM_GET_CUMULATIVE_BSS_STATS:
			print_cumulative_bss_stats(output, capi, status);
		break;

		case MAP_PLATFORM_GET_CUMULATIVE_STA_STATS:
			print_cumulative_sta_stats(output, capi, status);
		break;

		case MAP_PLATFORM_APPLY_ACL:
		break;

		case MAP_PLATFORM_QUERY_BEACON_METRICS:
		break;

		case MAP_PLATFORM_GET_BEACON_METRICS_RESPONSE:
		break;

		case MAP_PLATFORM_GET_RADIO_BSS_STATE_INFO:
			print_bss_state_info(cmd, cmdstr, subcmd, capi, output, status);
		break;

		case MAP_PLATFORM_GET_AP_FROM_BSSID:
			print_get_config(cmd, cmdstr, subcmd, capi, output, status);
		break;

		case MAP_PLATFORM_BTM_STA_STEER:
			print_set_steer(cmd, cmdstr, subcmd, capi, output, status);
		break;

		case MAP_PLATFORM_LEGACY_STA_STEER:
			print_set_steer(cmd, cmdstr, subcmd, capi, output, status);
		break;

		case MAP_PLATFORM_GET_ASSOC_FRAME:
		break;

		default:
			platform_log(MAP_LIBRARY,LOG_ERR, "Unknown command: %d\n", cmd);
		break;
	}
}


static char* get_type_name(int type)
{
	char* type_name = "unspec";
	switch (type)
	{
		case BLOBMSG_TYPE_ARRAY: 
			type_name = "array";
		break;

		case BLOBMSG_TYPE_TABLE: 
			type_name = "table";
		break;

		case BLOBMSG_TYPE_STRING: 
			type_name = "string";
		break;

		case BLOBMSG_TYPE_INT64: 
			type_name = "int64";
		break;

		case BLOBMSG_TYPE_INT32: 
			type_name = "int32";
		break;

		case BLOBMSG_TYPE_INT16: 
			type_name = "int16";
		break;

		case BLOBMSG_TYPE_INT8: 
			type_name = "int8/bool";
		break;
	}

	return type_name;
}


void print_blob_info(const struct blob_attr *msg, int cnt, int acnt)
{
	unsigned int r;
	struct blob_attr *c;
	int attrcnt = 0;

	platform_log(MAP_LIBRARY,LOG_ERR, "blob_info(%d:%d): name<%s> : type<%s(%d)>\n", cnt, acnt, blobmsg_name(msg), get_type_name(blobmsg_type(msg)), blobmsg_type(msg));

	if ((blobmsg_type(msg) == BLOBMSG_TYPE_TABLE) || (blobmsg_type(msg) == BLOBMSG_TYPE_ARRAY)) {
		blobmsg_for_each_attr(c, msg, r) {
			print_blob_info(c, cnt+1, attrcnt++);
		}
	}
}


void print_get_config(int cmd, const char* cmdstr, const char* subcmd, void* capi, void* output, int status)
{
	if (0 == status)
		platform_log(MAP_LIBRARY,LOG_INFO, "command: %s(%s) [success (%s implementation)]; result: %s\n", 
							cmdstr,subcmd, (capi? "C":"LUA"), (char*)output);
	else
		platform_log(MAP_LIBRARY,LOG_INFO, "command: %s(%s) [failed (%s implementation)]\n", cmdstr,subcmd, (capi? "C":"LUA"));
}

void print_bss_state_info(int cmd, const char* cmdstr, const char* subcmd, void* capi, void* output, int status)
{
	ssid_radio_state_t *state_info = (ssid_radio_state_t*)output;

	if (0 == status) {
		platform_log(MAP_LIBRARY,LOG_INFO, "command: %s(%s) [success (%s implementation)]\n", cmdstr,subcmd, (capi? "C":"LUA"));
		platform_log(MAP_LIBRARY,LOG_INFO, "result: if_name: %s, radio_state: %d, bss_state: %d]\n", 
								state_info->if_name, state_info->radio_state, state_info->bss_state);
	}
	else
		platform_log(MAP_LIBRARY,LOG_INFO, "command: %s(%s) [failed (%s implementation)]\n", cmdstr,subcmd, (capi? "C":"LUA"));
}


void print_set_ieee_wifi_params(int cmd, const char* cmdstr, const char* subcmd, void* capi, void* output, int status)
{
	struct wifi_params *wp = (struct wifi_params*)output;

	if (0 == status) {
		platform_log(MAP_LIBRARY,LOG_INFO, "command: %s(%s) [success (%s implementation)]\n", cmdstr,subcmd, (capi? "C":"LUA"));
		platform_log(MAP_LIBRARY,LOG_INFO, "result: interface: %s, ssid: %s, password: %s]\n", wp->interface, wp->ssid, wp->passwd);
	}
	else {
		platform_log(MAP_LIBRARY,LOG_INFO, "result: interface: %s, ssid: %s, password: %s]\n", wp->interface, wp->ssid, wp->passwd);
		platform_log(MAP_LIBRARY,LOG_INFO, "command: %s(%s) [failed (%s implementation)]\n", cmdstr,subcmd, (capi? "C":"LUA"));
	}
}


void print_set_steer(int cmd, const char* cmdstr, const char* subcmd, void* capi, void* output, int status)
{
	struct sta_steer_params *steer = (struct  sta_steer_params*)output;
	char dst_mac_str[MAX_MAC_STRING_LEN];
	char source_bssid_str[MAX_MAC_STRING_LEN];
	
	if (0 == status) {
		platform_log(MAP_LIBRARY,LOG_INFO, "command: %s(%s) [success (%s implementation)]\n", cmdstr,subcmd, (capi? "C":"LUA"));
		get_mac_string(steer->dst_mac, dst_mac_str);
		get_mac_string(steer->source_bssid, source_bssid_str);
		
		platform_log(MAP_LIBRARY,LOG_INFO, "dst_mac: %s\n", dst_mac_str);
		platform_log(MAP_LIBRARY,LOG_INFO, "source_bssid: %s\n", source_bssid_str);
		platform_log(MAP_LIBRARY,LOG_INFO, "ap_name: %s\n", steer->ap_name);

		platform_log(MAP_LIBRARY,LOG_INFO, "disassociation_timer: %d\n", steer->disassociation_timer);
		platform_log(MAP_LIBRARY,LOG_INFO, "opportunity_wnd: %d\n", steer->opportunity_wnd);
		platform_log(MAP_LIBRARY,LOG_INFO, "flag: %d\n", steer->flag);
		platform_log(MAP_LIBRARY,LOG_INFO, "abridged_mode: %d\n", steer->abridged_mode);
		platform_log(MAP_LIBRARY,LOG_INFO, "disassoc_imminent: %d\n", steer->disassoc_imminent);
		platform_log(MAP_LIBRARY,LOG_INFO, "sta_count: %d\n", steer->sta_count);
		platform_log(MAP_LIBRARY,LOG_INFO, "bssid_count: %d\n", steer->bssid_count);
		for (int index = 0; index < steer->sta_count; index++) {
			char dst_mac_str[MAX_MAC_STRING_LEN];
			get_mac_string(steer->sta_info[index].bssid, dst_mac_str);
			platform_log(MAP_LIBRARY,LOG_INFO, "steer->sta_info[%d].bssid: %s\n", index, dst_mac_str);
			platform_log(MAP_LIBRARY,LOG_INFO, "steer->sta_info[%d].channel: %d\n", index, steer->sta_info[index].channel);
			platform_log(MAP_LIBRARY,LOG_INFO, "steer->sta_info[%d].operatingclass: %d\n", index, steer->sta_info[index].operating_class);
			get_mac_string(steer->sta_info[index].sta_mac, dst_mac_str);
			platform_log(MAP_LIBRARY,LOG_INFO, "steer->sta_info[%d].sta_mac: %s\n", index, dst_mac_str);
		}
	}
	else
		platform_log(MAP_LIBRARY,LOG_INFO, "command: %s(%s) [failed (%s implementation)]\n", cmdstr,subcmd, (capi? "C":"LUA"));
}


void print_cumulative_sta_stats(void* config, void* capi, int status)
{
	cum_stats_t*     cum_sta =  (cum_stats_t *)config;
	map_sta_stats_t* sta_list = (map_sta_stats_t*)cum_sta->cum_stats;
	char macstring[MAX_MAC_STRING_LEN];
	
	platform_log(MAP_LIBRARY,LOG_INFO, "cumulative_sta_stats; [status: %d (%s)]\n", status, (capi? "C":"LUA"));
	platform_log(MAP_LIBRARY,LOG_INFO, "sta_stats cum_sta->stats_count: %d\n", cum_sta->stats_count);
	int index;
	for (index = 0; index < cum_sta->stats_count; index++)
	{
		platform_log(MAP_LIBRARY,LOG_INFO, "sta_list[%d].bssid: %s\n", index, get_mac_string(sta_list[index].bssid, macstring));
		platform_log(MAP_LIBRARY,LOG_INFO, "sta_list[%d].mac: %s\n", index, get_mac_string(sta_list[index].mac, macstring));

		platform_log(MAP_LIBRARY,LOG_INFO, "sta_list[%d].metrics.link.age: %u\n" , index, sta_list[index].metrics.link.age);
		platform_log(MAP_LIBRARY,LOG_INFO, "sta_list[%d].metrics.link.ul_mac_datarate: %u\n" , index, sta_list[index].metrics.link.ul_mac_datarate);
		platform_log(MAP_LIBRARY,LOG_INFO, "sta_list[%d].metrics.link.dl_mac_datarate: %u\n" , index, sta_list[index].metrics.link.dl_mac_datarate);
		platform_log(MAP_LIBRARY,LOG_INFO, "sta_list[%d].metrics.link.rssi: %u\n" , index, sta_list[index].metrics.link.rssi);

		platform_log(MAP_LIBRARY,LOG_INFO, "sta_list[%d].metrics.traffic.txbytes: %u\n" , index, sta_list[index].metrics.traffic.txbytes);
		platform_log(MAP_LIBRARY,LOG_INFO, "sta_list[%d].metrics.traffic.rxbytes: %u\n" , index, sta_list[index].metrics.traffic.rxbytes);
		platform_log(MAP_LIBRARY,LOG_INFO, "sta_list[%d].metrics.traffic.txpkts: %u\n" , index, sta_list[index].metrics.traffic.txpkts);
		platform_log(MAP_LIBRARY,LOG_INFO, "sta_list[%d].metrics.traffic.rxpkts: %u\n" , index, sta_list[index].metrics.traffic.rxpkts);
		platform_log(MAP_LIBRARY,LOG_INFO, "sta_list[%d].metrics.traffic.txpkterrors: %u\n" , index, sta_list[index].metrics.traffic.txpkterrors);
		platform_log(MAP_LIBRARY,LOG_INFO, "sta_list[%d].metrics.traffic.rxpkterrors: %u\n" , index, sta_list[index].metrics.traffic.rxpkterrors);
		platform_log(MAP_LIBRARY,LOG_INFO, "sta_list[%d].metrics.traffic.retransmission_cnt: %u\n" , index, sta_list[index].metrics.traffic.retransmission_cnt);
	}
}


void print_cumulative_bss_stats(void* config, void* capi, int status)
{
	cum_stats_t* cum_sta =  (cum_stats_t*)config;
	map_bss_stats_t* bss_list = (map_bss_stats_t*)cum_sta->cum_stats;
	char macstring[18];

	platform_log(MAP_LIBRARY,LOG_INFO, "cumulative_bss_stats; [status: %d (%s)]\n", status, (capi? "C":"LUA"));
	platform_log(MAP_LIBRARY,LOG_INFO, "bss_stats cum_sta->stats_count: %d\n", cum_sta->stats_count);

	int index;
	for (index = 0; index < cum_sta->stats_count; index++)
	{
		platform_log(MAP_LIBRARY,LOG_INFO, "bss_list[%d].bssid: %s\n", index, get_mac_string(bss_list[index].bssid, macstring));	
		platform_log(MAP_LIBRARY,LOG_INFO, "bss_list[%d].metrics.channel_utilization: %u\n", index, bss_list[index].metrics.channel_utilization);
		platform_log(MAP_LIBRARY,LOG_INFO, "bss_list[%d].metrics.sta_count: %d\n", index, bss_list[index].metrics.sta_count);
		platform_log(MAP_LIBRARY,LOG_INFO, "bss_list[%d].metrics.esp_present: %d\n", index, bss_list[index].metrics.esp_present);
		platform_log(MAP_LIBRARY,LOG_INFO, "bss_list[%d].esp.esp_subelement: 0x%x\n", index, bss_list[index].metrics.esp[WIFI_AC_BE].esp_subelement);
		platform_log(MAP_LIBRARY,LOG_INFO, "bss_list[%d].esp.estimated_air_time_fraction: %d\n", index, bss_list[index].metrics.esp[WIFI_AC_BE].estimated_air_time_fraction);
		platform_log(MAP_LIBRARY,LOG_INFO, "bss_list[%d].esp.ppdu_target_duration: %d\n", index, bss_list[index].metrics.esp[WIFI_AC_BE].ppdu_target_duration);
	}
}




void test_lib_apis(void)
{
	platform_log(MAP_LIBRARY,LOG_INFO, "============ starting api testing===============\n");
	int status;
	char resultstr[100];

	platform_log(MAP_LIBRARY,LOG_INFO, "Testig MAP_PLATFORM_GET_MULTIAP_CONFIG\n");
	status = platform_get(MAP_PLATFORM_GET_MULTIAP_CONFIG, 
						  "controller.macaddress", resultstr);
	platform_log(MAP_LIBRARY,LOG_INFO, "controller.macaddress; status: %d; result: %s\n", status, resultstr);

	status = platform_get(MAP_PLATFORM_GET_MULTIAP_CONFIG, 
						  "controller_policy_config.metrics_report_interval", resultstr);
	platform_log(MAP_LIBRARY,LOG_INFO, "controller_policy_config.metrics_report_interval; status: %d; result: %s\n", status, resultstr);

	status = platform_get(MAP_PLATFORM_GET_MULTIAP_CONFIG, 
						  "al_entity", resultstr);
	platform_log(MAP_LIBRARY,LOG_INFO, "al_entity; status: %d; result: %s\n", status, resultstr);


	platform_log(MAP_LIBRARY,LOG_INFO, "================ api testing done===============\n");

#if 0
{
		case MAP_PLATFORM_GET_MULTIAP_CONFIG:
			print_get_config(cmd, cmdstr, subcmd, capi, output, status);
		break;

		case MAP_PLATFORM_GET_IEEE1905_CONFIG:
			print_get_config(cmd, cmdstr, subcmd, capi, output, status);
		break;

		case MAP_PLATFORM_GET_INTERFACE_INFO:

		break;

		case MAP_PLATFORM_GET_AP_AUTOCONFIG:

		break;

		case MAP_PLATFORM_SET_IEEE_1905_WIFI_PARAMS:
			print_set_ieee_wifi_params(cmd, cmdstr, subcmd, capi, output, status);
		break;

		case MAP_PLATFORM_GET_MAP_MAC_ADDRESS:
			print_get_config(cmd, cmdstr, subcmd, capi, output, status);
		break;

		case MAP_PLATFORM_GET_IEEE_INTERFACE_FROM_MAC:
			print_get_config(cmd, cmdstr, subcmd, capi, output, status);
		break;

		case MAP_PLATFORM_GET_INTERFACE_STATE:
			print_get_config(cmd, cmdstr, subcmd, capi, output, status);
		break;

		case MAP_PLATFORM_GET_SSID:
			print_get_config(cmd, cmdstr, subcmd, capi, output, status);
		break;

		case MAP_PLATFORM_GET_WPA_PSK:
			print_get_config(cmd, cmdstr, subcmd, capi, output, status);
		break;

		case MAP_PLATFORM_GET_FREQUENCY_BAND:

		break;

		case MAP_PLATFORM_GET_VALID_FHBH_INTERFACE:
			print_get_config(cmd, cmdstr, subcmd, capi, output, status);
		break;

		case MAP_PLATFORM_GET_AGENT_BSSID:
			print_get_config(cmd, cmdstr, subcmd, capi, output, status);
		break;

		case MAP_PLATFORM_GET_BRIDGE_INFO:

		break;

		case MAP_PLATFORM_GET_CONTROLLER_POLICY_CONFIG:

		break;

		case MAP_PLATFORM_SET_CONTROLLER_INTERFACE_LINK:

		break;

		case MAP_PLATFORM_GET_RADIO_INFO:

		break;

		case MAP_PLATFORM_GET_CUMULATIVE_BSS_STATS:
			print_cumulative_bss_stats(output, capi, status);
		break;

		case MAP_PLATFORM_GET_CUMULATIVE_STA_STATS:
			print_cumulative_sta_stats(output, capi, status);
		break;

		case MAP_PLATFORM_APPLY_ACL:
		break;

		case MAP_PLATFORM_QUERY_BEACON_METRICS:
		break;

		case MAP_PLATFORM_GET_BEACON_METRICS_RESPONSE:
		break;

		case MAP_PLATFORM_GET_RADIO_BSS_STATE_INFO:
			print_bss_state_info(cmd, cmdstr, subcmd, capi, output, status);
		break;

		case MAP_PLATFORM_GET_AP_FROM_BSSID:
			print_get_config(cmd, cmdstr, subcmd, capi, output, status);
		break;

		case MAP_PLATFORM_BTM_STA_STEER:
			print_set_steer(cmd, cmdstr, subcmd, capi, output, status);
		break;

		case MAP_PLATFORM_LEGACY_STA_STEER:
			print_set_steer(cmd, cmdstr, subcmd, capi, output, status);
		break;

		case MAP_PLATFORM_GET_ASSOC_FRAME:
		break;

		default:
			platform_log(MAP_LIBRARY,LOG_ERR, "Unknown command: %d\n", cmd);
		break;
	}

#endif
}


void print_autoconfig_result(void *data)
{
	map_ale_info_t *agent_node = (map_ale_info_t*)data;

	platform_log(MAP_LIBRARY,LOG_INFO, "===============print_autoconfig_result===============\n");

	char macstring[MAX_MAC_STRING_LEN];
	get_mac_string(agent_node->al_mac, macstring);
	platform_log(MAP_LIBRARY,LOG_INFO, "al_mac: %s\n", macstring);
	get_mac_string(agent_node->iface_mac, macstring);
	platform_log(MAP_LIBRARY,LOG_INFO, "iface_mac: %s\n", macstring);
	platform_log(MAP_LIBRARY,LOG_INFO, "iface_name: %s\n", agent_node->iface_name);
	platform_log(MAP_LIBRARY,LOG_INFO, "num_radios: %d\n", agent_node->num_radios);
	platform_log(MAP_LIBRARY,LOG_INFO, "num_supported_radios: %d\n", agent_node->num_supported_radios);
	platform_log(MAP_LIBRARY,LOG_INFO, "bh_set: %d\n", agent_node->bh_set);

	map_radio_info_t* radio;
	int r = 0;
	for (int i = 0; i < MAX_RADIOS_PER_AGENT && r < agent_node->num_radios ; i++) {
		platform_log(MAP_LIBRARY,LOG_INFO, "[%d] radio_list size: %d\n", i, sizeof(agent_node->radio_list));
		radio = agent_node->radio_list[i];
		if (!radio)
			continue;
		r++;
		
		get_mac_string(radio->radio_id, macstring);
		platform_log(MAP_LIBRARY,LOG_INFO, "[%d] radio_id: %s\n", i, macstring);
		platform_log(MAP_LIBRARY,LOG_INFO, "[%d] iface_name: %s\n", i, radio->iface_name);
		platform_log(MAP_LIBRARY,LOG_INFO, "[%d] supported_freq: %d\n", i, radio->supported_freq);
		platform_log(MAP_LIBRARY,LOG_INFO, "[%d] max_bss: %d\n", i, radio->max_bss);
		platform_log(MAP_LIBRARY,LOG_INFO, "[%d] num_bss: %d\n", i, radio->num_bss);
		platform_log(MAP_LIBRARY,LOG_INFO, "[%d] current_op_class: %d\n", i, radio->current_op_class);
		platform_log(MAP_LIBRARY,LOG_INFO, "[%d] current_op_channel: %d\n", i, radio->current_op_channel);
		platform_log(MAP_LIBRARY,LOG_INFO, "[%d] state: %d\n", i, radio->state);
		platform_log(MAP_LIBRARY,LOG_INFO, "[%d] wsc_data: %p\n", i, radio->wsc_data);
		platform_log(MAP_LIBRARY,LOG_INFO, "[%d] ale: %p\n", i, radio->ale);

		int b = 0;
		for (int j = 0; j < MAX_BSS_PER_RADIO && b < radio->num_bss; j++) {
			map_bss_info_t* bss = radio->bss_list[j];
			if (!bss)
				continue;
			b++;
			platform_log(MAP_LIBRARY,LOG_INFO, "===============bss_list===============\n");
			get_mac_string(bss->bssid, macstring);
			platform_log(MAP_LIBRARY,LOG_INFO, "[%d] bssid: %s\n", i, macstring);
			platform_log(MAP_LIBRARY,LOG_INFO, "[%d] supported_sec_modes: %s\n", i, bss->supported_sec_modes);
			platform_log(MAP_LIBRARY,LOG_INFO, "[%d] ssid_len: %d\n", i, bss->ssid_len);
			platform_log(MAP_LIBRARY,LOG_INFO, "[%d] ssid: %s\n", i, bss->ssid);
			platform_log(MAP_LIBRARY,LOG_INFO, "[%d] iface_name: %s\n", i, bss->iface_name);
			platform_log(MAP_LIBRARY,LOG_INFO, "[%d] state: %d\n", i, bss->state);
			platform_log(MAP_LIBRARY,LOG_INFO, "[%d] type: %d\n", i, bss->type);
			platform_log(MAP_LIBRARY,LOG_INFO, "[%d] metrics, radio - not printing\n", i);

			if(bss->sta_list) {
				uint32_t count = list_get_size(bss->sta_list);
				platform_log(MAP_LIBRARY,LOG_INFO, "[%d] number of stations connected: %d\n", i, count);
				if (count)
					platform_log(MAP_LIBRARY,LOG_INFO, "---------------sta_list---------------\n");
				for(int k = 0; k < count; k++) {
					map_sta_info_t *sta = object_at_index(bss->sta_list, k);
					if (sta) {
						get_mac_string(sta->mac, macstring);
						platform_log(MAP_LIBRARY,LOG_INFO, "[%d] mac: %s\n", i, macstring);
						platform_log(MAP_LIBRARY,LOG_INFO, "[%d] not printing other station details now\n", i);
					}
				}
				if (count)
					platform_log(MAP_LIBRARY,LOG_INFO, "--------------------------------------\n");
			}
		}

		platform_log(MAP_LIBRARY,LOG_INFO, "===============radio_caps===============\n");
		platform_log(MAP_LIBRARY,LOG_INFO, "[%d] max_bss_supported: %d\n", i, radio->radio_caps.max_bss_supported);
		platform_log(MAP_LIBRARY,LOG_INFO, "[%d] max_tx_spatial_streams: %d\n", i, radio->radio_caps.max_tx_spatial_streams);
		platform_log(MAP_LIBRARY,LOG_INFO, "[%d] max_rx_spatial_streams: %d\n", i, radio->radio_caps.max_rx_spatial_streams);
		platform_log(MAP_LIBRARY,LOG_INFO, "[%d] type: %d\n", i, radio->radio_caps.type);
		platform_log(MAP_LIBRARY,LOG_INFO, "[%d] max_bandwidth: %d\n", i, radio->radio_caps.max_bandwidth);
		platform_log(MAP_LIBRARY,LOG_INFO, "[%d] sgi_support: %d\n", i, radio->radio_caps.sgi_support);
		platform_log(MAP_LIBRARY,LOG_INFO, "[%d] su_beamformer_capable: %d\n", i, radio->radio_caps.su_beamformer_capable);
		platform_log(MAP_LIBRARY,LOG_INFO, "[%d] mu_beamformer_capable: %d\n", i, radio->radio_caps.mu_beamformer_capable);
		platform_log(MAP_LIBRARY,LOG_INFO, "[%d] supported_standard: %d\n", i, radio->radio_caps.supported_standard);
		platform_log(MAP_LIBRARY,LOG_INFO, "[%d] transmit_power_limit: %d\n", i, radio->radio_caps.transmit_power_limit);

		platform_log(MAP_LIBRARY,LOG_INFO, "[%d] ===============ht_caps===============\n", i);
		if (radio->ht_caps) {
			platform_log(MAP_LIBRARY,LOG_INFO, "[%d] max_supported_tx_streams: %d\n", i, radio->ht_caps->max_supported_tx_streams);
			platform_log(MAP_LIBRARY,LOG_INFO, "[%d] max_supported_rx_streams: %d\n", i, radio->ht_caps->max_supported_rx_streams);
			platform_log(MAP_LIBRARY,LOG_INFO, "[%d] gi_support_20mhz: %d\n", i, radio->ht_caps->gi_support_20mhz);
			platform_log(MAP_LIBRARY,LOG_INFO, "[%d] gi_support_40mhz: %d\n", i, radio->ht_caps->gi_support_40mhz);
			platform_log(MAP_LIBRARY,LOG_INFO, "[%d] ht_support_40mhz: %d\n", i, radio->ht_caps->ht_support_40mhz);
		}
		platform_log(MAP_LIBRARY,LOG_INFO, "[%d] vht_caps: %p\n", i, radio->vht_caps);
		platform_log(MAP_LIBRARY,LOG_INFO, "[%d] he_caps: %p\n", i, radio->he_caps);
	}
	
	platform_log(MAP_LIBRARY,LOG_INFO, "===============agent_policy===============\n");
	platform_log(MAP_LIBRARY,LOG_INFO, "metric_reporting_interval: %d\n", agent_node->agent_policy.metric_reporting_interval);
	platform_log(MAP_LIBRARY,LOG_INFO, "number_of_local_steering_disallowed: %d\n", agent_node->agent_policy.number_of_local_steering_disallowed);
	platform_log(MAP_LIBRARY,LOG_INFO, "number_of_btm_steering_disallowed: %d\n", agent_node->agent_policy.number_of_btm_steering_disallowed);
	platform_log(MAP_LIBRARY,LOG_INFO, "local_steering_macs_disallowed_list: %p\n", agent_node->agent_policy.local_steering_macs_disallowed_list);
	platform_log(MAP_LIBRARY,LOG_INFO, "btm_steering_macs_disallowed_list: %p\n", agent_node->agent_policy.btm_steering_macs_disallowed_list);
	
	platform_log(MAP_LIBRARY,LOG_INFO, "===============agent_capablity===============\n");
	platform_log(MAP_LIBRARY,LOG_INFO, "ib_unassociated_sta_link_metrics_supported: %d\n", agent_node->agent_capability.ib_unassociated_sta_link_metrics_supported);
	platform_log(MAP_LIBRARY,LOG_INFO, "oob_unassociated_sta_link_metrics_supported: %d\n", agent_node->agent_capability.oob_unassociated_sta_link_metrics_supported);
	platform_log(MAP_LIBRARY,LOG_INFO, "rssi_agent_steering_supported: %d\n", agent_node->agent_capability.rssi_agent_steering_supported);
	platform_log(MAP_LIBRARY,LOG_INFO, "=====================================================\n");
}


void execute_platform_api_test(void)
{
	test_lib_apis();
}


