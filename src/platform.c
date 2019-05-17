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
#include "platform_map.h"
#include "platform_lib_capi.h"
#include "platform_lib_test.h"


typedef int(*T_ref_c_get_func_ptr)(const char *cmd, void *data, void *ctx);
typedef int(*T_ref_c_set_func_ptr)(void *data, void *ctx);

typedef struct _platform_handle
{
	unsigned int command;
	const char* cmd_name;
	T_ref_c_get_func_ptr get_data;
	T_ref_c_set_func_ptr set_data;
}platform_handle;


static platform_handle platform_table[]=
{
	{MAP_PLATFORM_UNUSED, "MAP_PLATFORM_UNUSED", NULL, NULL},
	{MAP_PLATFORM_UNUSED, "MAP_PLATFORM_UNUSED", NULL, NULL},
	{MAP_PLATFORM_UNUSED, "MAP_PLATFORM_UNUSED", NULL, NULL},
	{MAP_PLATFORM_GET_MULTIAP_CONFIG, "GET_MULTIAP_CONFIG", get_multiap_configuration, NULL},
	{MAP_PLATFORM_GET_IEEE1905_CONFIG, "GET_IEEE1905_CONFIG", get_ieee1905_configuration, NULL},
	{MAP_PLATFORM_GET_INTERFACE_INFO, "GET_INTERFACE_INFO", platform_if_info_get, NULL},
	{MAP_PLATFORM_GET_AP_AUTOCONFIG, "GET_AP_AUTOCONFIG", get_map_ap_autoconfig, NULL},
	{MAP_PLATFORM_SET_IEEE_1905_WIFI_PARAMS, "SET_IEEE_1905_WIFI_PARAMS", NULL, set_wifi_parameters},
	{MAP_PLATFORM_GET_MAP_MAC_ADDRESS, "GET_MAP_MAC_ADDRESS", get_map_interface_mac_address, NULL},
	{MAP_PLATFORM_GET_IEEE_INTERFACE_FROM_MAC, "GET_IEEE_INTERFACE_FROM_MAC", get_if_from_macaddress, NULL},
	{MAP_PLATFORM_UNUSED, "MAP_PLATFORM_UNUSED", NULL, NULL},
	{MAP_PLATFORM_GET_INTERFACE_STATE, "GET_INTERFACE_STATE", get_network_interface_state, NULL},
	{MAP_PLATFORM_GET_SSID, "GET_SSID", get_map_ssid, NULL},
	{MAP_PLATFORM_GET_WPA_PSK, "GET_WPA_PSK", get_ap_psk, NULL},
	{MAP_PLATFORM_GET_FREQUENCY_BAND, "GET_FREQUENCY_BAND", platform_get_frequency_band, NULL},
	{MAP_PLATFORM_GET_VALID_FHBH_INTERFACE, "GET_VALID_FHBH_INTERFACE", get_valid_interface, NULL},
	{MAP_PLATFORM_GET_AGENT_BSSID, "GET_AGENT_BSSID", platform_get_agent_bssid, NULL},
	{MAP_PLATFORM_GET_BRIDGE_INFO, "GET_BRIDGE_INFO", platform_get_bridge_info, NULL},
	{MAP_PLATFORM_GET_2G_CHANNEL_PREF, "GET_2G_CHANNEL_PREF", platform_get_2g_channel_pref, NULL},
	{MAP_PLATFORM_GET_CONTROLLER_POLICY_CONFIG, "GET_CONTROLLER_POLICY_CONFIG", platform_get_controller_policy_config, NULL},
	{MAP_PLATFORM_SET_CONTROLLER_INTERFACE_LINK, "SET_CONTROLLER_INTERFACE_LINK", NULL, platform_set_controller_interface_link},
	{MAP_PLATFORM_GET_RADIO_INFO, "GET_RADIO_INFO", platform_get_radio_info, NULL},
	{MAP_PLATFORM_GET_CUMULATIVE_BSS_STATS, "GET_CUMULATIVE_BSS_STATS", get_cumulative_bss_statistics, NULL},
	{MAP_PLATFORM_GET_CUMULATIVE_STA_STATS, "GET_CUMULATIVE_STA_STATS", get_cumulative_sta_statistics, NULL},
	{MAP_PLATFORM_APPLY_ACL, "APPLY_ACL", NULL, platform_apply_acl},
	{MAP_PLATFORM_QUERY_BEACON_METRICS, "QUERY_BEACON_METRICS", NULL, platform_query_beacon_metrics},
	{MAP_PLATFORM_GET_BEACON_METRICS_RESPONSE, "GET_BEACON_METRICS_RESPONSE", get_beacon_metrics_response, NULL},
	{MAP_PLATFORM_GET_RADIO_BSS_STATE_INFO, "GET_RADIO_BSS_STATE_INFO", get_radio_and_bss_state_information, NULL},
	{MAP_PLATFORM_GET_AP_FROM_BSSID, "GET_AP_FROM_BSSID", get_apname_from_bssid, NULL},
	{MAP_PLATFORM_BTM_STA_STEER, "BTM_STA_STEER", NULL, map_btm_sta_steer_set},
	{MAP_PLATFORM_LEGACY_STA_STEER, "LEGACY_STA_STEER", NULL, set_legacy_sta_steer},
	{MAP_PLATFORM_GET_ASSOC_FRAME, "GET_ASSOC_FRAME", platform_get_assoc_frame, NULL},
	{MAP_PLATFORM_SET_IEEE_1905_OFF_BSS, "SET_IEEE_1905_OFF_BSS", NULL, switch_off_bss},
	{MAP_PLATFORM_SET_IEEE_1905_OFF_RADIO, "SET_IEEE_1905_OFF_RADIO", NULL, switch_off_radio},
	{MAP_PLATFORM_REQ_UNASSOC_MEASUREMENT, "REQ_UNASSOC_MEASUREMENT", NULL, platform_req_unassoc_measurement},
	{MAP_PLATFORM_GET_UNASSOC_REPORT, "GET_UNASSOC_REPORT", platform_get_unassoc_report, NULL},
	{MAP_PLATFORM_GET_UNASSOC_MEASUREMENT_SUPPORT, "GET_UNASSOC_SUPPORT", platform_get_outofBand_measurement_support, NULL},
	{MAP_PLATFORM_SET_CHANNEL, "SET_CHANNEL", NULL, platform_set_channel},
	{MAP_PLATFORM_GET_5G_CHANNEL_PREF, "GET_5G_CHANNEL_PREF", platform_get_5g_channel_pref, NULL},
        {MAP_PLATFORM_FLUSH_UNASSOC_MEASUREMENT, "FLUSH_UNASSOC_MEASUREMENT", NULL, platform_flush_unassoc_measurement},
        {MAP_PLATFORM_GET_TX_LINK_METRICS, "GET_TX_LINK_MET", platform_neighbour_tx_link, NULL},
        {MAP_PLATFORM_GET_RX_LINK_METRICS, "GET_RX_LINK_MET", platform_neighbour_rx_link, NULL},
	{MAP_PLATFORM_SET_TX_PWR, "SET_TX_PWR", NULL, platform_set_tx_pwr},
	{MAP_PLATFORM_GET_TX_PWR, "GET_TX_PWR", platform_get_tx_pwr, NULL},	
	{MAP_PLATFORM_SEND_STN_EVT, "SEND_STN_EVT", NULL, platform_send_stn_evt},
};


unsigned int gnum_commands=sizeof(platform_table)/sizeof(platform_handle );

int platform_get(unsigned int command,const char* subcmd,void* data)
{
	unsigned int cmd_index = command & CMD_MASK;
	int status = -1;

	if ((cmd_index < gnum_commands) && (command == platform_table[cmd_index].command))
	{
		if (platform_table[cmd_index].get_data)
		{
			status = platform_table[cmd_index].get_data(subcmd, data, NULL);
		}
		else
		{
			status = platform_get_lua(command, subcmd, data);
		}
	}
	else
		platform_log(MAP_LIBRARY,LOG_ERR,"platform_get failed; command: %d\n", command);

	return status;
}


int platform_get_context(unsigned int command,const char* subcmd,void* data, void *ctxt)
{
	unsigned int cmd_index = command & CMD_MASK;
	int status = -1;

	if((cmd_index < gnum_commands) && (command == platform_table[cmd_index].command))
	{
		platform_log(MAP_LIBRARY,LOG_DEBUG,"platform_get_context(%s(%d)), subcmd:%s\n", platform_table[cmd_index].cmd_name, command, subcmd);

		if (platform_table[cmd_index].get_data)
		{
			status = platform_table[cmd_index].get_data(subcmd, data, ctxt);
		}
		else
		{
			status = platform_get_context_lua(command, subcmd, data, ctxt);
		}
	}
	else
		platform_log(MAP_LIBRARY,LOG_ERR,"platform_get_context failed; command: %d\n", command);

	return status;
}


int platform_set(unsigned int command,void* data)
{
	unsigned int cmd_index = command & CMD_MASK;
	int status = -1;

	if((cmd_index < gnum_commands) && (command == platform_table[cmd_index].command))
	{
		platform_log(MAP_LIBRARY,LOG_DEBUG,"platform_set(%s(%d))\n", platform_table[cmd_index].cmd_name, command);

		if (platform_table[cmd_index].set_data)
		{
			status = platform_table[cmd_index].set_data(data, NULL);
		}
		else
		{
			status = platform_set_lua(command, data);
		}
	}
	else
		platform_log(MAP_LIBRARY,LOG_ERR,"platform_set failed; command: %d\n", command);

	return status;
}


int platform_set_context(unsigned int command,void* data, void *ctxt)
{
	unsigned int cmd_index = command & CMD_MASK;
	int status = -1;

	platform_log(MAP_LIBRARY,LOG_DEBUG,"command %d - %d - %d\n", command, gnum_commands, platform_table[cmd_index].command);

	if((cmd_index < gnum_commands) && (command == platform_table[cmd_index].command))
	{
		platform_log(MAP_LIBRARY,LOG_DEBUG,"platform_set_context(%s(%d))\n", platform_table[cmd_index].cmd_name, command);

		if (platform_table[cmd_index].set_data)
		{
			status = platform_table[cmd_index].set_data(data, ctxt);
		}
		else
		{
			status = platform_set_context_lua(command, data, ctxt);
		}
	}
	else 
		platform_log(MAP_LIBRARY,LOG_ERR,"platform_set_context failed; command: %d\n", command);

	return status;
}


