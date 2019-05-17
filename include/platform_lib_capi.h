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

#ifndef PLATFORM_LIB_CAPI_H
#define PLATFORM_LIB_CAPI_H
#define BSS_LIST_DELIMIT ","

#include <stdarg.h>
#include <libubus.h>
#include "1905_platform.h"
#include "platform_lib_capi_util.h"
#include "map_common_defines.h"

typedef struct _map1905if_interface_info_t {
	char if_name[MAX_IFACE_NAME_LEN];
	char ap_name[MAX_AP_NAME_LEN];
	char radio_name[MAX_RADIO_NAME_LEN];
	uint8_t is_new_interface;
	struct interfaceInfo if_info;
} map1905if_interface_info_t;

int platform_if_info_init();
int platform_if_info_get(const char *name, void *data, void *ctx);
int platform_if_info_neighbor_list_update(struct ubus_context *ctx, const char *ap_no);
int platform_if_info_wireless_if_state_update(struct ubus_context *ctx, const char *interface, uint8_t *bssid);
int platform_if_info_wired_if_state_update(struct ubus_context *ctx, const char *interface);
int platform_if_info_wds_if_info_update(struct ubus_context *ctx, const char *interface, int8_t *is_new_wds, char *if_state);

int platform_get_radio_info(const char* radio_name, void* radio_channel_data, void* context);
int platform_get_agent_bssid(const char* ap_name, void* agent_bssid_data, void* context);
int platform_apply_acl(void* config, void* context);
int platform_get_frequency_band(const char* interface, void* freq_band_data, void* context);
int platform_get_bridge_info(const char* sub_command, void* bridge_list_data, void* context);
int platform_get_controller_policy_config(const char* sub_cmd, void* policy_data, void* context);
int platform_set_controller_interface_link(void* interface_name, void* context);
int platform_get_2g_channel_pref(const char* opclass_str, void* config, void *ctx);
int platform_query_beacon_metrics(void* config, void* context);
int platform_get_assoc_frame(const char * input_str, void *config, void* context);
int platform_auth_check(char *if_name,uint16_t *auth_type);

int get_cumulative_sta_statistics(const char* subcmd, void* config, void *ctx);
int get_cumulative_bss_statistics(const char* subcmd, void* config, void *ctx);
int get_radio_and_bss_state_information(const char* interface_name, void* data, void *ctx);
int get_apname_from_bssid(const char* bssid, void* data, void *ctx);
int get_map_interface_mac_address(const char* unused, void* data, void *ctx);
int get_valid_interface(const char* interface, void* data, void *ctx);
int get_if_from_macaddress(const char* key, void* data, void *ctx);
int set_wifi_parameters(void* data, void *ctx);
int map_btm_sta_steer_set(void* data, void *ctx);
int get_ieee1905_configuration(const char* key, void* data, void *ctx);
int get_network_interface_state(const char* ifname, void* data, void *ctx);
int get_map_ssid(const char* iftype, void* data, void *ctx);
int get_ap_psk(const char* iftype, void* data, void *ctx);
int set_legacy_sta_steer(void* data, void *ctx);
int get_multiap_configuration(const char* key, void* data, void *ctx);
int get_map_ap_autoconfig(const char *unused, void *data, void *ctx);
int get_beacon_metrics_response (const char* input, void* data, void *ctx);
int get_radio_name_from_if(char* if_name, char* radio_name, void* context);
int switch_off_bss(void* data, void *ctx);
int switch_off_radio(void* data, void *ctx);
int platform_set_channel(void* data, void *ctx);
int platform_get_5g_channel_pref(const char* opclass_str, void* config, void *ctx);

int platform_req_unassoc_measurement(void* data, void *ctx);
int platform_flush_unassoc_measurement(void* data, void *ctx);
int platform_get_unassoc_report(const char* subcmd, void* config, void *ctx);
int platform_get_outofBand_measurement_support(const char* subcmd, void* config, void *ctx);
int platform_neighbour_tx_link(const char* neighbour_dev_ptr, void* tx_met, void *ctx);
int platform_neighbour_rx_link(const char* neighbour_dev_ptr, void* rx_met, void *ctx);
int platform_set_tx_pwr(void* data, void *ctx);
int platform_get_tx_pwr(const char* radio_name, void* tx_pwr, void *ctx);
int platform_send_stn_evt(void* data, void *ctx);
uint8_t get_wps_state(char *ap_name,void *ctx);
int get_ap_from_bssid(char* bssid, char* ap_no, void* context);

#endif
#ifdef __cplusplus
}
#endif

