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

#ifndef PLATFORM_COMMANDS_H
#define PLATFORM_COMMANDS_H

#include "jansson.h"

#define CMD_MASK 0xFFFF
#define SUB_CMD_MASK 0xFF0000
#define SUB_CMD_FLAG 0x10000
#define CHECK_SUBCMD(x) (x&SUB_CMD_MASK)

#define MAX_SUBCMD_LEN 512

#define MAP_PLATFORM_UNUSED (0)
#define MAP_PLATFORM_GET_AGENT_CONFIG (1 | SUB_CMD_FLAG)
#define MAP_PLATFORM_GET_CONTROLLER_CONFIG (2 | SUB_CMD_FLAG)
#define MAP_PLATFORM_GET_MULTIAP_CONFIG (3 | SUB_CMD_FLAG)
#define MAP_PLATFORM_GET_IEEE1905_CONFIG (4 | SUB_CMD_FLAG)
#define MAP_PLATFORM_GET_INTERFACE_INFO (5 | SUB_CMD_FLAG)
#define MAP_PLATFORM_GET_AP_AUTOCONFIG (6)
#define MAP_PLATFORM_SET_IEEE_1905_WIFI_PARAMS (7 | SUB_CMD_FLAG)
#define MAP_PLATFORM_GET_MAP_MAC_ADDRESS (8)
#define MAP_PLATFORM_GET_IEEE_INTERFACE_FROM_MAC (9 | SUB_CMD_FLAG)
#define MAP_PLATFORM_SET_AGENT_STA_STEER (10 | SUB_CMD_FLAG)
#define MAP_PLATFORM_GET_INTERFACE_STATE (11 | SUB_CMD_FLAG)
#define MAP_PLATFORM_GET_SSID (12 | SUB_CMD_FLAG)
#define MAP_PLATFORM_GET_WPA_PSK (13 | SUB_CMD_FLAG)
#define MAP_PLATFORM_GET_FREQUENCY_BAND (14 | SUB_CMD_FLAG)
#define MAP_PLATFORM_GET_VALID_FHBH_INTERFACE (15 | SUB_CMD_FLAG)
#define MAP_PLATFORM_GET_AGENT_BSSID (16 | SUB_CMD_FLAG)
#define MAP_PLATFORM_GET_BRIDGE_INFO (17)
#define MAP_PLATFORM_GET_2G_CHANNEL_PREF (18 | SUB_CMD_FLAG)
#define MAP_PLATFORM_GET_CONTROLLER_POLICY_CONFIG (19)
#define MAP_PLATFORM_SET_CONTROLLER_INTERFACE_LINK (20 | SUB_CMD_FLAG)
#define MAP_PLATFORM_GET_RADIO_INFO (21 | SUB_CMD_FLAG)
#define MAP_PLATFORM_GET_CUMULATIVE_BSS_STATS (22)
#define MAP_PLATFORM_GET_CUMULATIVE_STA_STATS (23)
#define MAP_PLATFORM_APPLY_ACL (24 | SUB_CMD_FLAG)
#define MAP_PLATFORM_QUERY_BEACON_METRICS (25 | SUB_CMD_FLAG)
#define MAP_PLATFORM_GET_BEACON_METRICS_RESPONSE (26 | SUB_CMD_FLAG)
#define MAP_PLATFORM_GET_RADIO_BSS_STATE_INFO (27 | SUB_CMD_FLAG)
#define MAP_PLATFORM_GET_AP_FROM_BSSID (28 | SUB_CMD_FLAG)
#define MAP_PLATFORM_BTM_STA_STEER (29 | SUB_CMD_FLAG)
#define MAP_PLATFORM_LEGACY_STA_STEER (30 | SUB_CMD_FLAG)
#define MAP_PLATFORM_GET_ASSOC_FRAME (31 | SUB_CMD_FLAG)
#define MAP_PLATFORM_SET_IEEE_1905_OFF_BSS (32 | SUB_CMD_FLAG)
#define MAP_PLATFORM_SET_IEEE_1905_OFF_RADIO (33 | SUB_CMD_FLAG)
#define MAP_PLATFORM_REQ_UNASSOC_MEASUREMENT (34 | SUB_CMD_FLAG)
#define MAP_PLATFORM_GET_UNASSOC_REPORT (35 | SUB_CMD_FLAG)
#define MAP_PLATFORM_GET_UNASSOC_MEASUREMENT_SUPPORT (36 | SUB_CMD_FLAG)
#define MAP_PLATFORM_SET_CHANNEL (37 | SUB_CMD_FLAG)
#define MAP_PLATFORM_GET_5G_CHANNEL_PREF (38 | SUB_CMD_FLAG)
#define MAP_PLATFORM_FLUSH_UNASSOC_MEASUREMENT (39 | SUB_CMD_FLAG)
#define MAP_PLATFORM_GET_TX_LINK_METRICS (40 | SUB_CMD_FLAG)
#define MAP_PLATFORM_GET_RX_LINK_METRICS (41 | SUB_CMD_FLAG)
#define MAP_PLATFORM_SET_TX_PWR (42 | SUB_CMD_FLAG)
#define MAP_PLATFORM_GET_TX_PWR (43 | SUB_CMD_FLAG)
#define MAP_PLATFORM_SEND_STN_EVT (44 | SUB_CMD_FLAG)
#define COMMAND_END 254

int load_agent_config(void* config);

int load_controller_config(void* config);

int load_credential_config(void* config);

int get_operating_role(void);

int controller_load_policy_config(lua_State *L,void* config);

uint8_t get_eirp (uint8_t op_class, char* country);

int get_config(lua_State *L,void* config);

int get_bridge_conf(lua_State *L,void* config);

int get_map_mac_address(lua_State *L,void *config);

int get_interface_info(lua_State *L,void *config);

int get_ap_autoconfig(lua_State *L,void *config);

int get_frequency_band(lua_State *L,void* config);

int set_wifi_params(void *config, char *json_string);

int teardown_wifi_bss(void *config, char *json_string);

int map_query_beacon_metrics(void *config, char *json_str);

int map_beacon_metrics_response (lua_State *L,void* config);

int map_legacy_sta_steer(void *config, char *json_string); 

int map_btm_sta_steer(void *config, char *json_string); 

int map_apply_acl(void *config, char *json_string);

void def_config_path(unsigned int cmd,const char** path);

int get_current_channel_preference(lua_State *L,void *config);

int get_radio_info(lua_State *L,void *config);

int get_radio_bss_state(lua_State *L,void *config);

int set_config(void *config, char *json_string);

void print_json(json_t *root);

void print_json_aux(json_t *element, int indent);

void print_json_indent(int indent);

void print_json_array(json_t *element, int indent);

void print_json_string(json_t *element, int indent);

void print_json_integer(json_t *element, int indent);

void print_json_real(json_t *element, int indent);

void print_json_true(json_t *element, int indent);

void print_json_false(json_t *element, int indent);

void print_json_null(json_t *element, int indent);

void print_json_object(json_t *element, int indent);

int get_cumulative_bss_stats (lua_State *L,void* config);

int get_cumulative_sta_stats (lua_State *L,void* config);

int get_assoc_frame (lua_State *L,void* config);
#ifdef OPENWRT
#define MULTIAP_CONFIG "multiap"

#ifdef USE_C_API
#include <uci.h>

#define num_of_sections(x) sizeof(x)/sizeof(x[0])
typedef int (*T_uci_handler)(void* pconfig,struct uci_section *s);


int load_multiapagent_allconfig(const char* path,void*data);
int save_multiapagent_allconfig(const char* path,void*data);
int get_multiapagent_config(const char* path,void *value);
int set_multiapagent_config(const char* path,void *value);

#endif //OPENWRT
#endif //USE_C_API


#endif //PLATFORM_COMMANDS_H

#ifdef __cplusplus
}
#endif

