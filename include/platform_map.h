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

#ifndef PLATFORM_MAP_H
#define PLATFORM_MAP_H

#include "platform_utils.h"
#include "platform_lua.h"
#include "platform_commands.h"
#include "map_data_model.h"
#include <syslog.h>
#include "map_common_defines.h"
#include <uv.h>
#include "map_events.h"

#define set_loglevel(x) (x&0xFFFF)

#define al_entity_env_interfaces getenv("AL_ENTITY_INTERFACES") // getenv() returns char*
#define al_entity_topology_discovery_env_interval getenv("AL_ENTITY_TOPOLOGY_DISCOVERY_INTERVAL")

#define map_library_log_level getenv("MAP_LIB_LOG_LEVEL")
#define map_1905_log_level getenv("MAP_1905_LOG_LEVEL")
#define map_agent_log_level getenv("MAP_AGENT_LOG_LEVEL")
#define map_controller_log_level getenv("MAP_CONTROLLER_LOG_LEVEL")
#define map_vendor_ipc_log_level getenv("MAP_VENDOR_IPC_LOG_LEVEL")

#define map_agent_env_enabled getenv("MAP_AGENT_ENABLED")
#define map_agent_env_macaddress getenv("MAP_AGENT_MACADDRESS")
#define map_agent_frontahul_list getenv("MAP_AGENT_FRONTHAUL_LIST")
#define map_agent_backhaul_list getenv("MAP_AGENT_BACKHAUL_LIST")
#define map_agent_env_hidden_backhaul getenv("MAP_AGENT_HIDDEN_BACKHAUL")

#define map_controller_env_enabled getenv("MAP_CONTROLLER_ENABLED")
#define map_controller_env_macaddress getenv("MAP_CONTROLLER_MACADDRESS")
#define map_controller_env_fronthaul_bss_ssid getenv("MAP_CONTROLLER_FRONTHAUL_BSS_SSID")
#define map_controller_env_fronthaul_bss_security_modes getenv("MAP_CONTROLLER_FRONTHAUL_BSS_SECURITY_MODES")
#define map_controller_env_fronthaul_interface getenv("MAP_CONTROLLER_FRONTHAUL_INTERFACE")
#define map_controller_env_backhaul_bss_ssid getenv("MAP_CONTROLLER_BACKHAUL_BSS_SSID")
#define map_controller_env_backhaul_bss_security_modes getenv("MAP_CONTROLLER_BACKHAUL_BSS_SECURITY_MODES")
#define map_controller_env_backhaul_interface getenv("MAP_CONTROLLER_BACKHAUL_INTERFACE")
#define map_controller_env_preferred_bh_iface getenv("MAP_CONTROLLER_PREFERRED_BH_IFACE")
#define map_controller_env_freq_2_4_ghz getenv("MAP_CONTROLLER_FREQ_2_4_GHZ")
#define map_controller_env_freq_5_ghz getenv("MAP_CONTROLLER_FREQ_5_GHZ")
#define map_controller_env_freq_60_ghz getenv("MAP_CONTROLLER_FREQ_60_GHZ")
#define map_controller_env_mgmt_ipc_report_interval getenv("MGMT_IPC_REPORT_INTERVAL")
#define map_controller_env_link_metric_query_interval getenv("MAP_CONTROLLER_LINK_METRIC_QUERY_INTERVAL")
#define map_controller_env_topology_query_interval getenv("MAP_CONTROLLER_TOPOLOGY_QUERY_INTERVAL")
#define map_controller_env_channel_selection_enabled getenv("MAP_CONTROLLER_CHANNEL_SELECTION_ENABLED")
#define map_controller_env_dead_agent_detection_interval getenv("MAP_CONTROLLER_DEAD_AGENT_DETECTION_INTERVAL")
#define map_controller_env_configure_BH_STA getenv("MAP_CONTROLLER_CONFIGURE_BH_STA")

#define LIB_1905_NEW_IF_CREATED_EVENT		(0x01)
#define LIB_1905_IF_UP_EVENT				(0x02)
#define LIB_1905_IF_DOWN_EVENT				(0x03)

#define MAX_NUM_CREDETIALS 10
#define map_env_num_credentials getenv(MAP_NUM_CREDENTIALS)


typedef enum _logiface{
        log_syslog=0,
        log_stdout,
        log_socket
}logiface;

typedef enum _radio_type{
        IEEE80211_FREQUENCY_BAND_2_4_GHZ = 0x00,
        IEEE80211_FREQUENCY_BAND_5_GHZ   = 0x01,
        IEEE80211_FREQUENCY_BAND_60_GHZ  = 0x02,
    max_freq_type
}radio_type;

typedef enum _relay_indicator{
         RELAY_INDICATOR_OFF = 0,
         RELAY_INDICATOR_ON = 1
} relay_indicator_t;

typedef enum _interface_state {
        INTERFACE_STATE_UP   = 0,
        INTERFACE_STATE_DOWN = 1
} interface_state;

typedef union _multiapd_options{
    struct{
        uint32_t is_mgmt_ubus:1;
        uint32_t is_mgmt_sock:1;
        uint32_t is_controller_avail:1;
        uint32_t reserved:29;
    };
    uint32_t mapd_options;
}mapd_opts;

/*
 * Data structure for queue implementation across
 *  monitor thread and multiap agent.
 * 
 */

typedef struct map_bss_stats_s {
    uint8_t             bssid[MAC_ADDR_LEN];
    map_ap_metric_t     metrics;
} map_bss_stats_t;

typedef struct map_sta_stats_s {
    uint8_t         bssid[MAC_ADDR_LEN];
    uint8_t         mac[MAC_ADDR_LEN];   
    map_sta_metrics_t   metrics;
}map_sta_stats_t;

typedef struct cum_stats_s {
    uint8_t                 obj_type;
    struct timespec         measurement_time;       // Time at which the measurement was done;
    uint8_t                 inuse;
    uint8_t                 stats_count;
    void                    *cum_stats;
} cum_stats_t;

typedef struct cum_measurement_report_s {
    uint8_t       event_type;
    uint8_t       enable_ubus_resp;
    uint8_t       sta_mac[MAC_ADDR_LEN];
    uint8_t       num_of_reports;
    map_beacon_report_element_t beacon_report[1];  // This shall be expanded from 0 to num_of_reports;^M
} cum_measurement_report_t;

typedef struct platform_channel_pref_cmd {
    uint8_t           event_type;
    uint8_t           radio_type;
    char              radio_name[MAX_RADIO_NAME_LEN];
    uint8_t           op_class_count;
    map_op_class_t    op_class_list[1];
} platform_channel_pref_cmd_t;

struct unassoc_radio_info {
        char    radio_name[MAX_RADIO_NAME_LEN];
        uint16_t pending_count;
};

struct unassoc_metrics_info {
    struct  timespec last_query_time;
    uint8_t dst_mac[MAC_ADDR_LEN];
    char dst_iface[MAX_IFACE_NAME_LEN];
    uint8_t oper_class;
};

struct unassoc_platform_cmd {
    char     radio_name[MAX_RADIO_NAME_LEN];
    uint8_t  bw;
    uint16_t cnt;
	struct measurement_list {
	    uint8_t channel;
            uint8_t mac[MAC_ADDR_LEN];
	} list[1];
};

typedef struct stn_event_platform_cmd_s {    
    map_publish_event_t event;
    int8_t sta[MAX_MAC_STRING_LEN];
    int8_t bssid[MAX_MAC_STRING_LEN];
} stn_event_platform_cmd_t;

struct unassoc_response {
	uint8_t type;
	char    radio_name[MAX_RADIO_NAME_LEN];
	uint8_t oper_class;
	uint8_t sta_cnt;
	struct unassoc_report_list {
		uint8_t sta_mac[MAC_ADDR_LEN];
		uint8_t channel;
		uint32_t age;
		uint8_t ulrcpi;
	} list[1];
};

typedef struct acl_timeout_data {
    uint16_t mid;
    struct timespec msg_recvd_time;
    uint16_t validity_period;
    uint8_t bssid[MAC_ADDR_LEN];
    array_list_t *sta_list;
}acl_timeout_data_t;

typedef struct monitor_q_handle_s {
    array_list_t     *list_handle;
} monitor_q_handle_t;
//monitor queue data structure

typedef enum bh_interface_type_e {
    MAP_BH_PREFERENCE_ETHER,
    MAP_BH_PREFERENCE_2_4GHz,
    MAP_BH_PREFERENCE_5GHz,
    MAP_BH_PREFERENCE_AUTO
}bh_interface_type_t;

typedef struct config_credential_s{
    char bss_ssid[MAX_WIFI_SSID_LEN];
    char wpa_key[MAX_WIFI_PASSWORD_LEN];
    uint16_t supported_auth_modes;
    uint16_t supported_encryption_types;
    uint16_t bss_freq_bands;
    uint8_t bss_state;
}config_credential_t;

typedef struct _map_cfg{
    unsigned int        enabled;
    mapd_opts           multiap_opts;
    unsigned int        map_num_credentials;
    config_credential_t credential_config[MAX_NUM_CREDETIALS];
    bh_interface_type_t preferred_bh_iface;
    unsigned int        supportedfreq[max_freq_type];
    struct timespec     last_ap_metrics_time;
    array_list_t        *client_acl_list;
    uv_timer_t          periodic_timer;
    monitor_q_handle_t  monitor_q_hdle;
    int default_hysteresis_margin;
    char* version;
}map_cfg;

typedef struct _platformconfig{
    unsigned int init_completed;
    logiface log_output;
    unsigned int log_level;
    int logfile_fd;
    int al_fd;
    const char* config_file;
    const char* mgmt_sock_name;
    map_cfg map_config;
}plfrm_config;

typedef struct _map_policy_config_t {
    uint8_t metrics_report_interval;
    uint8_t sta_metrics_rssi_threshold_dbm;
    uint8_t sta_metrics_rssi_hysteresis_margin;
    uint8_t ap_metrics_channel_utilization_threshold_dbm;
    uint8_t sta_link_sta_traffic_stats;
} map_policy_config_t;

enum map_m2_bss_freq_band {
    MAP_M2_BSS_RADIO2G  = 0x10,
    MAP_M2_BSS_RADIO5GU = 0x20,
    MAP_M2_BSS_RADIO5GL = 0x40,
};

/* Input params: iface_name
                 state - MAP_M2_BSS_BACKHAUL or MAP_M2_BSS_FRONTHAUL

   Output params: ssid
                  state - MAP_M2_BSS_CONFIGURED
*/
typedef struct {
    char iface_name[MAX_IFACE_NAME_LEN];
    uint8_t bssid[MAC_ADDR_LEN];
    /* State is bit-map entity
     * x | x | x | x |   | x | MAP_M2_BSS_CONFIGURED | MAP_M2_BSS_BACKHAUL | MAP_M2_BSS_FRONTHAUL
     */
    uint16_t state;
    char ssid[MAX_SSID_LEN];
    char *supported_security_modes;
} map_iface_info;

typedef struct {
    int iface_count;
    map_iface_info iface_list[MAX_BSS_PER_RADIO];
} wsc_m2_data;

/*
 * @brief This structure is a sta node entry in global list of beacon metrics
 *        report
 */
typedef struct bcn_rprt_timeout_data {
    uint8_t evt;
    uint8_t sta_mac[MAC_ADDR_LEN];
    array_list_t    *bcon_rprt_list;
}bcn_rprt_timeout_data_t;

void platform_log(int module,int level,const char *format,...);

int platform_config_load(unsigned int cmd,plfrm_config * config); 

int daemonize(plfrm_config * config);

int platform_get(unsigned int command,const char* subcmd,void* data);

int platform_set(unsigned int command,void* data);

/* Extensions of platform_get/set with additional context.
This context can be used to send the UBUS context and similarly for DBUS*/
int platform_get_context(unsigned int command,const char* subcmd,void* data, void *ctxt);

int platform_set_context(unsigned int command,void* data, void *ctxt);

uint8_t map_pltfrm_send_gathered_beacon_metric_report(uint8_t * sta_mac);
uint8_t add_sta_to_bcon_pend_list(uint8_t *sta_mac);

#ifndef OPENWRT

static void signal_handler(unsigned int sn, siginfo_t si, struct ucontext *sc);
static void print_stack(unsigned int sn, siginfo_t si, struct ucontext *sc);
static void handle_sigterm(unsigned int sn, siginfo_t si, struct ucontext *sc);
int init_signal_handling();

#endif


#endif

#ifdef __cplusplus
}
#endif

