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

#ifndef MON_PLATFORM_H
#define MON_PLATFORM_H

#include <stdlib.h>                             /* For function exit() */
#include <stdio.h>                              /* For input/output */
#include <syslog.h>
#include <stdbool.h>
#include "platform_map.h"
#include "map_events.h"

#define RADIO_NAME_LEN 16
#define WORD_ALIGN 4
#define MAX_STATUS_LEN 5
#define MAX_BSSID_PER_AP_METRICS_QUERY 32

/* Event mapping strings */
#define WIRELESS_SSID_EVENT_STR		"wireless.ssid"
#define MULTIAP_CREDENTIAL_EVENT_STR   "multiap.controller_credentials"
#define WIRELESS_STA_EVENT_STR		"wireless.accesspoint.station"
#define WIRELESS_RADIO_EVENT_STR	"wireless.radio"
#define NETWORK_LINK_EVENT_STR		"network.link"
#define WIRELESS_BEACON_METRICS_EVENT   "wireless.accesspoint.station.beacon_report"
#define WIRELESS_UNASSOC_METRICS_OBJ_STR   "wireless.radio.monitor.station"
#define WIRELESS_BTM_REPORT_EVENT_STR   "wireless.accesspoint.station.btm_report"

/* cli mapping strings */
#define SEND_STA_STEER_METHOD_STR		"sendClientSteerReq"
#define SEND_TOPOLOGY_QUERY_METHOD_STR		"sendtopoquery"
#define SEND_CAPABILITY_QUERY_METHOD_STR	"sendAPcapabilityquery"
#define SEND_CLNT_CAPABILITY_QUERY_METHOD_STR	"sendClientcapabilityquery"
#define SEND_CHANNEL_PREF_QURY_METHOD_STR	"sendchannelprefquery"
#define SEND_CHANNEL_SEL_REQ_METHOD_STR		"sendchannelselectionreq"
#define SEND_CHANNEL_SEL_REQ_METHOD_DETAIL_STR		"sendchannelselectionreq_detail"
#define SEND_DUMP_CTRL_INFO_METHOD_STR		"dumpctrlinfo"
#define SEND_POLICY_CONFIG_METHOD_STR		"sendpolicyconfig"
#define SEND_STEER_POLICY_CONFIG_METHOD_STR		"sendsteerpolicyconfig"
#define SEND_DEBUG_AGENT_INFO_METHOD_STR		"debugagentinfo"
#define SEND_CLIENT_ACL_REQUEST_METHOD_STR      "sendCliAssocCtrlRequest"
#define SEND_ASSOC_STA_METRIC_QUERY_METHOD_STR  "sendAssocStaMetricQuery"
#define SEND_UNASSOC_STA_METRIC_QUERY_METHOD_STR  "sendUnAssocStaMetricQuery"
#define SEND_CHANNEL_PREF_REPORT_METHOD_STR      "sendChanPrefReport"
#define SEND_AUTOCONFIG_RENEW_METHOD_STR    "sendrenewmsg"
#define SEND_BEACON_METRIC_QUERY_METHOD_STR  "sendBeaconMetricQuery"
#define SEND_LINK_METRIC_QUERY_METHOD_STR    "sendLinkMetricquery"
#define SEND_HIGHLAYER_DATA_MSG_METHOD_STR   "hld"
#define SEND_AP_METRIC_QUERY_METHOD_STR      "apmetricsquery"
#define SEND_COMBINED_INFRA_METRIC_QUERY_METHOD_STR      "SendCombinedInfra"
#define DUMP_TOPO_TREE_METHOD_STR      "dumpMapNetwork"


/* Enum to identify the instance context */
enum MAP_MONITOR_MASTER{
	MAP_MONITOR_AGENT = 0,
	MAP_MONITOR_CONTROLLER = 1
};

enum {
        MAP_LINK_METRIC_QUERY_TLV_ALL_NEIGHBORS,
        MAP_LINK_METRIC_QUERY_TLV_SPECIFIC_NEIGHBOR
};

enum {
        MAP_TX_LINK_METRICS_ONLY,
        MAP_RX_LINK_METRICS_ONLY,
        MAP_BOTH_TX_AND_RX_LINK_METRICS
};

#define WDS_IF_NAME_PREFIX	"wds"
typedef struct _map_network_link_evt_data {
  char if_name[MAX_IFACE_NAME_LEN];
  char status[MAX_STATUS_LEN];
} map_network_link_evt_data;

/* Station event data structure, passed from platform layer to main thread */
typedef struct _stn_event_t {
	uint8_t mac_addr[MAC_ADDR_LEN];
	uint8_t bssid[MAC_ADDR_LEN];
	uint8_t association_event;
        uint16_t assoc_frame_len;
        uint8_t *assoc_frame;
} stn_event_t;

/* SSID change event data structure, passed from platform layer to main thread */
typedef struct _ssid_event_t {
        uint8_t ssid[MAX_WIFI_SSID_LEN + WORD_ALIGN]; //extra space for null character but need to word allign, cant add 1
        uint8_t network_key[MAX_WIFI_PASSWORD_LEN + WORD_ALIGN]; //extra space for null character but need to word allign, cant add 1
        uint8_t freq_band;
        uint8_t interface;
        char auth_type[MAX_AUTH_TYPE_LEN];
        char if_name[MAX_IFACE_NAME_LEN];
} ssid_event_t;

/* Radio channel change event data structure, passed from platform layer to main thread */
typedef struct _radio_channel_event_t {
	uint8_t radio_id[MAC_ADDR_LEN];
	uint8_t channel;
    uint8_t bandwidth;
    uint8_t op_class;
    uint8_t current_tx_pwr;
} radio_channel_event_t;

/* BTM steering report event data structure, passed from monitor task to agent */
typedef struct _btm_report_event_t {
	uint8_t stn_mac_addr[MAC_ADDR_LEN];
	uint8_t current_bssid[MAC_ADDR_LEN];
	uint8_t target_bssid[MAC_ADDR_LEN];
	uint8_t btm_status;
} btm_report_event_t;

/* Channel preference command datastructure from cli to main thread */
typedef struct chnl_pref_command_s
{
	uint8_t agent_mac_addr[MAC_ADDR_LEN];
	uint8_t radio_id[MAC_ADDR_LEN];
	uint8_t op_class;
	uint8_t channel1;
	uint8_t channel2;
	uint8_t pref;
} chnl_pref_command_t;

typedef struct _radio_steer_policy_t
{  
  uint8_t steering_policy;
  uint8_t chnlutil_threshold;
  uint8_t rcpi_threshold;
  uint8_t radio_mac[MAC_ADDR_LEN];
} radio_steer_policy_t;

/* Policy config command datastructure from cli to main thread */
typedef struct _map_steering_policy_config_cmd_t
{
	uint8_t btm_disalllowed_sta_cnt;
	uint8_t local_disalllowed_sta_cnt;
	uint8_t radio_count;
	uint8_t (*btm_disalllowed_sta_list)[MAC_ADDR_LEN];
	uint8_t (*local_disallowed_sta_list)[MAC_ADDR_LEN];
	uint8_t al_mac[MAC_ADDR_LEN];
	radio_steer_policy_t radio_list[MAX_RADIOS_PER_AGENT];
} map_steering_policy_config_cmd_t;

typedef struct _map_policy_config_cmd_t
{
	uint8_t radio_count;
	uint8_t station_count;
	uint8_t radio_mac[MAX_RADIOS_PER_AGENT][MAC_ADDR_LEN];
	uint8_t sta_mac[MAX_STATIONS][MAC_ADDR_LEN];
	uint8_t dst_mac[MAC_ADDR_LEN];
} map_policy_config_cmd_t;

typedef struct _map_monitor_client_info {
        uint8_t client_mac[MAC_ADDR_LEN];
        uint8_t bssid[MAC_ADDR_LEN];
        uint8_t agent_mac[MAC_ADDR_LEN];
} client_info_t;

typedef struct _map_higher_layer_data_info {
        uint8_t protocol;
        uint8_t *payload_pattern;
        uint16_t repeat_cnt;
        uint16_t payload_len;
        uint8_t dest_mac[MAC_ADDR_LEN];
}higherlayer_info_t;

typedef struct _map_monitor_ssid_radio_state {
       char if_name[MAX_IFACE_NAME_LEN];
       uint16_t radio_state;
       uint16_t bss_state;
} ssid_radio_state_t;

#define MAX_CLI_ASYNC_STATUS_LEN 64

typedef struct map_cli_async_response_s
{
    char     status[MAX_CLI_ASYNC_STATUS_LEN];
    uint16_t msg_type;
    uint16_t mid;
} map_cli_async_resp_t; 

typedef struct _station_list_s {
        uint8_t sta_mac[MAC_ADDR_LEN];
} station_list_t;

typedef struct _client_acl_data {
        uint8_t al_mac[MAC_ADDR_LEN];
        uint8_t bssid[MAC_ADDR_LEN];
        uint8_t block;
        uint16_t validity_period;
        uint8_t sta_count;
        station_list_t sta_list[]; /* Allocate based on the sta count */
}client_acl_data_t;

typedef struct platform_cmd_channel_set_s {
    uint8_t channel;
    char    radio_name[MAX_WIFI_RADIO_NAME_LEN];
} platform_cmd_channel_set_t;


typedef struct platform_cmd_tx_pwr_set_s {
    uint8_t type;
    uint8_t current_tx_pwr;
    uint8_t new_tx_pwr;
    char    radio_name[MAX_WIFI_RADIO_NAME_LEN];
} platform_cmd_tx_pwr_set_t;


struct ap_channel_report {
    uint8_t         length;
    uint8_t         operating_class;
    uint8_t         channel_list[MAX_TOTAL_CHANNELS];
};

typedef struct beacon_metrics_query {
    uint8_t send_iface[MAX_IFACE_NAME_LEN];
    uint8_t dst_mac[MAC_ADDR_LEN];
    uint8_t state;
    struct  timespec last_query_time;
    uint8_t sta_mac[MAC_ADDR_LEN];
    uint8_t bssid[MAC_ADDR_LEN];
    uint8_t channel;
    uint8_t report_detail;
    uint8_t operating_class;
    uint8_t ssid_len;
    uint8_t ssid[MAX_SSID_LEN];
    uint8_t element_id_count;                     /* This holds additional elements other than measurement report */
    uint8_t elementIds[MAX_ELEMENTID];
    uint8_t ap_channel_report_count;
    struct ap_channel_report  ap_channel_report[1];            /* This wil be available only when channel== 255, and dynamic grow */
}beacon_metrics_query_t;

typedef struct link_metric_query {
    uint8_t al_mac[MAC_ADDR_LEN];
    uint8_t neighbor_mac[MAC_ADDR_LEN];
    uint8_t specific_neighbor;
    uint8_t metric_req;
}link_metric_query_t;

typedef struct _mac_struct_s {
        uint8_t mac[MAC_ADDR_LEN];
} mac_struct_t;

typedef struct ap_metric_query {
    uint8_t al_mac[MAC_ADDR_LEN];
    uint8_t bss_cnt;
    mac_struct_t bss_list[0]; /* Allocate based on the bss count */
}ap_metric_query_t;

struct sta_params {
        uint8_t  bssid[MAC_ADDR_LEN];
        uint8_t  channel;
        uint8_t  operating_class;
        uint8_t  sta_mac[MAC_ADDR_LEN];
};

struct sta_steer_params {
    uint8_t  dst_mac[MAC_ADDR_LEN];
    uint8_t  source_bssid[MAC_ADDR_LEN];
    char     ap_name[MAX_IFACE_NAME_LEN];
    uint16_t disassociation_timer;
    uint16_t opportunity_wnd;
	uint8_t  flag;
    uint8_t  abridged_mode;
    uint8_t  disassoc_imminent;
    uint8_t  sta_count;
    uint8_t  bssid_count;
    struct sta_params sta_info[1];
};

struct unassoc_sta_dm_s {
    uint8_t type;
    uint8_t async_status_response;
    uint8_t al_mac[MAC_ADDR_LEN];
    uint8_t oper_class;
    uint8_t channel_list_cnt;
    struct sta_mac_channel_list {
        uint8_t channel;
        uint8_t sta_count;
        uint8_t (*sta_mac)[MAC_ADDR_LEN];
    } sta_list[MAX_CHANNEL_IN_OPERATING_CLASS];
};

typedef struct channel_preference_report {
    uint8_t type;
    uint8_t async_status_response; 
    uint8_t al_mac[MAC_ADDR_LEN];
    uint8_t radio_id[MAC_ADDR_LEN];
    uint8_t numOperating_class;
    uint8_t txpower;
    struct op_class_channel_list {
        uint8_t operating_class;
        uint8_t number_of_channels;
        uint8_t channel_num[MAX_CHANNEL_IN_OPERATING_CLASS];
        uint8_t pref_reason;
    }operating_class[1];
}channel_report_t ;


typedef struct neighbour_link_met_platform_cmd {
    uint8_t    dst_mac[MAC_ADDR_LEN];
    char       dst_iface_name[MAX_IFACE_NAME_LEN];
    uint16_t   mid;
    uint8_t    neighbour_entry_nr;
    uint8_t    request_type;
    struct     neighbour_entry {
        uint8_t  local_almac[MAC_ADDR_LEN];
        uint8_t  neighbour_almac[MAC_ADDR_LEN];
        uint8_t  local_iface_mac[MAC_ADDR_LEN];
        uint8_t  neighbour_iface_mac[MAC_ADDR_LEN];
        char     interface_name[MAX_IFACE_NAME_LEN];
        uint16_t  iface_type;
    } neighbour_list[1];
} neighbour_link_met_platform_cmd_t;


struct neighbour_link_met_response {
    uint8_t   type;
    uint8_t   dst_mac[MAC_ADDR_LEN];
    char      dst_iface_name[MAX_IFACE_NAME_LEN];
    uint16_t   mid;

    uint16_t  tlvs_cnt;
    uint8_t   *list_of_tlvs[1];
};


struct _txLinkMetricEntries
{
    uint8_t   local_interface_address[MAC_ADDR_LEN];      // MAC address of an interface in
                                             // the receiving AL, which connects
                                             // to an interface in the neighbor
                                             // AL

    uint8_t   neighbor_interface_address[MAC_ADDR_LEN];   // MAC addres of an interface in a
                                             // neighbor AL, which connects to
                                             // an interface in the receiving
                                             // AL

    uint16_t  intf_type;                // Underlaying network technology
                                      // One of the MEDIA_TYPE_* values.

    uint8_t   bridge_flag;              // Indicates whether or not the 1905 link
                                      // includes one or more IEEE 802.11
                                      // bridges

    uint32_t  packet_errors;            // Estimated number of lost packets on the
                                      // transmitting side of the link during
                                      // the measurement period (5 seconds??)

    uint32_t  transmitted_packets;      // Estimated number of packets transmitted
                                      // on the same measurement period used to
                                      // estimate 'packet_errors'

    uint16_t  mac_throughput_capacity;  // The maximum MAC throughput of the link
                                      // estimated at the transmitter and
                                      // expressed in Mb/s

    uint16_t  link_availability;        // The estimated average percentage of
                                      // time that the link is available for
                                      // data transmissions

    uint16_t  phy_rate;                 // This value is the PHY rate estimated at
                                      // the transmitter of the link expressed
                                      // in Mb/s
};


struct txLinkMetricTLV
{
    uint8_t  tlv_type;               // Must always be set to
                                   // TLV_TYPE_TRANSMITTER_LINK_METRIC

    uint8_t  local_al_address[MAC_ADDR_LEN];    // AL MAC address of the device that
                                   // transmits the response message that
                                   // contains this TLV

    uint8_t  neighbor_al_address[MAC_ADDR_LEN]; // AL MAC address of the neighbor whose
                                   // link metric is reported in this TLV

    uint8_t                       transmitter_link_metrics_nr;
    struct _txLinkMetricEntries   *transmitter_link_metrics;
                                   // Link metric information for the above
                                   // interface pair between the receiving AL
                                   // and the neighbor AL
};


struct  _rxLinkMetricEntries
{
    uint8_t   local_interface_address[MAC_ADDR_LEN];      // MAC address of an interface in
                                             // the receiving AL, which connects
                                             // to an interface in the neighbor
                                             // AL

    uint8_t   neighbor_interface_address[MAC_ADDR_LEN];   // MAC addres of an interface in a
                                             // neighbor AL, which connects to
                                             // an interface in the receiving
                                             // AL

    uint16_t  intf_type;                // Underlaying network technology

    uint32_t  packet_errors;            // Estimated number of lost packets on the
                                      // receiving side of the link during
                                      // the measurement period (5 seconds??)

    uint32_t  packets_received;         // Estimated number of packets received on
                                      // the same measurement period used to
                                      // estimate 'packet_errors'

    uint8_t  rssi;                      // This value is the estimated RSSI at the
                                      // receive side of the link expressed in
                                      // dB
};

struct rxLinkMetricTLV
{

    uint8_t   tlv_type;              // Must always be set to
                                   // TLV_TYPE_RECEIVER_LINK_METRIC

    uint8_t local_al_address[MAC_ADDR_LEN];     // AL MAC address of the device that
                                   // transmits the response message that
                                   // contains this TLV

    uint8_t neighbor_al_address[MAC_ADDR_LEN];  // AL MAC address of the neighbor whose
                                   // link metric is reported in this TLV

    uint8_t                         receiver_link_metrics_nr;
    struct _rxLinkMetricEntries     *receiver_link_metrics;
                                   // Link metric information for the above
                                   // interface pair between the receiving AL
                                   // and the neighbor AL
   
};



/** @brief This is an API to connect to UBUS.
 *
 *  This generic API will be called by monitor thread when it
 *  needs to establish a new connection to UBUS.
 *
 *  @param path
 *  @param event_mechanism event mechanism to notify main thread
 *	@param is_controller - controller/agent context
 *  @return IPC context pointer as void
 */
void * mon_platform_connect(const char *path, void *event_mechanism, bool is_controller, void** rpc_ctx);

/** @brief This is an API to register an event to the platform bus/rpc mechanism.
 *
 *  This generic API will be called by monitor thread when it
 *  needs to register any event.
 *
 *  @param ctx - platform context
 *  @param type - pattern which specifies the event
 *  @return int
 */
int mon_platform_register_event(void *ctx, const char *type);

/** @brief This is an API to register an method of the UBUS object (controller/agent).
 *
 *  This generic API will be called by monitor thread when it
 *  needs to register a method. The objects and the methods supported are static.
 *  BUt the monitor thread can use it to register callbacks for the supported methods
 *
 *  @param ctx - platform context
 *  @param method - pattern which specifies method name like "steer"
 *  @return int
 */
int mon_platform_register_method(void *ctx, const char *method);

/** @brief This is an API to free the UBUS connection.
 *
 *  This generic API will be called by monitor thread when it
 *  needs to free the existing rpc/bus connection.
 *
 *  @param ctx - platform context
 *  @return void
 */
void mon_platform_shutdown(void *ctx);

int map_async_cli_completion_cb(void *ctx, map_cli_async_resp_t *resp);

int map_send_async_ubus_response(void *ctx, void *resp);

uint8_t decr_unassoc_pending_cnt(char *radio_name);

#endif

#ifdef __cplusplus
}
#endif

