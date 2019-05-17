/********** COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) 2019 Technicolor                                       **
** - Connected Home Division of Technicolor Group                       **
** - Technicolor Delivery Technologies, SAS                             **
**   and/or Technicolor Connected Home USA, LLC                         **
** - All Rights Reserved                                                **
** Technicolor hereby informs you that certain portions                 **
** of this software module and/or Work are owned by Technicolor         **
** and/or its software providers.                                       **
** Distribution copying and modification of all such work are reserved  **
** to Technicolor and/or its affiliates, and are not permitted without  **
** express written authorization from Technicolor.                      **
** Technicolor is registered trademark and trade name of Technicolor,   **
** and shall not be used in any manner without express written          **
** authorization from Technicolor                                       **
*************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

#ifndef MAP_EVENTS_H
#define MAP_EVENTS_H

#include <stdint.h>

// Main thread to monitor thread IPC commands
typedef enum {
    MAP_MONITOR_MIN_CMD = 0x00,
    MAP_MONITOR_INIT_DATA_COLLECTION_CMD = 0x01,
    MAP_MONITOR_STOP_DATA_COLLECTION_CMD = 0x02,
    MAP_MONITOR_PUBLISH_SERVICES_CMD = 0x03,
    MAP_MONITOR_REGISTER_EVENTS_CMD = 0x04,
    MAP_MONITOR_MONITOR_THRESHOLD_CMD = 0x05,
    MAP_MONITOR_ADD_OBJ_CMD = 0x06,
    MAP_MONITOR_SEND_UBUS_DATA_CMD = 0x07,
    MAP_MONITOR_MAX_CMD = 0x08
} map_monitor_cmd;

// Main thread to monitor thread IPC sub commands
typedef enum {
    MAP_MONITOR_MIN_SUBCMD = 0x00,
    MAP_MONITOR_STATION_EVENTS_SUBCMD = 0x01,
    MAP_MONITOR_WIRELESS_SSID_EVENTS_SUBCMD = 0x02,
    MAP_MONITOR_RSSI_THRESHOLD_EVENTS_SUBCMD = 0x03,
    MAP_MONITOR_CHANNEL_UTILIZATION_EVENTS_SUBCMD = 0x04,
    MAP_MONITOR_BACKHAUL_METRICS_COLLECTION_SUBCMD = 0x05,
    MAP_MONITOR_AP_METRICS_COLLECTION_SUBCMD = 0x06,
    MAP_MONITOR_STATION_LINK_METRICS_COLLECTION_SUBCMD = 0x07,
    MAP_MONITOR_TOPOLOGY_QUERY_METHOD_SUBCMD = 0x08,
    MAP_MONITOR_STATION_STEER_METHOD_SUBCMD = 0x09,
    MAP_MONITOR_AP_CAPABILITY_QUERY_METHOD_SUBCMD = 0x0A,
    MAP_MONITOR_CHANNEL_PREFERENCE_QUERY_METHOD_SUBCMD = 0x0B,
    MAP_MONITOR_CHANNEL_SELECTION_REQUEST_METHOD_SUBCMD = 0x0C,
    MAP_MONITOR_WIRELESS_RADIO_EVENTS_SUBCMD = 0x0D,
    MAP_MONITOR_DUMP_CONTROLLER_INFO_SUBCMD = 0x0E,
    MAP_MONITOR_SEND_POLICY_CONFIG_METHOD_SUBCMD = 0x0F,
    MAP_MONITOR_CLIENT_CAPABILITY_QUERY_METHOD_SUBCMD = 0x10,
    MAP_MONITOR_NETWORK_LINK_EVENTS_SUBCMD = 0x11,
    MAP_MONITOR_DEBUG_AGENT_INFO_SUBCMD = 0x12,
    MAP_MONITOR_CLIENT_ACL_REQUEST_METHOD_SUBCMD = 0x13,
    MAP_MONITOR_ASSOC_STA_METRIC_QUERY_SUBCMD = 0x14,
    MAP_MONITOR_CLIENT_BEACON_METRICS_METHOD_SUBCMD = 0x15,
    MAP_MONITOR_LEGACY_STEERING_SUB_CMD = 0x16,
    MAP_MONITOR_BTM_STEERING_SUB_CMD = 0x17,
    MAP_MONITOR_OFF_BSS_SUB_CMD = 0x18,
    MAP_MONITOR_OFF_RADIO_SUB_CMD = 0x19,
    MAP_MONITOR_UNASSOC_STA_METRIC_QUERY_SUBCMD = 0x1A,
    MAP_MONITOR_UNASSOC_MEASUREMENT_REQ_METHOD_SUBCMD = 0x1B,
    MAP_MONITOR_UNASSOC_MEASUREMENT_RESPONSE_METHOD_SUBCMD = 0x1C,
    MAP_MONITOR_SET_CHANNEL_METHOD_SUBCMD = 0x1D,
    MAP_MONITOR_SEND_CHANNEL_PREF_REPORT_METHOD_SUBCMD = 0x1E,
    MAP_MONITOR_SEND_AUTOCONFIG_RENEW_SUBCMD = 0x1F,
    MAP_MONITOR_BEACON_METRIC_QUERY_SUBCMD = 0x20,
    MAP_MONITOR_LINK_METRIC_QUERY_METHOD_SUBCMD = 0x21,
    MAP_MONITOR_SEND_HIGHERLAYER_DATA_MSG_SUBCMD = 0x22,
    MAP_MONITOR_CREDENTIAL_EVENTS_SUBCMD = 0x23,
    MAP_MONITOR_SEND_STEERING_POLICY_CONFIG_METHOD_SUBCMD = 0x24,
    MAP_MONITOR_AP_METRIC_QUERY_METHOD_SUBCMD = 0x25,
    MAP_MONITOR_CHANNEL_SELECTION_REQUEST_DETAIL_SUBCMD = 0x26,
    MAP_MONITOR_UNASSOC_MEASUREMENT_FLUSH_METHOD_SUBCMD = 0x27,
    MAP_MONITOR_GET_NEIGHBOUR_LINK_MET_METHOD_SUBCMD = 0x28,
    MAP_MONITOR_COMBINED_INFRA_METRIC_QUERY_METHOD_SUBCMD = 0x29,
    MAP_MONITOR_BTM_REPORT_EVENTS_SUBCMD = 0x2A,
    MAP_MONITOR_RESPONSE_TO_CLI_SUBCMD = 0x2B,
    MAP_MONITOR_SET_TX_PWR_METHOD_SUBCMD = 0x2C,
    MAP_MONITOR_GET_TX_PWR_METHOD_SUBCMD = 0x2D,
    MAP_MONITOR_GET_CHANNEL_PREF_SUBCMD = 0x2E,
    MAP_MONITOR_SEND_STN_EVENT_SUBCMD = 0x2F,
    MAP_MONITOR_GET_TOPO_TREE_METHOD_SUBCMD = 0x30,
    MAP_MONITOR_SEND_TOPO_TREE_DATA = 0x31,
    MAP_MONITOR_MAX_SUBCMD = 0x32,
} map_monitor_subcmd;

// Below are the UBUS events/methods monitor thread listening to
// Main thread will be notified for the below events
typedef enum {
    MAP_MONITOR_RSSI_THRESHOLD_EVT,
    MAP_MONITOR_STATION_EVT,
    MAP_MONITOR_WIRELESS_SSID_EVT,
    MAP_MONITOR_CREDENTIAL_EVT,
    MAP_MONITOR_WIRELESS_RADIO_CHANNEL_EVT,
    MAP_MONITOR_CHANNEL_UTL_THRESHOLD_EVT,
    MAP_MONITOR_STEER_CALL,
    MAP_MONITOR_SEND_TOPOLOGY_QUERY_CALL,
    MAP_MONITOR_SEND_POLICY_CONFIG_CALL,
    MAP_MONITOR_SEND_AP_CAPABILITY_QUERY,
    MAP_MONITOR_SEND_CLIENT_CAPABILITY_QUERY,
    MAP_MONITOR_SEND_CHANNEL_PREFERENCE_QUERY_CALL,
    MAP_MONITOR_SEND_CHANNEL_SELECTION_REQUEST_CALL,
    MAP_MONITOR_SEND_STEER_POLICY_CONFIG_CALL,
    MAP_MONITOR_DUMP_CONTROLLER_INFO,
    MAP_MONITOR_WIRED_LINK_EVENT,
    MAP_MONITOR_WIRELESS_SSID_RADIO_EVT,
    MAP_MONITOR_SEND_CLIENT_ACL_REQUEST,
    MAP_MONITOR_DEBUG_AGENT_INFO,
    MAP_MONITOR_CUMULATIVE_BSS_STATS,
    MAP_MONITOR_CUMULATIVE_STA_STATS,
    MAP_MONITOR_SEND_ASSOC_STA_METRIC_QUERY,
    MAP_MONITOR_BEACON_METRICS_REPORT_EVT,
    MAP_MONITOR_SEND_UNASSOC_STA_METRICS_QUERY,
    MAP_MONITOR_BTM_REPORT_EVT,
    MAP_MONITOR_SEND_UNASSOC_STA_METRICS_RESPONSE,
    MAP_MONITOR_SEND_TOPOLOGY_QUERY,
    MAP_MONITOR_SEND_CHANNEL_PREF_REPORT,
    MAP_MONITOR_SEND_AUTOCONFIG_RENEW,
    MAP_MONITOR_BEACON_QUERY_CALL,
    MAP_MONITOR_SEND_LINK_METRIC_QUERY,
    MAP_MONITOR_HIGHLAYER_DATA_EVENT,
    MAP_MONITOR_SEND_AP_METRIC_QUERY,
    MAP_MONITOR_SEND_CHANNEL_SEL_REQ_DETAIL,
    MAP_MONITOR_LINK_METRICS_REPORT,
    MAP_MONITOR_SEND_COMBINED_INFRA_METRICS,
    MAP_MONITOR_TX_PWR_CHANGE_REPORT,
    MAP_MONITOR_SEND_CHANNEL_PREF,
    MAP_MONITOR_DUMP_TOPO_TREE,
    MAP_LAST_EVENT,
} map_monitor_event;

/* Event priority to decide which IPC medium to send event to main thread */
typedef enum
{
    MAP_HIGH_PRIORITY_EVENT    = 0x01,
    MAP_NORMAL_PRIORITY_EVENT  = 0x02
} event_priority_t;

/* Events published by MAP */
typedef enum
{
    PUBLISH_STN_DISCONNECT_EVT  = 0x00,
    PUBLISH_STN_CONNECT_EVT     = 0x01
} map_publish_event_t;

/* Data structure for passing event to main thread */
typedef struct map_event {
    uint8_t evt;
    uint8_t async_status_response;
    void    *evt_data;
} map_monitor_evt_t;

/* Data structure for passing event to monitor thread */
typedef struct _map_monitor_cmd_t {
    map_monitor_cmd cmd;
    map_monitor_subcmd subcmd;
    void* param;
} map_monitor_cmd_t;

/** @brief This API will identify the given event 
 * is of high or normal priority
 *
 *  @param : event id
 *  @return: Event priority (MAP_HIGH_PRIORITY_EVENT/MAP_NORMAL_PRIORITY_EVENT)
 */
uint8_t map_get_event_priority(uint8_t map_event);

/** @brief Validates the event ID range
 *
 *  @param : event (map_monitor_evt_t)
 *  @return: True - Valid event, False - Invalid events
 */
static inline uint8_t is_valid_ipc_event(map_monitor_evt_t *event) {
    if(event && (event->evt >= 0) && (event->evt < MAP_LAST_EVENT))
        return 1;
    return 0;
}

#endif

#ifdef __cplusplus
}
#endif
