/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

#include <libubus.h>
#include "mon_platform.h"
#include "platform_utils.h"
#include "platform_commands.h"
#include "platform_lib_capi.h"
#include "map_ipc_event_publisher.h"
#include "platform_multiap_get_info.h"

#define UBUS_REGISTERED (0x01)
#define UBUS_CMD_CALLOC(type,num) (type *) calloc((num),sizeof(type))

#define MAX_ELEMENTS_IN_JSON_ARRAY 32 

typedef struct _platform_homeware_ctx {
	bool is_controller;
        void *monitor_q_hdle;
	struct ubus_context *ubus_ctx;
        bool   cli_pending_response;
        struct ubus_request_data ubus_response;
} platform_homeware_ctx_t;

static platform_homeware_ctx_t *plt_hmwr_ctx;

/* Status values */
enum platform_ubus_status {
	PLATFORM_UBUS_STATUS_OK = 0,
	PLATFORM_UBUS_STATUS_ERROR = -0x1000,
	PLATFORM_UBUS_STATUS_INVALID_ARGUMENT = -0x1001
};

typedef enum {
    STATION_STATE_UNKNOWN = -1,
    STATION_STATE_DISCONNECTED = 0,
    STATION_STATE_ASSOCIATED = 1,
    STATION_STATE_CHANGED = 2,
    STATION_STATE_AUTHORIZED = 3
} station_state_t;

/* structures for ubus event/cli parameter data parsing */
enum {
	MAP_CTRL_STEERING_POLICY_AL_MAC,
	MAP_CTRL_STEERING_POLICY_BTM_DISALLOW_COUNT,
	MAP_CTRL_STEERING_POLICY_LOCAL_DISALLOW_COUNT,
	MAP_CTRL_STEERING_POLICY_RADIO_COUNT,
	MAP_CTRL_STEERING_POLICY_RADIO_LIST,
	MAP_CTRL_STEERING_POLICY_BTM_DISALLOW_LIST,
	MAP_CTRL_STEERING_POLICY_LOCAL_DISALLOW_LIST,
	MAP_CTRL_STEERING_POLICY_MAX
};

static struct blobmsg_policy send_steer_policy_config_policy[MAP_CTRL_STEERING_POLICY_MAX] = {
	[MAP_CTRL_STEERING_POLICY_AL_MAC] = { .name = "almac", .type = BLOBMSG_TYPE_STRING },
	[MAP_CTRL_STEERING_POLICY_BTM_DISALLOW_COUNT] = { .name = "btmdisallowstacnt", .type = BLOBMSG_TYPE_INT32 },
	[MAP_CTRL_STEERING_POLICY_LOCAL_DISALLOW_COUNT] = { .name = "localdisallowstacnt", .type = BLOBMSG_TYPE_INT32 },
	[MAP_CTRL_STEERING_POLICY_RADIO_COUNT] = { .name = "radiocnt", .type = BLOBMSG_TYPE_INT32 },
	[MAP_CTRL_STEERING_POLICY_RADIO_LIST] = { .name = "radiolist", .type = BLOBMSG_TYPE_ARRAY },
	[MAP_CTRL_STEERING_POLICY_BTM_DISALLOW_LIST] = { .name = "btmdisallowstalist", .type = BLOBMSG_TYPE_ARRAY },	
	[MAP_CTRL_STEERING_POLICY_LOCAL_DISALLOW_LIST] = { .name = "localdisallowstalist", .type = BLOBMSG_TYPE_ARRAY },	
};

/* structures for ubus event/cli parameter data parsing */
enum {
	MAP_CTRL_POLICY_DST_MAC,
	MAP_CTRL_POLICY_STA_COUNT,
	MAP_CTRL_POLICY_RADIO_COUNT,	
	MAP_CTRL_POLICY_STAMAC,
	MAP_CTRL_POLICY_RADIOMAC,
	MAP_CTRL_POLICY_MAX
};

static struct blobmsg_policy send_policy_config_policy[MAP_CTRL_POLICY_MAX] = {
	[MAP_CTRL_POLICY_DST_MAC] = { .name = "dstmac", .type = BLOBMSG_TYPE_STRING },
	[MAP_CTRL_POLICY_STA_COUNT] = { .name = "stacnt", .type = BLOBMSG_TYPE_INT32 },
	[MAP_CTRL_POLICY_STAMAC] = { .name = "stamac", .type = BLOBMSG_TYPE_STRING },
	[MAP_CTRL_POLICY_RADIO_COUNT] = { .name = "radiocnt", .type = BLOBMSG_TYPE_INT32 },
	[MAP_CTRL_POLICY_RADIOMAC] = { .name = "radiomac", .type = BLOBMSG_TYPE_ARRAY },
};

enum {
       MAP_SEND_TQ_DSTMAC,
       MAP_SEND_TQ_MAX
};

enum {
	MAP_TARGET_MAC,
	MAP_TARGET_MAX
};

static struct blobmsg_policy send_query[MAP_TARGET_MAX] = {
	[MAP_TARGET_MAC] = { .name = "almac", .type = BLOBMSG_TYPE_STRING },
};

enum {
        MAP_CTRL_LINK_METRIC_AL_MAC,
        MAP_CTRL_LINK_METRIC_METRIC_REQ,
        MAP_CTRL_LINK_METRIC_SPECIFIC_NEIGHBOR,
        MAP_CTRL_LINK_METRIC_NEIGHBOR_MAC,
        MAP_CTRL_LINK_METRIC_MAX
};

static struct blobmsg_policy send_link_metric_query[MAP_CTRL_LINK_METRIC_MAX] = {
        [MAP_CTRL_LINK_METRIC_AL_MAC] = { .name = "almac", .type = BLOBMSG_TYPE_STRING },
        [MAP_CTRL_LINK_METRIC_METRIC_REQ] = { .name = "metric_req", .type = BLOBMSG_TYPE_INT32 },
        [MAP_CTRL_LINK_METRIC_SPECIFIC_NEIGHBOR] = { .name = "specific_neighbor", .type = BLOBMSG_TYPE_INT32 },
        [MAP_CTRL_LINK_METRIC_NEIGHBOR_MAC] = { .name = "neighbor_mac", .type = BLOBMSG_TYPE_STRING },
};

enum {
        MAP_CTRL_AP_METRIC_AL_MAC,
        MAP_CTRL_AP_METRIC_BSS_COUNT,
        MAP_CTRL_AP_METRIC_BSSID_LIST,
        MAP_CTRL_AP_METRIC_MAX
};

static struct blobmsg_policy send_ap_metric_query[MAP_CTRL_AP_METRIC_MAX] = {
        [MAP_CTRL_AP_METRIC_AL_MAC] = { .name = "almac", .type = BLOBMSG_TYPE_STRING },
        [MAP_CTRL_AP_METRIC_BSS_COUNT] = { .name = "bssidcount", .type = BLOBMSG_TYPE_INT32 },
        [MAP_CTRL_AP_METRIC_BSSID_LIST] = { .name = "bssidlist", .type = BLOBMSG_TYPE_ARRAY },
};


enum {
        MAP_AGENT_CHANNEL_SEL_QUERY_ALMAC,
        MAP_AGENT_CHANNEL_SEL_QUERY_RADID,
        MAP_AGENT_CHANNEL_SEL_QUERY_OPCLASSLIST,
        MAP_AGENT_CHANNEL_SEL_QUERY_TXPWR,
        MAP_AGENT_CHANNEL_SEL_QUERY_MAX,
};


static struct blobmsg_policy send_channel_sel_query[MAP_AGENT_CHANNEL_SEL_QUERY_MAX] = {
        [MAP_AGENT_CHANNEL_SEL_QUERY_ALMAC] = { .name = "almac", .type = BLOBMSG_TYPE_STRING },
        [MAP_AGENT_CHANNEL_SEL_QUERY_RADID] = { .name = "radioid", .type = BLOBMSG_TYPE_STRING },
        [MAP_AGENT_CHANNEL_SEL_QUERY_TXPWR] = { .name = "txpower", .type = BLOBMSG_TYPE_INT32 },
        [MAP_AGENT_CHANNEL_SEL_QUERY_OPCLASSLIST] = { .name = "opclasslist", .type = BLOBMSG_TYPE_ARRAY },
};

enum {
	MAP_AGENT_CHANNEL_PREF_REPORT_ALMAC,
	MAP_AGENT_CHANNEL_PREF_REPORT_RADID,
	MAP_AGENT_CHANNEL_PREF_REPORT_OPCLASSLIST,
	MAP_AGENT_CHANNEL_PREF_REPORT_MAX,
};

static struct blobmsg_policy send_channel_pref_report[MAP_AGENT_CHANNEL_PREF_REPORT_MAX] = {
	[MAP_AGENT_CHANNEL_PREF_REPORT_ALMAC] = { .name = "almac", .type = BLOBMSG_TYPE_STRING },
	[MAP_AGENT_CHANNEL_PREF_REPORT_RADID] = { .name = "radioid", .type = BLOBMSG_TYPE_STRING },
	[MAP_AGENT_CHANNEL_PREF_REPORT_OPCLASSLIST] = { .name = "opclasslist", .type = BLOBMSG_TYPE_ARRAY },
};


enum {
	MAP_CTRL_UNASSOC_STA_DST_ALMAC,
	MAP_CTRL_UNASSOC_STA_OPER_CLASS,
	MAP_CTRL_UNASSOC_STA_TARGET_LIST,
	MAP_CTRL_UNASSOC_STA_METRICS_MAX,
};

static struct blobmsg_policy send_unassoc_sta_metrics_query[MAP_CTRL_UNASSOC_STA_METRICS_MAX] = {
	[MAP_CTRL_UNASSOC_STA_DST_ALMAC] = { .name = "almac", .type = BLOBMSG_TYPE_STRING },
	[MAP_CTRL_UNASSOC_STA_OPER_CLASS] = { .name = "oper_class", .type = BLOBMSG_TYPE_INT32 },
	[MAP_CTRL_UNASSOC_STA_TARGET_LIST] = { .name = "target_list", .type = BLOBMSG_TYPE_ARRAY },
};

enum {
	MAP_CTRL_STEER_ALMAC,
	MAP_CTRL_STEER_STA_CNT,		
	MAP_CTRL_STEER_STA_LIST,
	MAP_CTRL_STEER_CURRBSSID,
	MAP_CTRL_STEER_REQMODE,
	MAP_CTRL_STEER_BTM_DISASSOC_IMMINENT,
	MAP_CTRL_STEER_BTM_ABRIDGED,
	MAP_CTRL_STEER_OPPORTUNITY_WINDOW,
	MAP_CTRL_STEER_BTM_TIMER,
	MAP_CTRL_STEER_TARGBSSID,
	MAP_CTRL_STEER_TARGCHAN,
	MAP_CTRL_STEER_TARGOPCLASS,
	MAP_CTRL_STEER_STA_MAX,
};

static struct blobmsg_policy set_steer_policy[MAP_CTRL_STEER_STA_MAX] = {
	[MAP_CTRL_STEER_ALMAC] = { .name = "almac", .type = BLOBMSG_TYPE_STRING },
	[MAP_CTRL_STEER_STA_CNT] = { .name = "stacount", .type = BLOBMSG_TYPE_INT32},	
	[MAP_CTRL_STEER_STA_LIST] = { .name = "stalist", .type = BLOBMSG_TYPE_ARRAY },
	[MAP_CTRL_STEER_CURRBSSID] = { .name = "currbssid", .type = BLOBMSG_TYPE_STRING },
	[MAP_CTRL_STEER_REQMODE] = { .name = "reqmode", .type = BLOBMSG_TYPE_INT32 },
	[MAP_CTRL_STEER_BTM_DISASSOC_IMMINENT] = { .name = "disassoimmi", .type = BLOBMSG_TYPE_INT32 },
	[MAP_CTRL_STEER_BTM_ABRIDGED] = { .name = "btmabridged", .type = BLOBMSG_TYPE_INT32 },
	[MAP_CTRL_STEER_OPPORTUNITY_WINDOW] = { .name = "opporwindow", .type = BLOBMSG_TYPE_INT32 },
	[MAP_CTRL_STEER_BTM_TIMER] = { .name = "btmtimer", .type = BLOBMSG_TYPE_INT32 },	
	[MAP_CTRL_STEER_TARGBSSID] = { .name = "targbssid", .type = BLOBMSG_TYPE_STRING },
	[MAP_CTRL_STEER_TARGCHAN] = { .name = "targchan", .type = BLOBMSG_TYPE_INT32 },
	[MAP_CTRL_STEER_TARGOPCLASS] = { .name = "targopclass", .type = BLOBMSG_TYPE_INT32 },
};

enum {
    MAP_HIGHLAYER_AGENT_MAC,
    MAP_HIGHLAYER_PROTO,
    MAP_HIGHLAYER_PAYLOAD_PATTERN,
    MAP_HIGHLAYER_REPEAT_CNT,
    MAP_HIGHLAYER_DATAMSG_MAX,
    MAP_HIGHLAYER_PAYLOAD_MAX_LEN = 1470 /* A TLV cannot be more than network segment size */
};

static struct blobmsg_policy send_higherlayer_data_msg[MAP_HIGHLAYER_DATAMSG_MAX] = {
	[MAP_HIGHLAYER_AGENT_MAC] = {.name = "almac", .type = BLOBMSG_TYPE_STRING},
    [MAP_HIGHLAYER_PROTO] = {.name = "protocol", .type = BLOBMSG_TYPE_INT32},
    [MAP_HIGHLAYER_PAYLOAD_PATTERN] = {.name = "pattern", .type = BLOBMSG_TYPE_STRING},
    [MAP_HIGHLAYER_REPEAT_CNT] = {.name = "repeat_cnt", .type = BLOBMSG_TYPE_INT32},
};

enum {
        MAP_CTRL_BEACON_ALMAC,
        MAP_CTRL_BEACON_STAMAC,
   MAP_CTRL_BEACON_OPER_CLASS,
        MAP_CTRL_BEACON_TARGCHAN,
   MAP_CTRL_BEACON_TARGBSSID,
   MAP_CTRL_BEACON_REPORT_DETAIL,
        MAP_CTRL_BEACON_TARGSSID,
   MAP_CTRL_BEACON_CHANREPORT,
        MAP_CTRL_BEACON_MAX
};

static struct blobmsg_policy beacon_query[MAP_CTRL_BEACON_MAX] = {
        [MAP_CTRL_BEACON_ALMAC] = { .name = "almac", .type = BLOBMSG_TYPE_STRING },
        [MAP_CTRL_BEACON_STAMAC] = { .name = "stamac", .type = BLOBMSG_TYPE_STRING },
   [MAP_CTRL_BEACON_OPER_CLASS] = { .name = "oper_class", .type = BLOBMSG_TYPE_INT32 },
        [MAP_CTRL_BEACON_TARGCHAN] = { .name = "targchan", .type = BLOBMSG_TYPE_INT32 },
        [MAP_CTRL_BEACON_TARGBSSID] = { .name = "targbssid", .type = BLOBMSG_TYPE_STRING },
   [MAP_CTRL_BEACON_REPORT_DETAIL] = { .name = "reportdetail", .type = BLOBMSG_TYPE_INT32 },
        [MAP_CTRL_BEACON_TARGSSID] = { .name = "targssid", .type = BLOBMSG_TYPE_STRING },
   [MAP_CTRL_BEACON_CHANREPORT] = { .name = "chanreport", .type = BLOBMSG_TYPE_ARRAY},
};

enum {
        MAP_AGENT_MAC,
        MAP_STA_BSSID,
        MAP_STA_MAC,
        MAP_CLIENT_CAPABILITY_MAX
};

static struct blobmsg_policy send_client_capability_query[MAP_CLIENT_CAPABILITY_MAX] = {
        [MAP_AGENT_MAC] = { .name = "almac", .type = BLOBMSG_TYPE_STRING },
        [MAP_STA_BSSID] = { .name = "bssid", .type = BLOBMSG_TYPE_STRING },
        [MAP_STA_MAC] = { .name = "sta", .type = BLOBMSG_TYPE_STRING },
};

enum {
		MAP_ACL_ALMAC,
        MAP_ACL_STA_BSSID,
        MAP_ACL_ACTION,
        MAP_ACL_VALIDITY_PERIOD,
        MAP_ACL_STA_COUNT,
        MAP_ACL_STA_MAC,
        MAP_ACL_MAX
};

static struct blobmsg_policy send_cli_acl_req[] = {
        [MAP_ACL_ALMAC]           = { .name = "almac", .type = BLOBMSG_TYPE_STRING },
        [MAP_ACL_STA_BSSID]       = { .name = "bssid", .type = BLOBMSG_TYPE_STRING },
        [MAP_ACL_ACTION]          = { .name = "block", .type = BLOBMSG_TYPE_INT32 },
        [MAP_ACL_VALIDITY_PERIOD] = { .name = "validity_period", .type = BLOBMSG_TYPE_INT32 },
        [MAP_ACL_STA_COUNT]       = { .name = "sta_count", .type = BLOBMSG_TYPE_INT32 },
        [MAP_ACL_STA_MAC]         = { .name = "sta_mac", .type = BLOBMSG_TYPE_ARRAY},
};


enum {
    GET_VERSION,
    __GET_VERSION
};

static const struct blobmsg_policy get_policy[] = {
    [GET_VERSION] = { .name = "version", .type = BLOBMSG_TYPE_STRING },
};

enum {
        MAP_SUP_FREQ_BAND,
        MAP_RENEW_MAX
};

static struct blobmsg_policy send_autoconfig_renew[MAP_RENEW_MAX] = {
        [MAP_SUP_FREQ_BAND] = { .name = "supported_freq", .type = BLOBMSG_TYPE_INT32 },
};

/* Ubus event handler callback */
static void handle_event(struct ubus_context *ctx, struct ubus_event_handler *ev,
                                const char *type, struct blob_attr *msg);

/* UBUS event handler */
static struct ubus_event_handler ubus_event_handle = { .cb = handle_event, };

/* Platform event callback function prototype to notify application/main thread of the events */
typedef void (*platform_ubus_event_handler_t)(void *ctx, void *ev,
                                const char *type, struct blob_attr *msg);

/* Global array list to hold on the pending queried array_list and its time of arrival */
static array_list_t *g_beacon_metric_response_pend_list = NULL;

typedef struct platform_ubus_event
{
	const char* event_name;
	platform_ubus_event_handler_t platform_event_handler;
	uint8_t registered; 
}platform_ubus_event_t;

/* event callbacks for ubus */
static void map_monitor_stn_event_callback(void *ctx, void *ev, const char *type, struct blob_attr *msg);
static void map_monitor_wireless_radio_event_callback(void *ctx, void *ev, const char *type, struct blob_attr *msg);
static void map_monitor_network_link_event_callback(void *ctx, void *ev, const char *type, struct blob_attr *msg);
static void map_monitor_beacon_metrics_event_callback(void *ctx, void *ev, const char *type, struct blob_attr *msg);
static void map_monitor_wireless_ssid_event_agent_callback(void *ctx, void *ev, const char *type, struct blob_attr *msg);
static void map_monitor_credential_callback(void *ctx, void *ev, const char *type, struct blob_attr *msg);
static void map_monitor_unassoc_metrics_event_callback (void *ctx, void *ev, const char *type, struct blob_attr *msg);
static void map_monitor_btm_report_callback (void *ctx, void *ev, const char *type, struct blob_attr *msg);
/* Platform event table with the event pattern and the corresponding application callback
   The callbacks ar enabled only when application registers for the event */
platform_ubus_event_t *platform_ubus_event_table;

static unsigned int gnum_events;

/* Platform event table for multiap_agent with the event pattern and the corresponding 
   application callback. The callbacks are enabled on registration for the event */
platform_ubus_event_t platform_ubus_event_table_agent[]=
{
	/* Pattern , Function pointer to the application callback */
    {WIRELESS_SSID_EVENT_STR,map_monitor_wireless_ssid_event_agent_callback, 0},
    {WIRELESS_STA_EVENT_STR,map_monitor_stn_event_callback, 0},
    {WIRELESS_RADIO_EVENT_STR,map_monitor_wireless_radio_event_callback, 0},
    {NETWORK_LINK_EVENT_STR, map_monitor_network_link_event_callback, 0},
    {WIRELESS_BEACON_METRICS_EVENT, map_monitor_beacon_metrics_event_callback, 0},
    {WIRELESS_UNASSOC_METRICS_OBJ_STR, map_monitor_unassoc_metrics_event_callback, 0},
    {WIRELESS_BTM_REPORT_EVENT_STR, map_monitor_btm_report_callback, 0}
};

/* Platform event table for multiap_controller with the event pattern and the corresponding 
   application callback. The callbacks are enabled on registration for the event */
platform_ubus_event_t platform_ubus_event_table_ctrl[]=
{
	/* Pattern , Function pointer to the application callback */
	{MULTIAP_CREDENTIAL_EVENT_STR,map_monitor_credential_callback, 0},
	{NETWORK_LINK_EVENT_STR, map_monitor_network_link_event_callback, 0},
};


/* Platform cli callback function prototype to notify application/main thread */
typedef int (*platform_ubus_method_handler_t) (void *ctx, void *obj,
    							void *req, const char *method, struct blob_attr *msg);

typedef struct platform_ubus_method
{
	const char* method_name;
	platform_ubus_method_handler_t platform_method_handler;
	uint8_t registered; 
}platform_ubus_method_t;

/* cli call back methods for ubus */
static int map_monitor_cli_sendtq_callback(void *ctx, void *obj, void *req, const char *method, struct blob_attr *msg);
static int map_monitor_cli_send_apcap_query_callback(void *ctx, void *obj, void *req, const char *method, struct blob_attr *msg);
static int map_monitor_cli_sta_steer_callback (void *ctx, void *obj, void *req, const char *method, struct blob_attr *msg);
static int map_monitor_cli_channel_preference_query_callback(void *ctx, void *obj, void *req, const char *method, struct blob_attr *msg);
static int map_monitor_cli_channel_selection_request_callback(void *ctx, void *obj, void *req, const char *method, struct blob_attr *msg);
static int map_monitor_cli_channel_selection_request_detail_callback(void *ctx, void *obj, void *req, const char *method, struct blob_attr *msg);
static int map_monitor_cli_dump_controller_callback(void *ctx, void *obj, void *req, const char *method, struct blob_attr *msg);
static int map_monitor_cli_send_policy_config_callback(void *ctx, void *obj, void *req, const char *method, struct blob_attr *msg);
static int map_monitor_cli_send_steer_policy_config_callback (void *ctx, void *obj, void *req, const char *method, struct blob_attr *msg);
static int map_monitor_cli_send_clicap_query_callback(void *ctx, void *obj, void *req, const char *method, struct blob_attr *msg);
static int map_monitor_cli_dump_agent_callback(void *ctx, void *obj, void *req, const char *method, struct blob_attr *msg);
static int map_monitor_cli_send_acl_request_callback(void *ctx, void *obj, void *req, const char *method, struct blob_attr *msg);
static int map_monitor_cli_assoc_sta_metric_query_callback(void *ctx, void *obj, void *req, const char *method, struct blob_attr *msg);
static int map_monitor_cli_unassoc_sta_metric_query_callback(void *ctx, void *obj, void *req, const char *method, struct blob_attr *msg);
static int map_monitor_cli_get_version(struct ubus_context *ctx, struct ubus_object *obj,struct ubus_request_data *req, const char *method, struct blob_attr *msg);
static int map_monitor_cli_send_channel_pref_report_callback(void *ctx, void *obj, void *req, const char *method, struct blob_attr *msg);
static int map_monitor_cli_autoconfig_renew_callback(void *ctx, void *obj, void *req, const char *method, struct blob_attr *msg);
static int map_monitor_cli_beacon_metric_query_callback (void *ctx, void *obj, void *req, const char *method, struct blob_attr *msg);
static int map_monitor_cli_link_metric_query_callback(void *ctx, void *obj, void *req, const char *method, struct blob_attr *msg);
static int map_monitor_cli_send_higher_layer_data_msg_callback(void *ctx, void *obj, void *req, const char *method, struct blob_attr *msg);
static int map_monitor_cli_ap_metric_query_callback(void *ctx, void *obj, void *req, const char *method, struct blob_attr *msg);
static int map_monitor_cli_combined_infra_metric_query_callback(void *ctx, void *obj, void *req, const char *method, struct blob_attr *msg);
static int map_monitor_cli_dump_topo_tree_callback(void *ctx, void *obj, void *req, const char *method, struct blob_attr *msg);

/* Platform method table with the method pattern and the corresponding callback
   The callback is initially NULL and is then set when the application
   registers any callback. But make sure to update the pattern
   at compile time. This is not dynamic. */

/* IMP - THIS SHOULD CONTAIN ALL THE PATTERNS DEFINED IN THE UBUS METHOD OF CTRL AND AGENT
   ubus_method_ctrl AND ubus_method_agent*/
platform_ubus_method_t platform_ubus_method_table[]=
{
	/* Pattern , Function pointer to the application callback */
	{SEND_STA_STEER_METHOD_STR,map_monitor_cli_sta_steer_callback, 0},
	{SEND_TOPOLOGY_QUERY_METHOD_STR,map_monitor_cli_sendtq_callback, 0},
        {SEND_CAPABILITY_QUERY_METHOD_STR,map_monitor_cli_send_apcap_query_callback, 0},
	{SEND_CHANNEL_PREF_QURY_METHOD_STR,map_monitor_cli_channel_preference_query_callback, 0},
	{SEND_CHANNEL_SEL_REQ_METHOD_STR,map_monitor_cli_channel_selection_request_callback, 0},
	{SEND_CHANNEL_SEL_REQ_METHOD_DETAIL_STR,map_monitor_cli_channel_selection_request_detail_callback, 0},
	{SEND_DUMP_CTRL_INFO_METHOD_STR,map_monitor_cli_dump_controller_callback, 0},
	{SEND_POLICY_CONFIG_METHOD_STR,map_monitor_cli_send_policy_config_callback, 0},
	{SEND_STEER_POLICY_CONFIG_METHOD_STR,map_monitor_cli_send_steer_policy_config_callback,0},
	{SEND_CLNT_CAPABILITY_QUERY_METHOD_STR, map_monitor_cli_send_clicap_query_callback, 0},
	{SEND_DEBUG_AGENT_INFO_METHOD_STR, map_monitor_cli_dump_agent_callback, 0},
        {SEND_CLIENT_ACL_REQUEST_METHOD_STR, map_monitor_cli_send_acl_request_callback, 0},
        {SEND_ASSOC_STA_METRIC_QUERY_METHOD_STR, map_monitor_cli_assoc_sta_metric_query_callback, 0},
        {SEND_UNASSOC_STA_METRIC_QUERY_METHOD_STR, map_monitor_cli_unassoc_sta_metric_query_callback, 0},
        {SEND_CHANNEL_PREF_REPORT_METHOD_STR, map_monitor_cli_send_channel_pref_report_callback, 0},
        {SEND_AUTOCONFIG_RENEW_METHOD_STR,map_monitor_cli_autoconfig_renew_callback, 0},
        {SEND_BEACON_METRIC_QUERY_METHOD_STR, map_monitor_cli_beacon_metric_query_callback, 0},
        {SEND_LINK_METRIC_QUERY_METHOD_STR, map_monitor_cli_link_metric_query_callback, 0},
        {SEND_HIGHLAYER_DATA_MSG_METHOD_STR, map_monitor_cli_send_higher_layer_data_msg_callback, 0},
        {SEND_AP_METRIC_QUERY_METHOD_STR, map_monitor_cli_ap_metric_query_callback, 0},
        {SEND_COMBINED_INFRA_METRIC_QUERY_METHOD_STR, map_monitor_cli_combined_infra_metric_query_callback},
        {DUMP_TOPO_TREE_METHOD_STR, map_monitor_cli_dump_topo_tree_callback},
};


static unsigned int gnum_methods = sizeof(platform_ubus_method_table)/sizeof(platform_ubus_method_t);

/* Ubus object method handler */
static int handle_method (struct ubus_context *ctx, struct ubus_object *obj,
    struct ubus_request_data *req, const char *method, struct blob_attr *msg);

#define UBUS_METHOD_NAME(_name)	 UBUS_METHOD_NOARG(_name, handle_method)

/* UBUS method definitions for ctrl */

/* IMP - INCASE THIS IS UPDATED MAKE SURE TO UPDATE platform_ubus_method_table as well */
static struct ubus_method ubus_method_ctrl[] = {
	{.name = SEND_TOPOLOGY_QUERY_METHOD_STR, .handler = handle_method, .policy = send_query, .n_policy = ARRAY_SIZE(send_query)},
	{.name = SEND_STA_STEER_METHOD_STR, .handler= handle_method, .policy = set_steer_policy, .n_policy = ARRAY_SIZE(set_steer_policy)},
    {.name = SEND_CAPABILITY_QUERY_METHOD_STR, .handler = handle_method, .policy = send_query, .n_policy = ARRAY_SIZE(send_query)},
	{.name = SEND_CHANNEL_PREF_QURY_METHOD_STR, .handler = handle_method, .policy = send_query, .n_policy = ARRAY_SIZE(send_query)},
	{.name = SEND_CHANNEL_SEL_REQ_METHOD_STR, .handler = handle_method, .policy = send_query, .n_policy = ARRAY_SIZE(send_query)},
	{.name = SEND_CHANNEL_SEL_REQ_METHOD_DETAIL_STR, .handler = handle_method, .policy = send_channel_sel_query, .n_policy = ARRAY_SIZE(send_channel_sel_query)},
	{.name = SEND_DUMP_CTRL_INFO_METHOD_STR, .handler = handle_method, .policy = NULL, .n_policy = 0},
	{.name = SEND_POLICY_CONFIG_METHOD_STR, .handler = handle_method, .policy = send_policy_config_policy, .n_policy = ARRAY_SIZE(send_policy_config_policy)},
	{.name = SEND_STEER_POLICY_CONFIG_METHOD_STR, .handler = handle_method, .policy = send_steer_policy_config_policy, .n_policy = ARRAY_SIZE(send_steer_policy_config_policy)},
	{.name = SEND_CLNT_CAPABILITY_QUERY_METHOD_STR, .handler= handle_method, .policy = send_client_capability_query, .n_policy = ARRAY_SIZE(send_client_capability_query)},
        {.name = SEND_CLIENT_ACL_REQUEST_METHOD_STR, .handler = handle_method, .policy = send_cli_acl_req, .n_policy = ARRAY_SIZE(send_cli_acl_req)},
        {.name = SEND_ASSOC_STA_METRIC_QUERY_METHOD_STR, .handler = handle_method, .policy = send_query, .n_policy = ARRAY_SIZE(send_query)},
        {.name = SEND_UNASSOC_STA_METRIC_QUERY_METHOD_STR, .handler = handle_method, .policy = send_unassoc_sta_metrics_query, .n_policy = ARRAY_SIZE(send_unassoc_sta_metrics_query)},
        {.name = SEND_AUTOCONFIG_RENEW_METHOD_STR, .handler = handle_method, .policy = send_autoconfig_renew, .n_policy = ARRAY_SIZE(send_autoconfig_renew)},
        {.name = SEND_BEACON_METRIC_QUERY_METHOD_STR, .handler = handle_method, .policy = beacon_query, .n_policy = ARRAY_SIZE(beacon_query)},
        {.name = SEND_LINK_METRIC_QUERY_METHOD_STR, .handler = handle_method, .policy = send_link_metric_query, .n_policy = ARRAY_SIZE(send_link_metric_query)},
        {.name = SEND_HIGHLAYER_DATA_MSG_METHOD_STR, .handler = handle_method, .policy = send_higherlayer_data_msg, .n_policy = ARRAY_SIZE(send_higherlayer_data_msg)},
        {.name = SEND_AP_METRIC_QUERY_METHOD_STR, .handler = handle_method, .policy = send_ap_metric_query, .n_policy = ARRAY_SIZE(send_ap_metric_query)},
        {.name = SEND_COMBINED_INFRA_METRIC_QUERY_METHOD_STR, .handler = handle_method, .policy = send_query, .n_policy = ARRAY_SIZE(send_query)},
        {.name = DUMP_TOPO_TREE_METHOD_STR, .handler = handle_method, .policy = NULL, .n_policy =0},
	UBUS_METHOD("get_version", map_monitor_cli_get_version, get_policy),
};

static struct ubus_object_type ubus_type_ctrl =
    UBUS_OBJECT_TYPE("map_controller", ubus_method_ctrl);

static struct ubus_object ubus_object_ctrl = {
    .name = "map_controller",
    .type = &ubus_type_ctrl,
    .methods = ubus_method_ctrl,
    .n_methods = ARRAY_SIZE(ubus_method_ctrl),
};

/* UBUS method definitions for agent */

/* IMP - INCASE THIS IS UPDATED MAKE SURE TO UPDATE platform_ubus_method_table as well */
static struct ubus_method ubus_method_agent[] = {
	{.name = SEND_TOPOLOGY_QUERY_METHOD_STR, .handler = handle_method, .policy = send_query, .n_policy = ARRAY_SIZE(send_query)},
	{.name = SEND_CLNT_CAPABILITY_QUERY_METHOD_STR, .handler= handle_method, .policy = send_client_capability_query, .n_policy = ARRAY_SIZE(send_client_capability_query)},	
	{.name = SEND_CHANNEL_PREF_REPORT_METHOD_STR, .handler = handle_method, .policy = send_channel_pref_report, .n_policy = ARRAY_SIZE(send_channel_pref_report)},
	{.name = SEND_DEBUG_AGENT_INFO_METHOD_STR, .handler = handle_method, .policy = send_query, .n_policy = ARRAY_SIZE(send_query)},
    {.name = SEND_HIGHLAYER_DATA_MSG_METHOD_STR, .handler = handle_method, .policy = send_higherlayer_data_msg, .n_policy = ARRAY_SIZE(send_higherlayer_data_msg)},
	UBUS_METHOD("get_version", map_monitor_cli_get_version, get_policy),
};

static struct ubus_object_type ubus_type_agent =
    UBUS_OBJECT_TYPE("map_agent", ubus_method_agent);

static struct ubus_object ubus_object_agent = {
    .name = "map_agent",
    .type = &ubus_type_agent,
    .methods = ubus_method_agent,
    .n_methods = ARRAY_SIZE(ubus_method_agent),
};

/* static helper functions */
static station_state_t get_station_state(const char *state);
static int defer_cli(void *ctx, void *req);
static int platform_send_reply(void *ctx, void *req, struct blob_attr *msg);
static int get_platform_event_index(const char* event);
static int get_platform_method_index(const char* method);


/* API to get the index of a particular event in the global platform table */
static int get_platform_event_index(const char* event)
{
	int i, ret = -1;

	/* Iterate through the platform event table and get the index
	 for the pattern */
	for(i=0;i<gnum_events;i++)
	{
		if (strcmp(event, platform_ubus_event_table[i].event_name) == 0)
		{
			ret = i;
			break;
		}
	}

	return ret;
}

/* API to get the index of a particular method in the global platform table */
static int get_platform_method_index(const char* method)
{
	int i, ret = -1;

	/* Iterate through the platform method table and get the index
	 for the pattern */
	for(i=0;i<gnum_methods;i++)
	{
		if (strcmp(method, platform_ubus_method_table[i].method_name) == 0)
		{
			ret = i;
			break;
		}
	}

	return ret;
}

static int platform_send_reply(void *ctx, void *req, struct blob_attr *msg)
{
	int ret = PLATFORM_UBUS_STATUS_ERROR;
	struct ubus_context *uctx;
	struct ubus_request_data *ureq;

	/* Context should be UBUS context*/
	uctx = (struct ubus_context *)ctx;

	ureq = (struct ubus_request_data *)req;

	/* Input parameters check */
	if (uctx == NULL || ureq == NULL)
	{
		platform_log(MAP_LIBRARY,LOG_ERR,"invalid arguments for %s",__FUNCTION__);
	}
	else
	{
		/* Ubus send reply */
		ret = ubus_send_reply(uctx, ureq, msg);
	}

	return ret;
}

static int defer_cli(void *ctx, void *req) 
{
    int ret = 0;
    struct ubus_context *uctx;
    struct ubus_request_data *ureq;

    /* Context should be UBUS context*/
    uctx = (struct ubus_context *)ctx;

    ureq = (struct ubus_request_data *)req;

    /* Input parameters check */
    if (uctx == NULL || ureq == NULL || plt_hmwr_ctx == NULL)
    {
        platform_log(MAP_LIBRARY,LOG_ERR,"invalid arguments for %s",__FUNCTION__);
        ret = -EINVAL;
    }
    else
    {
        /* Ubus send reply */
        if(!plt_hmwr_ctx->cli_pending_response) {
            ubus_defer_request(uctx, ureq, &plt_hmwr_ctx->ubus_response);
            plt_hmwr_ctx->cli_pending_response = 1;
        } else {
            platform_log(MAP_LIBRARY,LOG_ERR, "Error:  Already an ubus cli waiting for completion");
        }
    }
    return ret;
}


static station_state_t get_station_state(const char *state)
{
    if (!state) {
        return STATION_STATE_UNKNOWN;
    }
    else if (strcmp(state, "Disconnected") == 0) {
        return STATION_STATE_DISCONNECTED;
    }
    else if (strcmp(state, "StateChanged") == 0) {
        return STATION_STATE_CHANGED;
    }
    else if (strcmp(state, "Associated") == 0) {
        return STATION_STATE_ASSOCIATED;
    }
    else if (strcmp(state, "Authorized") == 0) {
        return STATION_STATE_AUTHORIZED;
    }
    else {
        return STATION_STATE_UNKNOWN;
    }
}

static void map_monitor_wireless_radio_event_callback(void *ctx, void *ev, const char *type, struct blob_attr *msg)
{
	map_monitor_evt_t *monitor_evt = NULL;
	radio_channel_event_t *radio_channel = NULL;
	struct blob_attr *c = NULL;
    struct blob_attr *data = blob_data(msg);
    int rem = blob_len(msg);
	const char *chnl_switch = NULL;
	const char *radio_name = NULL;

	platform_log(MAP_LIBRARY,LOG_DEBUG,"%s event call back for %s \n", __FUNCTION__, type);
    if(ctx == NULL)
    {
        platform_log(MAP_LIBRARY,LOG_DEBUG,"%s Context NULL for event callback\n", __FUNCTION__);
    }
	
	monitor_evt = (map_monitor_evt_t*) malloc(sizeof(map_monitor_evt_t));
	radio_channel = (radio_channel_event_t *) malloc (sizeof(radio_channel_event_t));
	
	if((NULL != monitor_evt) && (NULL != radio_channel)) {
	memset(monitor_evt, 0, sizeof(map_monitor_evt_t));
	memset(radio_channel, 0, sizeof(radio_channel_event_t));
	
		__blob_for_each_attr(c, data, rem)
		{
			if (strcmp(blobmsg_name(c), "channel_switch") == 0) {
				chnl_switch = blobmsg_get_string(c);
			}
			if (strcmp(blobmsg_name(c), "name") == 0) {
				radio_name = blobmsg_get_string(c);
			}
		}

		if((chnl_switch != NULL) && (radio_name != NULL ))
		{
			platform_get_context(MAP_PLATFORM_GET_RADIO_INFO,radio_name,(void *)radio_channel,ctx);
			platform_get_context(MAP_PLATFORM_GET_TX_PWR, radio_name,(void *)&radio_channel->current_tx_pwr,ctx);
			platform_log(MAP_LIBRARY,LOG_DEBUG,"%s Channel - %d , NAME - %s, current tx power %d\n", __FUNCTION__,radio_channel->channel,radio_name, radio_channel->current_tx_pwr);
			platform_log(MAP_LIBRARY,LOG_DEBUG,"%s Length of blob radio - %d \n", __FUNCTION__,strlen(radio_name));
			platform_log(MAP_LIBRARY,LOG_DEBUG, "%s %d, %2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx \n",__func__, __LINE__,
				radio_channel->radio_id[0], radio_channel->radio_id[1],
				radio_channel->radio_id[2], radio_channel->radio_id[3],
				radio_channel->radio_id[4], radio_channel->radio_id[5]);
			/* Populate the data to be passed to agent from monitor */
                        monitor_evt->evt = MAP_MONITOR_WIRELESS_RADIO_CHANNEL_EVT;
			monitor_evt->evt_data = radio_channel;

            /* Notify event to main thread */
			if(event_notify_main_thread((void*)plt_hmwr_ctx->monitor_q_hdle,(void*)monitor_evt))
			{
				free(radio_channel);
				free(monitor_evt);
				platform_log(MAP_LIBRARY,LOG_ERR,"%s uv_callback failed \n", __FUNCTION__);
			}
		}
		else
		{
                    if (NULL != radio_channel)
                        free(radio_channel);
                    if (NULL != monitor_evt)
			free(monitor_evt);
                    platform_log(MAP_LIBRARY,LOG_DEBUG,"%s Ignore event \n", __FUNCTION__);
		}
	}
	else {
            if (NULL != radio_channel)
                free(radio_channel);
            if (NULL != monitor_evt)
                free(monitor_evt);
            platform_log(MAP_LIBRARY,LOG_ERR,"%s memory allocation failed \n", __FUNCTION__);
	}

	return;
}

static void map_monitor_stn_event_callback(void *ctx, void *ev, const char *type, struct blob_attr *msg)
{
    map_monitor_evt_t monitor_evt;
    stn_event_t *stn_event = NULL;
    struct blob_attr *c = NULL;
    struct blob_attr *data = blob_data(msg);
    int rem = blob_len(msg);
    const char *ap_name = NULL;
    const char *station = NULL;
    char bssid[MAX_MAC_STRING_LEN];
    station_state_t state = STATION_STATE_UNKNOWN;

    platform_log(MAP_LIBRARY,LOG_DEBUG,"%s event call back for %s \n", __FUNCTION__, type);
    if(ctx == NULL)
    {
        platform_log(MAP_LIBRARY,LOG_DEBUG,"%s Context NULL for event callback\n", __FUNCTION__);
    }

    stn_event = (stn_event_t*) malloc(sizeof(stn_event_t));
    if(NULL == stn_event) {
        platform_log(MAP_LIBRARY,LOG_ERR,"%s memory allocation failed \n", __FUNCTION__);
        return;
    }
    /* Parse the JSON data received from UBUS */
    memset(&monitor_evt, 0, sizeof(map_monitor_evt_t));
    memset(stn_event, 0, sizeof(stn_event_t));

    __blob_for_each_attr(c, data, rem)
    {
        if (strcmp(blobmsg_name(c), "ap_name") == 0) {
            ap_name = blobmsg_get_string(c);
        } else if (strcmp(blobmsg_name(c), "macaddr") == 0) {
            station = blobmsg_get_string(c);
        } else if (strcmp(blobmsg_name(c), "state") == 0) {
            state = get_station_state(blobmsg_get_string(c));
        }
    }
    platform_log(MAP_LIBRARY,LOG_DEBUG,"%s AP NAME %s \n", __FUNCTION__, ap_name);
    platform_log(MAP_LIBRARY,LOG_DEBUG,"%s MAC ADDR %s \n", __FUNCTION__, station);
    platform_log(MAP_LIBRARY,LOG_DEBUG,"%s STATE %d \n", __FUNCTION__, state);

    /* Usually for client connect , 3 events are received with state as "StateChanged","Authorized"
    and "Associated". Considering only the "Associated" event for Topology notification */
    if (state == STATION_STATE_DISCONNECTED || state == STATION_STATE_ASSOCIATED)
    {
        if(platform_if_info_neighbor_list_update(ctx, ap_name)) {
            platform_log(MAP_LIBRARY,LOG_ERR,"%s Failed to update cached neighbor list for ap %s\n", __FUNCTION__, ap_name);
        }

        platform_get_mac_from_string((char*)station, stn_event->mac_addr);

        platform_log(MAP_LIBRARY,LOG_DEBUG,"%s Get BSSID from Lua with context \n", __FUNCTION__);
        memset(bssid,'\0',sizeof(bssid));
        platform_get_context(MAP_PLATFORM_GET_AGENT_BSSID,ap_name,(void *)bssid,ctx);
        platform_get_mac_from_string(bssid, stn_event->bssid);
        /* For association, bit 7 is set to 1 and for disconnect it is set 0 */
        if(state == STATION_STATE_ASSOCIATED) {

            json_t *root        = json_object();
            char * json_str     = NULL;

            json_object_set_new ( root, "macaddr", json_string(station));
            json_object_set_new ( root, "name", json_string(ap_name));
          
            json_str = json_dumps(root, 0);

            platform_log(MAP_LIBRARY,LOG_DEBUG,"\n\n%s %d, input to get assoc %s\n\n", __FUNCTION__, __LINE__, json_str);

            /* get Assoc frame */
            platform_get_context(MAP_PLATFORM_GET_ASSOC_FRAME, json_str, (void *)stn_event, ctx);

            platform_log(MAP_LIBRARY,LOG_DEBUG,"\n\n%s %d, assoc len %d \n\n", __FUNCTION__, __LINE__, stn_event->assoc_frame_len);
            /* set the event */
            stn_event->association_event = (1 << 7);

            free(json_str);
            json_decref(root);
        }

        /* Populate the data to be passed to agent from monitor */
        monitor_evt.evt = MAP_MONITOR_STATION_EVT;
        monitor_evt.evt_data = stn_event;

        /* Notify event to main thread */
        if(map_notify_main_thread(&monitor_evt)) {
            platform_log(MAP_LIBRARY,LOG_ERR,"%s Failed to notify main thread \n", __FUNCTION__);
            goto CLEANUP;
        }
    }
    else {
        platform_log(MAP_LIBRARY,LOG_DEBUG,"%s Ignored event: MAP_MONITOR_STATION_EVT \n", __FUNCTION__);
        goto CLEANUP;
    }

    // Return on succesfull event notification
    return;

CLEANUP:
    if(NULL != stn_event)
        free(stn_event);
    return;
}

static void map_monitor_btm_report_callback (void *ctx, void *ev, const char *type, struct blob_attr *msg)
{
    btm_report_event_t *btm_report_evt = NULL;
    struct blob_attr *c = NULL;
    map_monitor_evt_t *monitor_evt = NULL;
    struct blob_attr *data = blob_data(msg);
    int rem = blob_len(msg);
    const char *ap_name = NULL;
    const char *station = NULL;
    const char *btm_target_bssid = NULL;
    uint8_t btm_steer_status = -1;
    char bssid[MAX_MAC_STRING_LEN] = {0};

    platform_log(MAP_LIBRARY,LOG_DEBUG,"%s event call back for %s \n", __FUNCTION__, type);
    if(ctx == NULL)
    {
        platform_log(MAP_LIBRARY,LOG_DEBUG,"%s Context NULL for event callback\n", __FUNCTION__);
    }

    monitor_evt = (map_monitor_evt_t*) malloc(sizeof(map_monitor_evt_t));
    btm_report_evt = (btm_report_event_t*)calloc(1, sizeof(btm_report_event_t));

    if(NULL != monitor_evt && NULL != btm_report_evt) {
        __blob_for_each_attr(c, data, rem)
        {
            if (strcmp(blobmsg_name(c), "ap_name") == 0) {
                ap_name = blobmsg_get_string(c);
            } else if (strcmp(blobmsg_name(c), "macaddr") == 0) {
                station = blobmsg_get_string(c);
            } else if (strcmp(blobmsg_name(c), "target_mac") == 0) {
                btm_target_bssid = blobmsg_get_string(c);
            } else if (strcmp(blobmsg_name(c), "response_code") == 0) {
                btm_steer_status = (uint8_t)blobmsg_get_u32(c);
            }
        }
        /* get current bssid from ap name */
        memset(bssid,'\0',sizeof(bssid));
        platform_get_context(MAP_PLATFORM_GET_AGENT_BSSID,ap_name,(void *)bssid,ctx);
        platform_get_mac_from_string(bssid, btm_report_evt->current_bssid);

        /* get station mac */
        platform_get_mac_from_string((char*)station, btm_report_evt->stn_mac_addr);

        /* get target bssid */
        platform_get_mac_from_string((char*)btm_target_bssid, btm_report_evt->target_bssid);

        btm_report_evt->btm_status = btm_steer_status;

        monitor_evt->evt = MAP_MONITOR_BTM_REPORT_EVT;
        monitor_evt->evt_data = btm_report_evt;
        /* Notify event to main thread */
        if(event_notify_main_thread((void*)plt_hmwr_ctx->monitor_q_hdle,(void*)monitor_evt))
        {
            free(btm_report_evt);
            free(monitor_evt);
            platform_log(MAP_LIBRARY,LOG_ERR,"%s uv_callback failed \n", __FUNCTION__);
        }
    }else {
        if(NULL != monitor_evt)
            free(monitor_evt);
        if(NULL != btm_report_evt)
            free(btm_report_evt);
        platform_log(MAP_LIBRARY,LOG_DEBUG,"%s %d memory allocation failed \n", __FUNCTION__,__LINE__);
    }
}

static void map_monitor_credential_callback(void *ctx, void *ev, const char *type, struct blob_attr *msg)
{
        map_monitor_evt_t *monitor_evt      = NULL;

        platform_log(MAP_LIBRARY,LOG_DEBUG,"%s event call back for %s \n", __FUNCTION__, type);

        monitor_evt = (map_monitor_evt_t*) calloc(1, sizeof(map_monitor_evt_t));

        if(NULL != monitor_evt) {

            monitor_evt->evt = MAP_MONITOR_CREDENTIAL_EVT;
            monitor_evt->evt_data = NULL;
            /* Notify event to main thread */
            if(event_notify_main_thread((void*)plt_hmwr_ctx->monitor_q_hdle,(void*)monitor_evt))
            {
                free(monitor_evt);
                platform_log(MAP_LIBRARY,LOG_ERR,"%s event notification failed \n", __FUNCTION__);
            }
        }
        else {
            platform_log(MAP_LIBRARY,LOG_ERR,"%s memory allocation failed for monitor_event\n", __FUNCTION__);
            goto Cleanup;
        }

        return;

Cleanup:
    if (NULL != monitor_evt)
        free(monitor_evt);

    return;
}

static void map_monitor_wireless_ssid_event_agent_callback(void *ctx, void *ev, const char *type, struct blob_attr *msg)
{
    map_monitor_evt_t monitor_evt;
    struct blob_attr *c                 = NULL;
    struct blob_attr *data              = blob_data(msg);
    ssid_radio_state_t *radio_data      = NULL;
    int rem                             = blob_len(msg);
    int len                             = 0;
    char   bssid_str[MAX_MAC_STRING_LEN]= {0};
    char ap_name[MAX_AP_NAME_LEN];
    uint8_t bssid[MAC_ADDR_LEN];
    uint8_t state                       = -1;

    platform_log(MAP_LIBRARY,LOG_DEBUG,"%s event call back for %s \n", __FUNCTION__, type);

    monitor_evt.evt = MAP_MONITOR_WIRELESS_SSID_RADIO_EVT;
    monitor_evt.evt_data = NULL;

    radio_data = (ssid_radio_state_t *) calloc (1,sizeof(ssid_radio_state_t));
    if (NULL == radio_data) {
        platform_log(MAP_LIBRARY,LOG_ERR,"%s memory allocation failed for radio_data\n", __FUNCTION__);
        goto CLEANUP;
    }

    __blob_for_each_attr(c, data, rem) {
        if (strcmp(blobmsg_name(c), "name") == 0) {
            strncpy(radio_data->if_name, blobmsg_get_string(c), MAX_IFACE_NAME_LEN);
            len = strnlen(radio_data->if_name, MAX_IFACE_NAME_LEN);
            radio_data->if_name[len] = '\0';
        }
    }

    // Get the radio data from platform
    platform_get_context(MAP_PLATFORM_GET_RADIO_BSS_STATE_INFO, radio_data->if_name, (void *)radio_data,ctx);
    monitor_evt.evt_data = (void *)radio_data;

    /* update the 1905 cached interfaceinfo for reported i/f */
    if((NULL != radio_data) && ('\0' != radio_data->if_name[0])) {
        platform_if_info_wireless_if_state_update(ctx, radio_data->if_name, bssid);
    } else {
        platform_log(MAP_LIBRARY,LOG_ERR,"%s invalid i/f name, 1905 interface info invalid \n", __FUNCTION__);
    }
    snprintf(bssid_str, MAX_MAC_STRING_LEN, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);

    get_ap_from_bssid(bssid_str, ap_name, ctx);
    state = get_wps_state(ap_name,ctx);
    if(state != -1)
    {
        if(state)
            set_bss_state_wps_supported(&radio_data->bss_state);
        else
            set_bss_state_wps_unsupported(&radio_data->bss_state);
    }
    else
    {
        platform_log(MAP_LIBRARY,LOG_ERR,"WPS state get failed \n");
    }

    /* Notify event to main thread */
    if(map_notify_main_thread(&monitor_evt)) {
        platform_log(MAP_LIBRARY,LOG_ERR,"MAP_MONITOR_WIRELESS_SSID_RADIO_EVT event notification failed \n");
        goto CLEANUP;
    }

    // Return of successfull notification case
    return;

CLEANUP:
    if (NULL != radio_data)
        free(radio_data);
    return;
}

static void map_monitor_network_link_event_callback(void *ctx, void *ev, const char *type, struct blob_attr *msg)
{
    map_monitor_evt_t monitor_evt;
    map_network_link_evt_data *network_evt_data = NULL;
    struct blob_attr *c                 = NULL;
    struct blob_attr *data              = blob_data(msg);
    const char *if_name                 = NULL;
    char *status_str                    = NULL;
	int8_t is_new_wds                   = 0;
    int rem                             = blob_len(msg);

    platform_log(MAP_LIBRARY,LOG_DEBUG,"%s event call back for %s \n", __FUNCTION__, type);

    monitor_evt.evt = MAP_MONITOR_WIRED_LINK_EVENT;
    monitor_evt.evt_data = NULL;

    network_evt_data = (map_network_link_evt_data*) calloc(1,sizeof(map_network_link_evt_data));
    if (NULL == network_evt_data) {
        platform_log(MAP_LIBRARY,LOG_ERR,"%s memory allocation failed for status\n", __FUNCTION__);
        goto CLEANUP;
    }

    __blob_for_each_attr(c, data, rem) {
        if (strcmp(blobmsg_name(c), "interface") == 0) {
            if_name = blobmsg_get_string(c);
        }
        else if (strcmp(blobmsg_name(c), "action") == 0) {
            status_str = blobmsg_get_string(c);
        }
    }

    if (NULL == if_name || NULL == status_str) {
         platform_log(MAP_LIBRARY,LOG_ERR,"%s Attributes missing from the obtained blobmsg\n", __FUNCTION__);
         goto CLEANUP;
    }

    strncpy(network_evt_data->if_name,if_name,sizeof(network_evt_data->if_name)-1);
    strncpy(network_evt_data->status,status_str,sizeof(network_evt_data->status)-1);
       
    platform_log(MAP_LIBRARY,LOG_DEBUG,"%s interface %s status %s\n", __FUNCTION__, if_name, status_str);
    /* wds interface created/up/down collect data and cache it */
    if(NULL != strstr(if_name, WDS_IF_NAME_PREFIX)) {           
        if(0 != platform_if_info_wds_if_info_update(ctx, if_name, &is_new_wds, status_str)) {
            platform_log(MAP_LIBRARY,LOG_ERR,"%s Failed to update wds if info %s\n", __FUNCTION__, if_name);
            goto CLEANUP;
        }
        /* new wds interface created */
        if(is_new_wds) {
            strncpy(network_evt_data->status,"new",sizeof(network_evt_data->status));
            platform_log(MAP_LIBRARY,LOG_DEBUG,"%s New wds interface %s identified\n", __FUNCTION__, if_name);
        }             
    } else {
        platform_log(MAP_LIBRARY,LOG_DEBUG,"%s not a wds interface, %s status %s\n", __FUNCTION__, if_name, status_str);
        if(platform_if_info_wired_if_state_update(ctx, if_name)) {
            platform_log(MAP_LIBRARY,LOG_ERR,"%s failed to update cached interface info data for %s\n", __FUNCTION__, if_name);
        }
    }
        
    monitor_evt.evt_data = (void *)network_evt_data;
    if(map_notify_main_thread(&monitor_evt)) {
        platform_log(MAP_LIBRARY,LOG_ERR,"%s event notification failed \n", __FUNCTION__);
        goto CLEANUP;
    }

    // Retrun of successfull event notification
    return;

CLEANUP:
    if (NULL != network_evt_data)
        free(network_evt_data);

    return;
}

int map_str_to_hex(char *out_data, char *in_str,  int len )
{
    int i, j;

    for (i=0; i<len; i++) {
        out_data[i] = 0;
        for (j=0; j<2; j++) {
            int c = in_str[2*i+j];
            out_data[i] <<= 4;

            if (c>='0' && c<='9') {
                out_data[i] += c - '0';
            } else if (c>='a' && c<='f') {
                out_data[i] += c - 'a' + 10;
            } else if (c>='A' && c<='F') {
                out_data[i] += c - 'A' + 10;
            } else {
                return -1;
            }
        }
    }
    return 0;

}

int compare_bcon_objs(void *obj, void* sta_mac)
{
    bcn_rprt_timeout_data_t     *sta_node_bcon_list = (bcn_rprt_timeout_data_t     *)obj;
    return !memcmp(sta_mac, sta_node_bcon_list->sta_mac, 6);
}

static void map_monitor_beacon_metrics_event_callback(void *ctx, void *ev, const char *type, struct blob_attr *msg)
{
    struct blob_attr *c                 = NULL;
    struct blob_attr *data              = blob_data(msg);
    int rem                             = blob_len(msg);
    uint8_t  beacon_metrics_completed   = 0;
    uint8_t  valid_sta_mac              = 0;
    char * tmp_str                      = NULL;
    int req_body_len = 0;
    int tmp_str_len = 0;
    uint8_t sta_macaddr[MAC_ADDR_LEN] = {0};

    bcn_rprt_timeout_data_t     *sta_node_bcon_list  = NULL;
    map_beacon_report_element_t *individual_report_element = NULL;

    platform_log(MAP_LIBRARY,LOG_DEBUG,"%s event call back for %s \n", __FUNCTION__, type);
    
    __blob_for_each_attr(c, data, rem)
    {
        if (strcmp(blobmsg_name(c), "event") == 0) {
            if (strcmp(blobmsg_get_string(c), "completed") == 0 ||
                    strcmp(blobmsg_get_string(c), "timeout"  ) == 0) {
                beacon_metrics_completed = 1;
            }
        
        } else if (strcmp(blobmsg_name(c), "macaddr") == 0) {
            
            if (!platform_get_mac_from_string(blobmsg_get_string(c), sta_macaddr)) {
                platform_log(MAP_LIBRARY,LOG_ERR, "%s: Invalid MAC\n", __func__);
                goto cleanup;
            }

            sta_node_bcon_list = find_object(g_beacon_metric_response_pend_list, (void*)sta_macaddr, compare_bcon_objs);

            if (sta_node_bcon_list == NULL) 
                goto cleanup;
                /* 
                 * If sta mac is not available in report pending list, 
                 * then report is already sent because of timeout and 
                 * subsequent reponses for that sta mac can be discarded 
                 */
            valid_sta_mac = 1;

        } else if ((strcmp(blobmsg_name(c), "body") == 0) && beacon_metrics_completed != 1) {
            individual_report_element = (map_beacon_report_element_t *)calloc(1,sizeof(map_beacon_report_element_t));
            if (individual_report_element == NULL) {
                goto cleanup;
            }
            /* 
             * read 31 hex octets(before start of subelement) and 
             * convert the data into beacon report, 
             * As 2 characters of a string comprise to form a single hex octet, 
             * read 2*31 chars ie 62 characters from the string, 
             * organise it into beacon report and then fill it in the beacon report 
             */

            req_body_len = sizeof(map_beacon_report_element_t);
            tmp_str      = blobmsg_get_string(c);
            tmp_str_len  = strlen(tmp_str);

            if(map_str_to_hex((char *)individual_report_element, tmp_str, (tmp_str_len/2 < req_body_len) ? tmp_str_len/2 : req_body_len) < 0) {
                platform_log(MAP_LIBRARY,LOG_ERR,"%s: Failed converting hex stream to string\n", __func__);
                goto cleanup;
            }

            sta_node_bcon_list = find_object(g_beacon_metric_response_pend_list, (void*)sta_macaddr, compare_bcon_objs);

            if (sta_node_bcon_list == NULL) { 
                platform_log(MAP_LIBRARY,LOG_ERR,"%s: No such sta registered for beacon mertics\n", __func__);
                goto cleanup;
            }

            if(insert_last_object(sta_node_bcon_list->bcon_rprt_list, (void*)individual_report_element) == -1) {
                platform_log(MAP_LIBRARY,LOG_ERR,"%s: Failed adding beacon metric report element to list\n", __func__);
                goto cleanup;
            }
        }
    }

    if(valid_sta_mac && beacon_metrics_completed)
        map_pltfrm_send_gathered_beacon_metric_report(sta_macaddr);

    return;

cleanup:

    if(individual_report_element != NULL) {
        free(individual_report_element);
    }

    return;
}


uint8_t add_sta_to_bcon_pend_list(uint8_t *sta_mac) 
{
    int                     ret                 = 0;
    bcn_rprt_timeout_data_t *sta_node_bcon_list = NULL;

    if (g_beacon_metric_response_pend_list == NULL) {
        g_beacon_metric_response_pend_list = new_array_list(eListTypeDefault);
    
        if(g_beacon_metric_response_pend_list == NULL) {
            platform_log(MAP_LIBRARY,LOG_ERR, "%s: beacon metric response pending list creation failed\n",__func__);
            ret = -EINVAL;
            goto Failure;
        }
    }

    sta_node_bcon_list = find_object(g_beacon_metric_response_pend_list, (void*)sta_mac, compare_bcon_objs);

     if(sta_node_bcon_list == NULL) {
         sta_node_bcon_list = (bcn_rprt_timeout_data_t *) calloc(1, sizeof(bcn_rprt_timeout_data_t));
         if(sta_node_bcon_list == NULL) {
             platform_log(MAP_LIBRARY,LOG_ERR, "%s: beacon report timeout data struct allocation failed\n", __func__);
             ret = -1;
             goto Failure;
         }
         sta_node_bcon_list->bcon_rprt_list = new_array_list(eListTypeDefault);
     } else {
         /* 
          * If sta node is already present in 
          * g_beacon_metric_response_pend_list, we should clean all its 
          * bcon_rprts and reuse the same.
          */
         while (list_get_size(sta_node_bcon_list->bcon_rprt_list))
             free(remove_last_object(sta_node_bcon_list->bcon_rprt_list)); 
     }
     memcpy(sta_node_bcon_list->sta_mac, sta_mac, MAC_ADDR_LEN);

    /* 
     * Add the sta entry to the g_beacon_metric_response_pend_list
     */

     if(insert_last_object(g_beacon_metric_response_pend_list, (void*)sta_node_bcon_list) == -1) {
         platform_log(MAP_LIBRARY,LOG_ERR,"%s: Failed adding beacon report timeout data list\n", __func__);
         ret = -1;
     }

Failure:
     return ret;
}


uint8_t map_pltfrm_send_gathered_beacon_metric_report(uint8_t * sta_mac) {
    bcn_rprt_timeout_data_t    *sta_node_bcon_list  = NULL;
    int ret = 0;

    platform_log(MAP_LIBRARY,LOG_DEBUG,"%s\n", __func__);

    sta_node_bcon_list = find_object(g_beacon_metric_response_pend_list, (void*)sta_mac, compare_bcon_objs);
    if (sta_node_bcon_list == NULL) return -1;

    remove_object(g_beacon_metric_response_pend_list, (void*)sta_mac, compare_bcon_objs);

    sta_node_bcon_list->evt      = MAP_MONITOR_BEACON_METRICS_REPORT_EVT;

    if(event_notify_main_thread((void*)plt_hmwr_ctx->monitor_q_hdle, (void*)sta_node_bcon_list))
    {
        platform_log(MAP_LIBRARY,LOG_ERR,"%s event notification failed \n", __FUNCTION__);

        /* 
         *Free sta_node 
         */
        while (list_get_size(sta_node_bcon_list->bcon_rprt_list))
            free(remove_last_object(sta_node_bcon_list->bcon_rprt_list));

        delete_array_list(sta_node_bcon_list->bcon_rprt_list);
        ret = -1;
    }

    return ret;
}

static void map_monitor_unassoc_metrics_event_callback (void *ctx, void *ev, const char *type, struct blob_attr *msg)
{

    struct blob_attr *c                 = NULL;
    struct blob_attr *data              = blob_data(msg);
    int rem                             = blob_len(msg);
    char radio_name[32]                 = {0};
    uint8_t  valid_radio_name           = 0;

    platform_log(MAP_LIBRARY,LOG_DEBUG,"%s event call back for %s \n", __FUNCTION__, type);
    __blob_for_each_attr(c, data, rem)
     {
            if (strcmp(blobmsg_name(c), "name") == 0) {
                strncpy(radio_name, blobmsg_get_string(c), MAX_RADIO_NAME_LEN);
                valid_radio_name = 1;
            } 
     }
	 
     if(valid_radio_name) {
         if(decr_unassoc_pending_cnt(radio_name) == 0) {
             struct unassoc_response *unassoc_response = NULL;
             platform_get_context(MAP_PLATFORM_GET_UNASSOC_REPORT, radio_name, (void *)&unassoc_response, ctx);
             if(unassoc_response != NULL) {
                unassoc_response->type = MAP_MONITOR_SEND_UNASSOC_STA_METRICS_RESPONSE;
                if(event_notify_main_thread((void*)plt_hmwr_ctx->monitor_q_hdle,(void*)unassoc_response)) 
	        {
		     free(unassoc_response);
		     platform_log(MAP_LIBRARY,LOG_ERR,"%s event notification failed \n", __FUNCTION__);
		}
             }
         }
     }
    return;
}

static int map_fill_sta_mac_channel_list(struct blob_attr *list_attr, struct unassoc_sta_dm_s **unassoc_sta_data_m)
{
   struct blob_attr *list_item_attr;
   int               list_rem       = 0;
   int               size           = 0;
   char*             sta            = NULL;
   uint8_t           channel        = 0;
   int               sta_count      = 0;
   int               index          = 0;
   struct unassoc_sta_dm_s *unassoc_sta_dm = NULL;

   if(unassoc_sta_data_m == NULL)
       return -EINVAL;

   *unassoc_sta_data_m = NULL;

   size = blobmsg_check_array(list_attr, BLOBMSG_TYPE_TABLE);
   if(size <= 0)
       return -EINVAL;

   unassoc_sta_dm = calloc(1, sizeof(struct unassoc_sta_dm_s));
   if(unassoc_sta_dm == NULL) {
       return -EINVAL;
   }

   unassoc_sta_dm->channel_list_cnt = (uint8_t)size;

   /* Go over all table entries */
   blobmsg_for_each_attr(list_item_attr, list_attr, list_rem) {
       struct blob_attr *list_item_param_attr;
       struct blob_attr *list_item_param_array_attr;
       int              list_item_rem;
       int              list_array_rem;

       /* Go over all data in item (blobmsg_parse cannot be used again here) */
       blobmsg_for_each_attr(list_item_param_attr, list_item_attr, list_item_rem) {
           if (blobmsg_type(list_item_param_attr)==BLOBMSG_TYPE_INT32 && !strcmp(blobmsg_name(list_item_param_attr), "channel")) {
               channel = blobmsg_get_u32(list_item_param_attr);
               platform_log(MAP_LIBRARY,LOG_ERR, "%s %d, unassocc channel %d\n",__func__, __LINE__, channel);
               unassoc_sta_dm->sta_list[index].channel = channel;
           }

           if (blobmsg_type(list_item_param_attr)==BLOBMSG_TYPE_ARRAY && !strcmp(blobmsg_name(list_item_param_attr), "sta_list")) {
               uint8_t (*sta_mac)[MAC_ADDR_LEN];

               sta_count = blobmsg_check_array(list_item_param_attr, BLOBMSG_TYPE_STRING);
               if (sta_count <= 0) {
                   platform_log(MAP_LIBRARY,LOG_ERR, "%s %d, unassocc Failure\n",__func__, __LINE__);
                   goto Failure;
               }

               /* get length of array */
               unassoc_sta_dm->sta_list[index].sta_count = sta_count;
               unassoc_sta_dm->sta_list[index].sta_mac   = (uint8_t (*)[MAC_ADDR_LEN])calloc(unassoc_sta_dm->sta_list[index].sta_count, MAC_ADDR_LEN);
               if(unassoc_sta_dm->sta_list[index].sta_mac == NULL) {
                   platform_log(MAP_LIBRARY,LOG_ERR, "%s %d, unassocc Failure\n",__func__, __LINE__);
                   goto Failure;
               }

               /* Go over all mac address */
               sta_mac = NULL;
               sta_mac = unassoc_sta_dm->sta_list[index].sta_mac;

               platform_log(MAP_LIBRARY,LOG_ERR, "%s %d, unassocc MAC [\n",__func__, __LINE__);
               blobmsg_for_each_attr(list_item_param_array_attr, list_item_param_attr, list_array_rem) {
                   sta = blobmsg_get_string(list_item_param_array_attr);
                   platform_log(MAP_LIBRARY,LOG_ERR, "%s %d, unassocc sta_mac %s \n",__func__, __LINE__, sta);

                   if(!platform_get_mac_from_string(sta, (uint8_t *)sta_mac)) {
                       platform_log(MAP_LIBRARY,LOG_ERR, "%s %d, unassocc Failure\n",__func__, __LINE__);
                       goto Failure;
                   }
                   sta_mac++;
               }
               platform_log(MAP_LIBRARY,LOG_ERR, "%s %d, unassocc ]\n",__func__, __LINE__);
           }
       }
       channel = 0;
       sta_count = 0;
       index++;
    }

    *unassoc_sta_data_m = unassoc_sta_dm;
    return 0;

Failure:
   if(unassoc_sta_dm != NULL) {
       for (index = 0; index<unassoc_sta_dm->channel_list_cnt; index++) {
          free(unassoc_sta_dm->sta_list[index].sta_mac);
       }
       free(unassoc_sta_dm);
   }

   *unassoc_sta_data_m = NULL; 
   platform_log(MAP_LIBRARY,LOG_ERR, "%s %d, unassocc Failure\n",__func__, __LINE__);
   return -EINVAL;
}

static int map_get_oper_class_channel_list(struct blob_attr *list_attr, struct channel_preference_report **ch_pref_report_ptr)
{
   struct blob_attr *list_item_attr;
   int               list_rem       = 0;
   int               size           = 0;
   int               index          = 0;
   struct channel_preference_report *ch_pref_report = NULL;

   if (ch_pref_report_ptr == NULL || list_attr == NULL)
       return -EINVAL;

   *ch_pref_report_ptr = NULL;

   size = blobmsg_check_array(list_attr, BLOBMSG_TYPE_TABLE);
   if(size <= 0 || size >MAX_OPERATING_CLASS)
       return -EINVAL;

   ch_pref_report = (struct channel_preference_report *)malloc(sizeof(struct channel_preference_report) + (size * sizeof(struct op_class_channel_list)));
   if(ch_pref_report == NULL) {
       return -EINVAL;
   }

   ch_pref_report->numOperating_class = (uint8_t)size;

   /* Go over all table entries */
   blobmsg_for_each_attr(list_item_attr, list_attr, list_rem) {
       struct blob_attr *list_item_param_attr;
       struct blob_attr *list_item_param_array_attr;
       int              list_item_rem;
       int              list_array_rem;
       uint8_t          is_op_class_present;
       uint8_t          is_pref_present;
       uint8_t          is_chan_list_present;

       is_op_class_present  = 0;
       is_pref_present      = 0;
       is_chan_list_present = 0;

       /* Go over all data in item (blobmsg_parse cannot be used again here) */
       blobmsg_for_each_attr(list_item_param_attr, list_item_attr, list_item_rem) {

           if (blobmsg_type(list_item_param_attr)==BLOBMSG_TYPE_INT32 && !strcmp(blobmsg_name(list_item_param_attr), "opclass")) {
              uint8_t           opclass        = 0;

              opclass = blobmsg_get_u32(list_item_param_attr);
              ch_pref_report->operating_class[index].operating_class = opclass;
              is_op_class_present  = 1;
           }

           if (blobmsg_type(list_item_param_attr)==BLOBMSG_TYPE_INT32 && !strcmp(blobmsg_name(list_item_param_attr), "preference")) {
              uint8_t pref_reason = 0;
              pref_reason = (uint8_t) blobmsg_get_u32(list_item_param_attr);
              ch_pref_report->operating_class[index].pref_reason = pref_reason;
              is_pref_present      = 1;
           }

           if (blobmsg_type(list_item_param_attr)==BLOBMSG_TYPE_ARRAY && !strcmp(blobmsg_name(list_item_param_attr), "chanlist")) {
                uint8_t j             = 0;
                int     ch_count      = 0;
                uint8_t ch            = 0;

               j = 0;
               ch_count = blobmsg_check_array(list_item_param_attr, BLOBMSG_TYPE_INT32);
               if (ch_count < 0 || ch_count > MAX_ELEMENTS_IN_JSON_ARRAY) {
                   platform_log(MAP_LIBRARY,LOG_ERR, "%s %d, channel pref response Failure\n",__func__, __LINE__);
                   goto Failure;
               }

               is_chan_list_present = 1;
               ch_pref_report->operating_class[index].number_of_channels = ch_count;

               blobmsg_for_each_attr(list_item_param_array_attr, list_item_param_attr, list_array_rem) {

                   ch = (uint8_t)blobmsg_get_u32(list_item_param_array_attr);
                   ch_pref_report->operating_class[index].channel_num[j] = ch;
                   j++;
               }
           }
       }

       if (!is_op_class_present  || 
           !is_pref_present      ||
           !is_chan_list_present ) {
           goto Failure; 
       }
       index++;
    }

    *ch_pref_report_ptr = ch_pref_report;
    return 0;

Failure:
    free(ch_pref_report);

   *ch_pref_report_ptr = NULL; 
   return -EINVAL;
}


static int map_monitor_cli_send_channel_pref_report_callback(void *ctx, void *obj, void *req, const char *method, struct blob_attr *msg)
{
    struct blob_buf buff = {};
    struct blob_attr *tb[MAP_AGENT_CHANNEL_PREF_REPORT_MAX];

    struct channel_preference_report *monitor_evt  = NULL;


    blobmsg_parse(send_channel_pref_report, MAP_AGENT_CHANNEL_PREF_REPORT_MAX, tb, blob_data(msg), blob_len(msg));

    if ((!tb[MAP_AGENT_CHANNEL_PREF_REPORT_ALMAC]) || (!tb[MAP_AGENT_CHANNEL_PREF_REPORT_RADID])  
           || (!tb[MAP_AGENT_CHANNEL_PREF_REPORT_OPCLASSLIST])) {
           platform_log(MAP_LIBRARY,LOG_ERR, "%s : %d Input Parameters Missing\n", __FUNCTION__, __LINE__);
           return PLATFORM_UBUS_STATUS_INVALID_ARGUMENT;
    }



    if (map_get_oper_class_channel_list(tb[MAP_AGENT_CHANNEL_PREF_REPORT_OPCLASSLIST], &monitor_evt) < 0) {
        platform_log(MAP_LIBRARY,LOG_ERR, "%s %d, ubus failure to decode target_list in unassoc sta metrics \n",__func__, __LINE__);
        goto Failure;
    }

    if(monitor_evt == NULL) 
        goto Failure;

    if(!platform_get_mac_from_string(blobmsg_get_string(tb[MAP_AGENT_CHANNEL_PREF_REPORT_ALMAC]), monitor_evt->al_mac)) {
        platform_log(MAP_LIBRARY,LOG_ERR, "%s %d, ubus failure to decode al_mac in unassoc sta metrics \n",__func__, __LINE__);
        goto Failure;
    }

    if(!platform_get_mac_from_string(blobmsg_get_string(tb[MAP_AGENT_CHANNEL_PREF_REPORT_RADID]), monitor_evt->radio_id)) {
        platform_log(MAP_LIBRARY,LOG_ERR, "%s %d, ubus failure to decode al_mac in unassoc sta metrics \n",__func__, __LINE__);
        goto Failure;
    }

    monitor_evt->type = MAP_MONITOR_SEND_CHANNEL_PREF_REPORT;
    monitor_evt->async_status_response = 0;
    if (!plt_hmwr_ctx->cli_pending_response) monitor_evt->async_status_response = 1;
    /* Notify event to main thread */
    if(event_notify_main_thread((void*)plt_hmwr_ctx->monitor_q_hdle,(void*)monitor_evt) < 0) {
         platform_log(MAP_LIBRARY,LOG_ERR,"%s event notification failed \n", __FUNCTION__);
         goto Failure;
     }

    defer_cli(ctx, req);
    return PLATFORM_UBUS_STATUS_OK;
Failure:
    blob_buf_init (&buff, 0);
    blobmsg_add_string (&buff, "Status", "Failure");
    blobmsg_add_u32(&buff,"Mtype:",0);
    blobmsg_add_u32(&buff,"Mid:",0);
    platform_send_reply(ctx, req, buff.head);
    platform_log(MAP_LIBRARY,LOG_ERR, "%s : %d -- Param Incorrect\n", __FUNCTION__, __LINE__);

    /* Free the allocated memory if, any */
    if(monitor_evt != NULL) {
         free(monitor_evt);
     }

    blob_buf_free(&buff);
    return -1;
}



static int map_monitor_cli_unassoc_sta_metric_query_callback(void *ctx, void *obj, void *req, const char *method, struct blob_attr *msg)
{
    struct blob_buf buff = {};
    struct blob_attr *tb[MAP_CTRL_UNASSOC_STA_METRICS_MAX];
    struct unassoc_sta_dm_s *monitor_evt  = NULL;

    blobmsg_parse(send_unassoc_sta_metrics_query, MAP_CTRL_UNASSOC_STA_METRICS_MAX, tb, blob_data(msg), blob_len(msg));

    if ((!tb[MAP_CTRL_UNASSOC_STA_DST_ALMAC]) || (!tb[MAP_CTRL_UNASSOC_STA_OPER_CLASS])  
           || (!tb[MAP_CTRL_UNASSOC_STA_TARGET_LIST])) {
           platform_log(MAP_LIBRARY,LOG_ERR, "%s : %d Input Parameters Missing\n", __FUNCTION__, __LINE__);
           goto Failure;
    }



    if (map_fill_sta_mac_channel_list(tb[MAP_CTRL_UNASSOC_STA_TARGET_LIST], &monitor_evt) < 0) {
        platform_log(MAP_LIBRARY,LOG_ERR, "%s %d, ubus failure to decode target_list in unassoc sta metrics \n",__func__, __LINE__);
        goto Failure;
    }


    monitor_evt->oper_class = (uint8_t )blobmsg_get_u32(tb[MAP_CTRL_UNASSOC_STA_OPER_CLASS]);

    if(!platform_get_mac_from_string(blobmsg_get_string(tb[MAP_CTRL_UNASSOC_STA_DST_ALMAC]), monitor_evt->al_mac)) {
        platform_log(MAP_LIBRARY,LOG_ERR, "%s %d, ubus failure to decode al_mac in unassoc sta metrics \n",__func__, __LINE__);
        goto Failure;
    }

    monitor_evt->type = MAP_MONITOR_SEND_UNASSOC_STA_METRICS_QUERY;
    monitor_evt->async_status_response = 0;
    if (!plt_hmwr_ctx->cli_pending_response) monitor_evt->async_status_response = 1;
    /* Notify event to main thread */
    if(event_notify_main_thread((void*)plt_hmwr_ctx->monitor_q_hdle,(void*)monitor_evt) < 0) {
         platform_log(MAP_LIBRARY,LOG_ERR,"%s event notification failed \n", __FUNCTION__);
         goto Failure;
     }

    defer_cli(ctx, req);

    return PLATFORM_UBUS_STATUS_OK;

Failure:
    blob_buf_init (&buff, 0);
    blobmsg_add_string (&buff, "Status", "Failure");
    blobmsg_add_u32(&buff,"Mtype:",0);
    blobmsg_add_u32(&buff,"Mid:",0);
    platform_send_reply(ctx, req, buff.head);
    platform_log(MAP_LIBRARY,LOG_ERR, "%s : %d -- Param Incorrect\n", __FUNCTION__, __LINE__);

    /* Free the allocated memory if, any */
    if(monitor_evt != NULL) {
         for (int index = 0; index < monitor_evt->channel_list_cnt; index++) {
             free(monitor_evt->sta_list[index].sta_mac);
         }
         free(monitor_evt);
     }

    blob_buf_free(&buff);
    return -1;
}

static int map_monitor_cli_assoc_sta_metric_query_callback(void *ctx, void *obj, void *req, const char *method, struct blob_attr *msg)
{
    struct blob_buf buff = {};
    const char * err_str = NULL;
    struct blob_attr *tb[MAP_TARGET_MAC];
    char* tmp_str;
    uint8_t *mac = NULL;
    map_monitor_evt_t *monitor_evt = NULL;

    monitor_evt = (map_monitor_evt_t*) calloc(1, sizeof(map_monitor_evt_t));
    if(NULL != monitor_evt) {

        mac = (uint8_t *) calloc (MAC_ADDR_LEN, sizeof(uint8_t));
        if (NULL == mac) {
            platform_log(MAP_LIBRARY,LOG_ERR,"%s Mac addr memory allocation failed \n", __FUNCTION__);
            goto Failure;
        }
        monitor_evt->evt = MAP_MONITOR_SEND_ASSOC_STA_METRIC_QUERY;

        blobmsg_parse(send_query, ARRAY_SIZE(send_query), tb, blob_data(msg), blob_len(msg));

        tmp_str = blobmsg_get_string(tb[MAP_TARGET_MAC]);
        if(NULL == tmp_str) {
            err_str = "AGENT MAC";
            goto Failure;
        }

        if(0 == platform_get_mac_from_string(tmp_str,mac))
            goto Failure;

        monitor_evt->evt_data = (void *)mac;
        monitor_evt->async_status_response = 0;
        if (!plt_hmwr_ctx->cli_pending_response) monitor_evt->async_status_response = 1;
        /* Notify event to main thread */
        if(event_notify_main_thread((void*)plt_hmwr_ctx->monitor_q_hdle,(void*)monitor_evt))
        {
            platform_log(MAP_LIBRARY,LOG_ERR,"%s event notification failed \n", __FUNCTION__);
            free(monitor_evt);
            free(mac);
        }
    }
    else {
        platform_log(MAP_LIBRARY,LOG_ERR,"%s memory allocation failed \n", __FUNCTION__);
        goto Failure;
    }

    defer_cli(ctx, req);
    return PLATFORM_UBUS_STATUS_OK;

Failure:
    if (mac != NULL)
        free(mac);

    if (monitor_evt != NULL)
        free(monitor_evt);

    blob_buf_init (&buff, 0);
    blobmsg_add_string (&buff, "Status", "Failure");
    blobmsg_add_u32(&buff,"Mtype:",0);
    blobmsg_add_u32(&buff,"Mid:",0);
    platform_send_reply(ctx, req, buff.head);
    platform_log(MAP_LIBRARY,LOG_ERR, "%s : %d -- %s Param Incorrect\n", __FUNCTION__, __LINE__,err_str);
    blob_buf_free(&buff);

	return -1;
}


static int map_monitor_cli_sendtq_callback(void *ctx, void *obj, void *req, const char *method, struct blob_attr *msg)
{

	struct blob_attr *tb[MAP_TARGET_MAX];
        struct blob_buf buff = {};
	char* tmp_str;
	char dbg_msg[64] = {0};


	blobmsg_parse(send_query, ARRAY_SIZE(send_query), tb, blob_data(msg), blob_len(msg));
        if (!tb[MAP_TARGET_MAC]) {
              platform_log(MAP_LIBRARY,LOG_ERR, "%s : %d Input Parameters Missing\n", __FUNCTION__, __LINE__);
              return PLATFORM_UBUS_STATUS_INVALID_ARGUMENT;
        }

	tmp_str = blobmsg_get_string(tb[MAP_TARGET_MAC]);

	snprintf(dbg_msg, ARRAY_SIZE(dbg_msg)-1, "%s", tmp_str);
	platform_log(MAP_LIBRARY,LOG_DEBUG,"%s : %d ubus object call back, parameter %s\n", __FUNCTION__, __LINE__, dbg_msg);
        /* 
         * send TQ 
         */
        map_monitor_evt_t *monitor_evt = NULL;
        uint8_t           *target_al_mac = NULL;

        monitor_evt = (map_monitor_evt_t*) calloc(1, sizeof(map_monitor_evt_t));
        if(NULL != monitor_evt) {

            target_al_mac = (uint8_t *) calloc (MAC_ADDR_LEN, sizeof(uint8_t));
	    if (NULL == target_al_mac) {
	        platform_log(MAP_LIBRARY,LOG_ERR,"%s Mac addr memory allocation failed \n", __FUNCTION__);
                goto Failure;
            }

            monitor_evt->evt = MAP_MONITOR_SEND_TOPOLOGY_QUERY;
            monitor_evt->async_status_response = 0;
            if (!plt_hmwr_ctx->cli_pending_response) monitor_evt->async_status_response = 1;

            if(0 == platform_get_mac_from_string(tmp_str, target_al_mac))
                goto Failure;

            monitor_evt->evt_data = (void *)target_al_mac;

            /* Notify event to main thread */
            if(event_notify_main_thread((void*)plt_hmwr_ctx->monitor_q_hdle,(void*)monitor_evt)) 
            {
                platform_log(MAP_LIBRARY,LOG_ERR,"%s event notification failed \n", __FUNCTION__);
                goto Failure;
            }
        }
        else {
            platform_log(MAP_LIBRARY,LOG_ERR,"%s memory allocation failed \n", __FUNCTION__);
            goto Failure;
        }

        defer_cli(ctx, req);
        return PLATFORM_UBUS_STATUS_OK;

Failure:
       blob_buf_init (&buff, 0);
       blobmsg_add_string (&buff, "Status", "Failure");
       blobmsg_add_u32(&buff,"Mtype:",0);
       blobmsg_add_u32(&buff,"Mid:",0);
       platform_send_reply(ctx, req, buff.head);

       blob_buf_free(&buff);
       free(monitor_evt);
       free(target_al_mac);
	
       return 0;
}

static int map_monitor_cli_link_metric_query_callback(void *ctx, void *obj, void *req, const char *method, struct blob_attr *msg)
{
        struct blob_buf buff = {};
        const char * err_str = NULL;
        struct blob_attr *tb[MAP_CTRL_LINK_METRIC_MAX];
        char* tmp_str;
        char dbg_msg[64] = {0};
        map_monitor_evt_t *monitor_evt = NULL;
        link_metric_query_t *lm_query = NULL;


        blobmsg_parse(send_link_metric_query, ARRAY_SIZE(send_link_metric_query), tb, blob_data(msg), blob_len(msg));

    	if ((!tb[MAP_CTRL_LINK_METRIC_AL_MAC]) || (!tb[MAP_CTRL_LINK_METRIC_METRIC_REQ])  
         		|| (!tb[MAP_CTRL_LINK_METRIC_SPECIFIC_NEIGHBOR])) {
           	platform_log(MAP_LIBRARY,LOG_ERR, "%s : %d Input Parameters Missing\n", __FUNCTION__, __LINE__);
                goto Failure;
    	}

        monitor_evt = (map_monitor_evt_t*)calloc(1,sizeof(map_monitor_evt_t));
        lm_query = (link_metric_query_t *)calloc(1,sizeof(link_metric_query_t));

        platform_log(MAP_LIBRARY,LOG_DEBUG,"%s \n", __FUNCTION__);
        if(NULL != monitor_evt && NULL != lm_query)
        {
            tmp_str = blobmsg_get_string(tb[MAP_CTRL_LINK_METRIC_AL_MAC]);
            if(NULL == tmp_str) {
                err_str = "AL MAC";
                goto Failure;
            }
            snprintf(dbg_msg, ARRAY_SIZE(dbg_msg)-1, "%s", tmp_str);

            if(0 == platform_get_mac_from_string(tmp_str,lm_query->al_mac))
                goto Failure;

            lm_query->metric_req = blobmsg_get_u32(tb[MAP_CTRL_LINK_METRIC_METRIC_REQ]);
            if(!(lm_query->metric_req == MAP_TX_LINK_METRICS_ONLY || lm_query->metric_req == MAP_RX_LINK_METRICS_ONLY || lm_query->metric_req == MAP_BOTH_TX_AND_RX_LINK_METRICS))
            {
                platform_log(MAP_LIBRARY,LOG_ERR,"%s Invalid Metric type requested \n", __FUNCTION__);
                goto Failure;
            }

            lm_query->specific_neighbor = blobmsg_get_u32(tb[MAP_CTRL_LINK_METRIC_SPECIFIC_NEIGHBOR]);
            if(lm_query->specific_neighbor == MAP_LINK_METRIC_QUERY_TLV_SPECIFIC_NEIGHBOR)
            {
                tmp_str = blobmsg_get_string(tb[MAP_CTRL_LINK_METRIC_NEIGHBOR_MAC]);
                if(NULL == tmp_str) {
                    err_str = "NEIGHBOR MAC";
                    goto Failure;
                }
                snprintf(dbg_msg, ARRAY_SIZE(dbg_msg)-1, "%s", tmp_str);

                if(0 == platform_get_mac_from_string(tmp_str,lm_query->neighbor_mac))
                    goto Failure;
            }
            else if (lm_query->specific_neighbor > 1)
            	goto Failure;

            monitor_evt->evt = MAP_MONITOR_SEND_LINK_METRIC_QUERY;
            monitor_evt->evt_data = (link_metric_query_t *)lm_query;
            monitor_evt->async_status_response = 0;
            if (!plt_hmwr_ctx->cli_pending_response) monitor_evt->async_status_response = 1;
            /* Notify event to main thread */
             if(event_notify_main_thread((void*)plt_hmwr_ctx->monitor_q_hdle,(void*)monitor_evt))
             {
                 free(lm_query);
                 free(monitor_evt);
                 platform_log(MAP_LIBRARY,LOG_ERR,"%s event notification failed \n", __FUNCTION__);
             }
        }
       else
        {
            platform_log(MAP_LIBRARY,LOG_ERR,"%s memory allocation failed \n", __FUNCTION__);
            goto Failure;
        }

        defer_cli(ctx, req);
        return PLATFORM_UBUS_STATUS_OK;

Failure:
        if (monitor_evt != NULL)
           free(monitor_evt);
        if (lm_query != NULL)
           free(lm_query);

        blob_buf_init (&buff, 0);
        blobmsg_add_string (&buff, "Status", "Failure");
        blobmsg_add_u32(&buff,"Mtype:",0);
        blobmsg_add_u32(&buff,"Mid:",0);
        platform_send_reply(ctx, req, buff.head);
        platform_log(MAP_LIBRARY,LOG_ERR, "%s : %d -- %s Param Incorrect", __FUNCTION__, __LINE__,err_str);
        blob_buf_free(&buff);
        return -1;
}

static int map_fill_bssid_list(struct blob_attr *list_attr, ap_metric_query_t *ap_query)
{
    char* tmp_str;
    uint8_t i = 0;
    int list_attr_size = 0;
    struct blob_attr *list_array_attr;

    if(ap_query == NULL)
       return -EINVAL;

    blobmsg_for_each_attr(list_array_attr, list_attr, list_attr_size) {
        tmp_str = blobmsg_get_string(list_array_attr);
        if(NULL != tmp_str) {
            if(0 == platform_get_mac_from_string(tmp_str,ap_query->bss_list[i++].mac))
                return -1;
        }
        else
        {
            platform_log(MAP_LIBRARY,LOG_ERR, "%s : %d tmp_str is NULL\n", __FUNCTION__, __LINE__);
           return -1;
        }
    }

    return 0;
}

static int map_monitor_cli_ap_metric_query_callback(void *ctx, void *obj, void *req, const char *method, struct blob_attr *msg)
{
    struct blob_buf buff = {};
    const char * err_str = NULL;
    char* tmp_str;
    uint8_t len                   = 0;
    uint8_t bss_count              = 0;
    uint8_t size = 0;
    struct blob_attr *tb[MAP_CTRL_AP_METRIC_MAX];
    map_monitor_evt_t *monitor_evt = NULL;
    ap_metric_query_t *ap_query    = NULL;

    blobmsg_parse(send_ap_metric_query, MAP_CTRL_AP_METRIC_MAX, tb, blob_data(msg), blob_len(msg));

    if ((!tb[MAP_CTRL_AP_METRIC_AL_MAC]) || (!tb[MAP_CTRL_AP_METRIC_BSS_COUNT])
          || (!tb[MAP_CTRL_AP_METRIC_BSSID_LIST])) {
       platform_log(MAP_LIBRARY,LOG_ERR, "%s : %d Input Parameters Missing\n", __FUNCTION__, __LINE__);
        err_str = "PARAMETER MISSING";
       goto Failure;
    }

    bss_count = (uint8_t )blobmsg_get_u32(tb[MAP_CTRL_AP_METRIC_BSS_COUNT]);

   if (bss_count <= 0 || bss_count > MAX_BSSID_PER_AP_METRICS_QUERY)
   {
        platform_log(MAP_LIBRARY,LOG_ERR, "Invalid bss count");
      err_str = "BSS COUNT";
        goto Failure;
    }

   size = blobmsg_check_array(tb[MAP_CTRL_AP_METRIC_BSSID_LIST], BLOBMSG_TYPE_STRING);
   if(size != bss_count)
  {
        err_str = "COUNT MISMATCH WITH BSSID LIST";
        goto Failure;
   }

    len = sizeof(ap_metric_query_t) + (bss_count *  sizeof(mac_struct_t));
    ap_query = (ap_metric_query_t *) calloc (1, len);

    if (NULL == ap_query)
    {
        platform_log(MAP_LIBRARY,LOG_ERR,"Calloc Failed for ap_query");
        goto Failure;
   }

    ap_query->bss_cnt = bss_count;

    tmp_str = blobmsg_get_string(tb[MAP_CTRL_AP_METRIC_AL_MAC]);
    if(NULL == tmp_str) {
        err_str = "AL MAC";
        goto Failure;
    }

    if(0 == platform_get_mac_from_string(tmp_str,ap_query->al_mac))
        goto Failure;

    if (map_fill_bssid_list(tb[MAP_CTRL_AP_METRIC_BSSID_LIST], ap_query) < 0) {
        platform_log(MAP_LIBRARY,LOG_ERR, "%s %d, ubus failure to decode bssid list in ap metrics query \n",__func__, __LINE__);
        err_str = "BSSID LIST";
        goto Failure;
    }

    monitor_evt = (map_monitor_evt_t*)calloc(1,sizeof(map_monitor_evt_t));
    if(NULL == monitor_evt)
    {
        platform_log(MAP_LIBRARY,LOG_ERR,"%s Memory allocation failed \n", __FUNCTION__);
        goto Failure;
    }

    monitor_evt->evt = MAP_MONITOR_SEND_AP_METRIC_QUERY;
    monitor_evt->evt_data = (void *)ap_query;
    monitor_evt->async_status_response = 0;
    if (!plt_hmwr_ctx->cli_pending_response) monitor_evt->async_status_response = 1;
    /* Notify event to main thread */
    if(event_notify_main_thread((void*)plt_hmwr_ctx->monitor_q_hdle,(void*)monitor_evt) < 0) {
         platform_log(MAP_LIBRARY,LOG_ERR,"%s event notification failed \n", __FUNCTION__);
         goto Failure;
     }

    defer_cli(ctx, req);

    return PLATFORM_UBUS_STATUS_OK;

Failure:
        if (ap_query != NULL)
            free(ap_query);

        if (monitor_evt != NULL)
            free(monitor_evt);

        blob_buf_init (&buff, 0);
        blobmsg_add_string (&buff, "Status", "Failure");
        blobmsg_add_u32(&buff,"Mtype:",0);
        blobmsg_add_u32(&buff,"Mid:",0);
        platform_send_reply(ctx, req, buff.head);
        platform_log(MAP_LIBRARY,LOG_ERR, "%s : %d -- %s Param Incorrect\n", __FUNCTION__, __LINE__,err_str);
       blob_buf_free(&buff);

        return -1;
}

static int map_monitor_cli_send_apcap_query_callback(void *ctx, void *obj, void *req, const char *method, struct blob_attr *msg)
{
        struct blob_buf buff = {};
        const char * err_str = NULL;
        struct blob_attr *tb[MAP_TARGET_MAC];
        char* tmp_str;
        uint8_t *mac = NULL;
        map_monitor_evt_t *monitor_evt = NULL;        

        monitor_evt = (map_monitor_evt_t*) malloc(sizeof(map_monitor_evt_t));
        if(NULL != monitor_evt) {
            memset(monitor_evt, 0, sizeof(map_monitor_evt_t));
			mac = (uint8_t *) calloc (MAC_ADDR_LEN, sizeof(uint8_t));
	        if (NULL == mac) {
	            platform_log(MAP_LIBRARY,LOG_ERR,"%s Mac addr memory allocation failed \n", __FUNCTION__);
	            goto Failure;
	        }
            monitor_evt->evt = MAP_MONITOR_SEND_AP_CAPABILITY_QUERY;

            blobmsg_parse(send_query, ARRAY_SIZE(send_query), tb, blob_data(msg), blob_len(msg));
            tmp_str = blobmsg_get_string(tb[MAP_TARGET_MAC]);
            if(NULL == tmp_str) {
                err_str = "AGENT MAC";
                goto Failure;
            }

            if(0 == platform_get_mac_from_string(tmp_str,mac))
                goto Failure;

            monitor_evt->evt_data = (void *)mac;
            monitor_evt->async_status_response = 0;
            if (!plt_hmwr_ctx->cli_pending_response) monitor_evt->async_status_response = 1;
            /* Notify event to main thread */
			if(event_notify_main_thread((void*)plt_hmwr_ctx->monitor_q_hdle,(void*)monitor_evt)) 
			{
				free(monitor_evt);
				free(mac);
				platform_log(MAP_LIBRARY,LOG_ERR,"%s event notification failed \n", __FUNCTION__);
			}
        }
        else {
            platform_log(MAP_LIBRARY,LOG_ERR,"%s memory allocation failed \n", __FUNCTION__);
            goto Failure;
        }

        defer_cli(ctx, req);
        return PLATFORM_UBUS_STATUS_OK;
Failure:
        if (mac != NULL)
            free(mac);

        if (monitor_evt != NULL)
            free(monitor_evt);

        blob_buf_init (&buff, 0);
        blobmsg_add_string (&buff, "Status", "Failure");
        blobmsg_add_u32(&buff,"Mtype:",0);
        blobmsg_add_u32(&buff,"Mid:",0);
        platform_send_reply(ctx, req, buff.head);
        platform_log(MAP_LIBRARY,LOG_ERR, "%s : %d -- %s Param Incorrect\n", __FUNCTION__, __LINE__,err_str);
        blob_buf_free(&buff);

        return -1;
}

static int map_monitor_cli_beacon_metric_query_callback(void *ctx, void *obj, void *req, const char *method, struct blob_attr *msg)
{
    struct blob_buf buff = {};
    const char * err_str = NULL;
    struct blob_attr *tb[MAP_CTRL_BEACON_MAX];
    beacon_metrics_query_t* beacon_req = NULL;
    map_monitor_evt_t *monitor_evt = NULL;
    char* tmp_str;

    int ret = 0;
    int chan_report_list_cnt = 0;
    int list_rem = 0;
    struct blob_attr *list_attr;

    blobmsg_parse(beacon_query, MAP_CTRL_BEACON_MAX, tb, blob_data(msg), blob_len(msg));

    /* Mandatory Parameters */
    if ((!tb[MAP_CTRL_BEACON_ALMAC]) || (!tb[MAP_CTRL_BEACON_STAMAC])){
        platform_log(MAP_LIBRARY,LOG_ERR, "%s : %d Mandatory Input Parameters ALMAC/STAMAC Missing\n", __FUNCTION__, __LINE__);
        goto PARAM_ERR;
    }

    if(tb[MAP_CTRL_BEACON_CHANREPORT]) {
        chan_report_list_cnt = blobmsg_check_array(tb[MAP_CTRL_BEACON_CHANREPORT], BLOBMSG_TYPE_TABLE);
        platform_log(MAP_LIBRARY,LOG_DEBUG, "%s : %d chan report list count - %d\n", __FUNCTION__, __LINE__, chan_report_list_cnt);
    }

    beacon_req = malloc(sizeof(beacon_metrics_query_t) + (sizeof(struct ap_channel_report) * chan_report_list_cnt));

    if(NULL == beacon_req)
    {
        platform_log(MAP_LIBRARY,LOG_ERR, "%s : %dCalloc failed\n", __FUNCTION__, __LINE__);
        goto PARAM_ERR;
    }
    memset(beacon_req, 0, sizeof(beacon_metrics_query_t) + (sizeof(struct ap_channel_report) * chan_report_list_cnt));
    beacon_req->ap_channel_report_count = chan_report_list_cnt;
    /* Traverse through the channel report table */
    struct blob_attr *list_param_attr;
    int list_param_rem = 0;
    int chan_report_table_index = 0;
    int chan_cnt = 0;
    struct blob_attr *list_param_chan_attr;
    int list_param_chan_rem = 0;
    int chan_array_index = 0;
    int table_sequence_validate = 0;
    blobmsg_for_each_attr(list_attr, tb[MAP_CTRL_BEACON_CHANREPORT], list_rem) {

        blobmsg_for_each_attr(list_param_attr, list_attr, list_param_rem) { /* Traverse Array of Table*/
/* First element of Table */
            if (strcmp(blobmsg_name(list_param_attr), "oper_class") == 0) {
                if(table_sequence_validate %2) {
                    err_str = "Channel report array's table arg syntax must be oper_class:<int>, channel:<int array> mandatory";
                    goto PARAM_ERR;
                }
                beacon_req->ap_channel_report[chan_report_table_index].operating_class = blobmsg_get_u32(list_param_attr);
                table_sequence_validate++;
            }
            if (strcmp(blobmsg_name(list_param_attr), "channel") == 0) {
                if (!(table_sequence_validate % 2)) {
                    err_str = "Channel report array's table arg syntax must be oper_class:<int>, channel:<int array> mandatory";
                    goto PARAM_ERR;
                }
                /* Second element of Table: Channel list array */
                table_sequence_validate++;
                chan_cnt = blobmsg_check_array(list_param_attr, BLOBMSG_TYPE_INT32);
                beacon_req->ap_channel_report[chan_report_table_index].length = chan_cnt+1;
                list_param_chan_rem = 0;
                chan_array_index = 0;

                blobmsg_for_each_attr(list_param_chan_attr, list_param_attr, list_param_chan_rem) {
                    /* Parse array of channel list */
                    beacon_req->ap_channel_report[chan_report_table_index].channel_list[chan_array_index] = blobmsg_get_u32(list_param_chan_attr);
                    chan_array_index ++;
                }
                chan_report_table_index ++;
            }
        }
    }
    tmp_str = blobmsg_get_string(tb[MAP_CTRL_BEACON_ALMAC]);
    if (NULL == tmp_str)
    {
        err_str = "AL MAC";
        goto PARAM_ERR;
    }

    ret = platform_get_mac_from_string(tmp_str,beacon_req->dst_mac);
    if(ret == -1)
    {
        platform_log(MAP_LIBRARY,LOG_ERR, "%s : %d - AL MAC is not valid MAC format\n", __FUNCTION__, __LINE__);
        err_str = "AL MAC";
        goto PARAM_ERR;
    }

    tmp_str = blobmsg_get_string(tb[MAP_CTRL_BEACON_STAMAC]);
    if (NULL == tmp_str)
    {
        err_str = "STA MAC";
        goto PARAM_ERR;
    }
    ret = platform_get_mac_from_string(tmp_str,beacon_req->sta_mac);
    if(ret == -1)
    {
        platform_log(MAP_LIBRARY,LOG_ERR, "%s : %d - STA MAC is not valid MAC format\n", __FUNCTION__, __LINE__);
        err_str = "STA MAC";
        goto PARAM_ERR;
    }

    tmp_str = blobmsg_get_string(tb[MAP_CTRL_BEACON_TARGBSSID]);
    if (tmp_str)
    {
        ret = platform_get_mac_from_string(tmp_str,beacon_req->bssid);
        if(ret == -1)
        {
            platform_log(MAP_LIBRARY,LOG_ERR, "%s : %d - TARGET BSSID is not valid MAC format\n", __FUNCTION__, __LINE__);
            err_str = "TARGET BSSID";
            goto PARAM_ERR;
        }
    } else {
        ret = platform_get_mac_from_string("FF:FF:FF:FF:FF:FF",beacon_req->bssid);
    }

    tmp_str = blobmsg_get_string(tb[MAP_CTRL_BEACON_TARGSSID]);
    if (tmp_str)
    {
        strncpy((char *)beacon_req->ssid, tmp_str, strlen(tmp_str) );
        beacon_req->ssid_len = strlen((char *)beacon_req->ssid);
        platform_log(MAP_LIBRARY,LOG_DEBUG, "%s : %d - SSID : %s , ssid len - %d\n", __FUNCTION__, __LINE__, beacon_req->ssid,
                beacon_req->ssid_len);
    }
    if(tb[MAP_CTRL_BEACON_TARGCHAN]) {
        beacon_req->channel = blobmsg_get_u32(tb[MAP_CTRL_BEACON_TARGCHAN]);
        platform_log(MAP_LIBRARY,LOG_DEBUG, "%s : %d: Channel - %d\n", __FUNCTION__, __LINE__, beacon_req->channel);
    }

    if(tb[MAP_CTRL_BEACON_REPORT_DETAIL]) {
        beacon_req->report_detail = blobmsg_get_u32(tb[MAP_CTRL_BEACON_REPORT_DETAIL]);
        platform_log(MAP_LIBRARY,LOG_DEBUG, "%s : %d: reporting_detail - %d\n", __FUNCTION__, __LINE__, beacon_req->report_detail);
    }
    if (!(tb[MAP_CTRL_BEACON_OPER_CLASS]))
    {

        /* If operating class not provided by user, use following assignments, This is derived
           only by checking channel number and not considering other parameters like channel spacing
           and DFS behavior to be analysed for arriving at operating class identification */

        /* reference from hostapd */
        /* rclass: Assumption is 11h not used, use global operating classes */
        /* See 802.11 2012 Annex E, Table E.1 */

        if (beacon_req->channel < 14) {
            beacon_req->operating_class = 81;
        } else if (beacon_req->channel == 14) {
            beacon_req->operating_class = 82;
        } else if (beacon_req->channel < 52) {
            beacon_req->operating_class = 115;
        } else if (beacon_req->channel < 100) {
            beacon_req->operating_class = 118;
        } else if (beacon_req->channel < 149) {
            beacon_req->operating_class = 121;
        } else {
            beacon_req->operating_class = 124;   /* or 125??? */
        }
    } else {
        beacon_req->operating_class = blobmsg_get_u32(tb[MAP_CTRL_BEACON_OPER_CLASS]);
    }
    platform_log(MAP_LIBRARY,LOG_DEBUG, "%s: %d: Operating_class - %d\n", __FUNCTION__, __LINE__, beacon_req->operating_class);

    monitor_evt = (map_monitor_evt_t*) malloc(sizeof(map_monitor_evt_t));
    if(NULL != monitor_evt) {
        memset(monitor_evt, 0, sizeof(map_monitor_evt_t));
        monitor_evt->evt = MAP_MONITOR_BEACON_QUERY_CALL;
        monitor_evt->evt_data = (void*)beacon_req;
        monitor_evt->async_status_response = 0;
        if (!plt_hmwr_ctx->cli_pending_response) monitor_evt->async_status_response = 1;
        /* Notify event to main thread */
        if(event_notify_main_thread((void*)plt_hmwr_ctx->monitor_q_hdle,(void*)monitor_evt))
        {
            platform_log(MAP_LIBRARY,LOG_ERR,"%s event notification failed \n", __FUNCTION__);
            err_str = "Event trigger; Event notification failed";
            goto PARAM_ERR;
        }
    } else {
        platform_log(MAP_LIBRARY,LOG_ERR, "%s : %d memory allocated failed\n", __FUNCTION__, __LINE__);
    }

    defer_cli(ctx, req);

    return PLATFORM_UBUS_STATUS_OK;

PARAM_ERR:
    if (NULL != beacon_req)
    {
        free(beacon_req);
        beacon_req = NULL;
    }
    if (NULL != monitor_evt)
    {
        free(monitor_evt);
        monitor_evt = NULL;
    }
    blob_buf_init (&buff, 0);
    blobmsg_add_string (&buff, "Status", "Failure");
    blobmsg_add_u32(&buff,"Mtype:",0);
    blobmsg_add_u32(&buff,"Mid:",0);
    platform_send_reply(ctx, req, buff.head);
    platform_log(MAP_LIBRARY,LOG_ERR, "%s : %d -- %s Param Incorrect\n", __FUNCTION__, __LINE__,err_str);
    blob_buf_free(&buff);
    return -1;
}

static int map_monitor_cli_sta_steer_callback (void *ctx, void *obj, void *req, const char *method, struct blob_attr *msg)
{
    struct blob_buf buff = {};
    int sta_count = 0;
    const char * err_str = NULL;
    struct blob_attr *tb[MAP_CTRL_STEER_STA_MAX];
    struct blob_attr *list_item = NULL;
    struct sta_steer_params* steer_req = NULL;
    map_monitor_evt_t *monitor_evt = NULL;
    char* tmp_str;
    uint8_t targ_channel = 0;
    uint8_t targ_opclass = 0;
    int ret = 0;    

    platform_log(MAP_LIBRARY,LOG_DEBUG, "%s : %d\n", __FUNCTION__, __LINE__);
    blobmsg_parse(set_steer_policy, ARRAY_SIZE(set_steer_policy), tb, blob_data(msg), blob_len(msg));

    if((!tb[MAP_CTRL_STEER_REQMODE]) || (!tb[MAP_CTRL_STEER_CURRBSSID]) || (!tb[MAP_CTRL_STEER_ALMAC]) || (!tb[MAP_CTRL_STEER_STA_CNT])) {
        platform_log(MAP_LIBRARY,LOG_ERR, "%s : %d Input Parameter Missing\n", __FUNCTION__, __LINE__);
        err_str = "MANDATORY IP PARAM MISSING";
        goto PARAM_ERR;
    } else {
        /* Get station count */
        sta_count = (uint8_t)blobmsg_get_u32(tb[MAP_CTRL_STEER_STA_CNT]);
        if (sta_count > MAX_STATIONS) {
            err_str = "STA CNT EXCEEDS MAX";
            goto PARAM_ERR;
        }
        /* allocate memory based on station count */
        if(sta_count > 1) {
            steer_req = calloc(1, (sizeof(struct sta_steer_params) + (sta_count-1)*(sizeof(struct sta_params))));    
        } else {
            steer_req = calloc(1, sizeof(struct sta_steer_params));    
        }
        if(NULL == steer_req) {
            platform_log(MAP_LIBRARY,LOG_ERR, "%s : %dCalloc failed\n", __FUNCTION__, __LINE__);
            return PLATFORM_UBUS_STATUS_ERROR;
        }
        /* update sta count */
        steer_req->sta_count = sta_count;
        /* get sta list data */        
        if((steer_req->sta_count > 0) && (tb[MAP_CTRL_STEER_STA_LIST])) {
            if(blobmsg_type(tb[MAP_CTRL_STEER_STA_LIST])==BLOBMSG_TYPE_ARRAY) {
                sta_count = blobmsg_check_array(tb[MAP_CTRL_STEER_STA_LIST], BLOBMSG_TYPE_STRING);
                platform_log(MAP_LIBRARY,LOG_DEBUG, "%s : %d sta count from list %d\n", __FUNCTION__, __LINE__,sta_count);
            } else {
                platform_log(MAP_LIBRARY,LOG_ERR, "%s : %d ubus parse policy not valid\n", __FUNCTION__, __LINE__);
                err_str = "STA NOT IN LIST FORMAT";
                goto PARAM_ERR;
            }
        
            if(sta_count != steer_req->sta_count) {
                err_str = "STA LIST MISMATCH WITH STA CNT";
                goto PARAM_ERR;
            }
        
            int rem = 0;
            int cnt = 0;
            blobmsg_for_each_attr(list_item, tb[MAP_CTRL_STEER_STA_LIST], rem) {
               tmp_str = blobmsg_get_string(list_item);               
               if((NULL != tmp_str) && (tmp_str[0] != '\0')) {
                   platform_log(MAP_LIBRARY,LOG_DEBUG, "%s %d sta_mac %s \n",__func__, __LINE__, tmp_str);
                   if(!platform_get_mac_from_string(tmp_str, (uint8_t *)steer_req->sta_info[cnt].sta_mac)) {
                       platform_log(MAP_LIBRARY,LOG_ERR, "%s %d, mac from string Failure\n",__func__, __LINE__);
                       err_str = "STA LIST";
                       goto PARAM_ERR;
                   }
                   cnt++;
               } else {
                   platform_log(MAP_LIBRARY,LOG_ERR, "%s %d, station list parse Failure\n",__func__, __LINE__);
                   err_str = "STA LIST PARSE";
                   goto PARAM_ERR;
               }
            }
        }
        /* parse agent mac */
        tmp_str = blobmsg_get_string(tb[MAP_CTRL_STEER_ALMAC]);
        if((NULL != tmp_str) && (tmp_str[0] !='\0')) {           
            ret = platform_get_mac_from_string(tmp_str,steer_req->dst_mac);
            if(ret == 0) {
                err_str = "AL MAC";
                goto PARAM_ERR;
            }
        } else {
            err_str = "AL MAC PARSE";
            goto PARAM_ERR;
        }
        
        /* current bssid */
        tmp_str = blobmsg_get_string(tb[MAP_CTRL_STEER_CURRBSSID]);
        if((NULL != tmp_str) && (tmp_str[0] !='\0')) {           
            ret = platform_get_mac_from_string(tmp_str,steer_req->source_bssid);
            if(ret == 0) {
                err_str = "CURRENT BSSID";
                goto PARAM_ERR;
            }
        } else {
            err_str = "CURRENT BSSID PARSE";
            goto PARAM_ERR;
        }
        
        /* Get steering mode */
        if(blobmsg_get_u32(tb[MAP_CTRL_STEER_REQMODE])) {
            steer_req->flag |= STEERING_REQUEST_MODE_BIT;
        } else {
            steer_req->flag &= ~STEERING_REQUEST_MODE_BIT;
        }
        
        if(steer_req->flag & STEERING_REQUEST_MODE_BIT) {
            if((!tb[MAP_CTRL_STEER_BTM_DISASSOC_IMMINENT]) || (!tb[MAP_CTRL_STEER_BTM_ABRIDGED]) || (!tb[MAP_CTRL_STEER_BTM_TIMER]) 
                || (!tb[MAP_CTRL_STEER_TARGBSSID]) || (!tb[MAP_CTRL_STEER_TARGCHAN]) || (!tb[MAP_CTRL_STEER_TARGOPCLASS])) {
                platform_log(MAP_LIBRARY,LOG_ERR, "%s : %d Steer mandate Input Parameters Missing\n", __FUNCTION__, __LINE__);
                err_str = "STEER MANDATE INPUT PARAM MISSING";
                goto PARAM_ERR;
            } else {
                /* BTM disassoc imminent bit */
                if(blobmsg_get_u32(tb[MAP_CTRL_STEER_BTM_DISASSOC_IMMINENT])) {
                    steer_req->flag |= BTM_DISSOC_IMMINENT_BIT;
                } else {
                    steer_req->flag &= ~BTM_DISSOC_IMMINENT_BIT;
                }
                /* BTM abridged bit */
                if(blobmsg_get_u32(tb[MAP_CTRL_STEER_BTM_ABRIDGED])) {
                    steer_req->flag |= BTM_ABRIDGED_BIT;
                } else {
                    steer_req->flag &= ~BTM_ABRIDGED_BIT;
                }
                /* BTM dis assoc timer */
                steer_req->disassociation_timer = (uint16_t)blobmsg_get_u32(tb[MAP_CTRL_STEER_BTM_TIMER]);

                /* Opportunity window */                
                steer_req->opportunity_wnd = 0x00;
                
                platform_log(MAP_LIBRARY,LOG_DEBUG, "%s %d, window %d timer %d \n",__func__, __LINE__, steer_req->opportunity_wnd, steer_req->disassociation_timer);
                /* Parse target bssid related data */
                tmp_str = blobmsg_get_string(tb[MAP_CTRL_STEER_TARGBSSID]);
                if((NULL == tmp_str) || (tmp_str[0] =='\0')) {
                    err_str = "TARGET BSSID";
                    goto PARAM_ERR;
                } 
                targ_channel = (uint8_t)blobmsg_get_u32(tb[MAP_CTRL_STEER_TARGCHAN]);
                targ_opclass = (uint8_t)blobmsg_get_u32(tb[MAP_CTRL_STEER_TARGOPCLASS]);                
                steer_req->bssid_count = 0x01;
                platform_log(MAP_LIBRARY,LOG_DEBUG, "%s %d, target channel %d target op class %d targbssid %s \n",__func__, __LINE__, targ_channel, targ_opclass, tmp_str);
                
                int i = 0;              
                /* steering mandate, fill target bssid, channel, operating class data */
                /* use same target bssid details for all */       
                do {    
                    ret = platform_get_mac_from_string(tmp_str,steer_req->sta_info[i].bssid);
                    if(ret == 0)
                    {
                        err_str = "TARGET BSSID";
                        goto PARAM_ERR;
                    }
        
                    steer_req->sta_info[i].channel = targ_channel;
        
                    /* reference from hostapd */
                    /* rclass: Assumption is 11h not used, use global operating classes */
                    /* See 802.11 2012 Annex E, Table E.1 */
                    if(!targ_opclass) {
                        if (steer_req->sta_info[i].channel < 14) {
                            steer_req->sta_info[i].operating_class = 81;
                        } else if (steer_req->sta_info[i].channel == 14) {
                            steer_req->sta_info[i].operating_class = 82;
                        } else if (steer_req->sta_info[i].channel < 52) {
                            steer_req->sta_info[i].operating_class = 115;
                        } else if (steer_req->sta_info[i].channel < 100) {
                            steer_req->sta_info[i].operating_class = 118;
                        } else if (steer_req->sta_info[i].channel < 149) {
                            steer_req->sta_info[i].operating_class = 121;
                        } else {
                            steer_req->sta_info[i].operating_class = 124;   /* or 125??? */
                        }
                    } else {
                        steer_req->sta_info[i].operating_class = targ_opclass;
                    }
                    i++;
                }while(i<sta_count);
            }
        } else {
            if(!(steer_req->flag & STEERING_REQUEST_MODE_BIT) && (!tb[MAP_CTRL_STEER_OPPORTUNITY_WINDOW])) {
                platform_log(MAP_LIBRARY,LOG_ERR, "%s : %d Steer opportunity Input Parameters Missing\n", __FUNCTION__, __LINE__);
                err_str = "STEER OPPORTUNITY INPUT PARAM MISSING";
                goto PARAM_ERR;
            } else {
                /* steering opportunity window */
                steer_req->bssid_count = 0x00;
                steer_req->disassociation_timer = 0x00;
                steer_req->opportunity_wnd = (uint16_t)blobmsg_get_u32(tb[MAP_CTRL_STEER_OPPORTUNITY_WINDOW]);
            }
        }                                                            
            
        monitor_evt = (map_monitor_evt_t*) malloc(sizeof(map_monitor_evt_t));   
        if(NULL != monitor_evt) {
            memset(monitor_evt, 0, sizeof(map_monitor_evt_t));  
            monitor_evt->evt = MAP_MONITOR_STEER_CALL;
            monitor_evt->evt_data = (void*)steer_req;
            monitor_evt->async_status_response = 0;
            if (!plt_hmwr_ctx->cli_pending_response) monitor_evt->async_status_response = 1;
            /* Notify event to main thread */
            if(event_notify_main_thread((void*)plt_hmwr_ctx->monitor_q_hdle,(void*)monitor_evt)) {
                free(steer_req);
                free(monitor_evt);
                platform_log(MAP_LIBRARY,LOG_ERR,"%s event notification failed \n", __FUNCTION__);
            }
            defer_cli(ctx, req);
            return PLATFORM_UBUS_STATUS_OK;
        } else {
            platform_log(MAP_LIBRARY,LOG_ERR, "%s : %d memory allocated failed\n", __FUNCTION__, __LINE__);
            err_str = "memory alloc failed";
            goto PARAM_ERR;
        }
       }
      

PARAM_ERR:

    if(NULL != steer_req)
        free(steer_req);
    blob_buf_init (&buff, 0);
    blobmsg_add_string (&buff, "Status", "Failure");
    blobmsg_add_u32(&buff,"Mtype:",0);
    blobmsg_add_u32(&buff,"Mid:",0);
    platform_send_reply(ctx, req, buff.head);
    platform_log(MAP_LIBRARY,LOG_ERR, "%s : %d -- %s Param Incorrect\n", __FUNCTION__, __LINE__,err_str);
    blob_buf_free(&buff);

    return -1;
}

static int map_monitor_cli_channel_preference_query_callback(void *ctx, void *obj, void *req, const char *method, struct blob_attr *msg)
{
        struct blob_buf buff = {};
        const char * err_str = NULL;
        struct blob_attr *tb[MAP_TARGET_MAX];
        char* tmp_str;
        uint8_t *mac;
        map_monitor_evt_t *monitor_evt = NULL;

        mac = (uint8_t *) calloc (MAC_ADDR_LEN, sizeof(uint8_t));
        monitor_evt = (map_monitor_evt_t*) malloc(sizeof(map_monitor_evt_t));
        memset(monitor_evt, 0, sizeof(map_monitor_evt_t));

        if(NULL != monitor_evt) {
            monitor_evt->evt = MAP_MONITOR_SEND_CHANNEL_PREFERENCE_QUERY_CALL;
            monitor_evt->evt_data = (void *)mac;
            monitor_evt->async_status_response = 0;
            if (!plt_hmwr_ctx->cli_pending_response) monitor_evt->async_status_response = 1;

            blobmsg_parse(send_query, ARRAY_SIZE(send_query), tb, blob_data(msg), blob_len(msg));
            tmp_str = blobmsg_get_string(tb[MAP_TARGET_MAC]);
            if(NULL == tmp_str) {
                err_str = "AGENT MAC";
                goto Failure;
            }

            if(0 == platform_get_mac_from_string(tmp_str,mac))
                goto Failure;
            /* Notify event to main thread */
			if(event_notify_main_thread((void*)plt_hmwr_ctx->monitor_q_hdle,(void*)monitor_evt)) 
			{
				free(mac);
				free(monitor_evt);
				platform_log(MAP_LIBRARY,LOG_ERR,"%s event notification failed \n", __FUNCTION__);
			}
        }
        else {
            if(mac != NULL)
                free(mac);
            if (monitor_evt != NULL)
                free(monitor_evt);

            platform_log(MAP_LIBRARY,LOG_ERR,"%s memory allocation failed \n", __FUNCTION__);
            return -1;
        }
        defer_cli(ctx, req);
	return PLATFORM_UBUS_STATUS_OK;

Failure:
        if(mac != NULL)
            free(mac);
		if (monitor_evt != NULL)
            free(monitor_evt);
		
        blob_buf_init (&buff, 0);
        blobmsg_add_string (&buff, "Status", "Failure");
        blobmsg_add_u32(&buff,"Mtype:",0);
        blobmsg_add_u32(&buff,"Mid:",0);
        platform_send_reply(ctx, req, buff.head);
        platform_log(MAP_LIBRARY,LOG_ERR, "%s : %d -- %s Param Incorrect\n", __FUNCTION__, __LINE__,err_str);
        blob_buf_free(&buff);

        return -1;
}


static int map_monitor_cli_combined_infra_metric_query_callback(void *ctx, void *obj, void *req, const char *method, struct blob_attr *msg)
{
    const char * err_str = NULL;
    map_monitor_evt_t *monitor_evt = NULL;
    struct blob_buf buff = {0};
    struct blob_attr *tb[MAP_TARGET_MAX];
    char *tmp_str = NULL;
    uint8_t *target_al_mac = NULL;

    blobmsg_parse(send_query, ARRAY_SIZE(send_query), tb, blob_data(msg), blob_len(msg));
    tmp_str = blobmsg_get_string(tb[MAP_TARGET_MAC]);
    if(NULL == tmp_str) {
        err_str = "INVALID IP PARAM";
        goto Failure;
    }

    monitor_evt = (map_monitor_evt_t*) calloc(1,sizeof(map_monitor_evt_t));
    if(NULL != monitor_evt) {
        target_al_mac = (uint8_t *) calloc (MAC_ADDR_LEN, sizeof(uint8_t));
        if (NULL == target_al_mac) {
            platform_log(MAP_LIBRARY,LOG_ERR,"%s Mac addr memory allocation failed \n", __FUNCTION__);
            err_str = "AL MAC NULL";
            goto Failure;
        }

        if(0 == platform_get_mac_from_string(tmp_str, target_al_mac)) {
            err_str = "STR TO MAC";
            goto Failure;
        }

        monitor_evt->evt = MAP_MONITOR_SEND_COMBINED_INFRA_METRICS;
        monitor_evt->evt_data = target_al_mac;
        monitor_evt->async_status_response = 0;
        if (!plt_hmwr_ctx->cli_pending_response) monitor_evt->async_status_response = 1;
        /* Notify event to main thread */
        if(event_notify_main_thread((void*)plt_hmwr_ctx->monitor_q_hdle,(void*)monitor_evt))
        {
            platform_log(MAP_LIBRARY,LOG_ERR,"%s event notification failed \n", __FUNCTION__);
            err_str = "NOTIFY CNT";
            goto Failure;
        }
    } else {
        platform_log(MAP_LIBRARY,LOG_ERR,"%s memory allocation failed \n", __FUNCTION__);
        err_str = "OUT OF MEMORY";
        goto Failure;
    }
        
    defer_cli(ctx, req);
    return PLATFORM_UBUS_STATUS_OK;


Failure:
    free(monitor_evt);
    free(target_al_mac);

    blob_buf_init (&buff, 0);
    blobmsg_add_string (&buff, "Status", "Failure");
    blobmsg_add_u32(&buff,"Mtype:",0);
    blobmsg_add_u32(&buff,"Mid:",0);

    platform_send_reply(ctx, req, buff.head);
    platform_log(MAP_LIBRARY,LOG_ERR, "%s : %d -- %s Param Incorrect\n", __FUNCTION__, __LINE__,err_str);
    blob_buf_free(&buff);

    return -1;
}

static int map_monitor_cli_dump_topo_tree_callback(void *ctx, void *obj, void *req, const char *method, struct blob_attr *msg)
{
    map_monitor_evt_t *monitor_evt = NULL;

    platform_log(MAP_LIBRARY,LOG_DEBUG, "%s : %d MONITOR TASK CALLBACK\n", __FUNCTION__, __LINE__);

    monitor_evt = (map_monitor_evt_t*) calloc(1,sizeof(map_monitor_evt_t));
    if(NULL != monitor_evt) {
        monitor_evt->evt = MAP_MONITOR_DUMP_TOPO_TREE;
        monitor_evt->evt_data = NULL;

        /* Notify event to main thread */
        if(event_notify_main_thread((void*)plt_hmwr_ctx->monitor_q_hdle,(void*)monitor_evt))
        {
            free(monitor_evt);
            platform_log(MAP_LIBRARY,LOG_ERR,"%s event notification failed \n", __FUNCTION__);
            return -1;
        }
    }
    else {
        platform_log(MAP_LIBRARY,LOG_ERR,"%s memory allocation failed \n", __FUNCTION__);
        return -1;
    }

    defer_cli(ctx, req);

    return 0;
}

static int map_monitor_cli_channel_selection_request_detail_callback(void *ctx, void *obj, void *req, const char *method, struct blob_attr *msg)
{
    struct blob_buf buff = {};
    struct blob_attr *tb[MAP_AGENT_CHANNEL_SEL_QUERY_MAX];

    channel_report_t *monitor_evt  = NULL;


    blobmsg_parse(send_channel_sel_query, MAP_AGENT_CHANNEL_SEL_QUERY_MAX, tb, blob_data(msg), blob_len(msg));

    if ((!tb[MAP_AGENT_CHANNEL_SEL_QUERY_ALMAC]) || (!tb[MAP_AGENT_CHANNEL_SEL_QUERY_RADID])  
       || (!tb[MAP_AGENT_CHANNEL_SEL_QUERY_OPCLASSLIST]) || (!tb[MAP_AGENT_CHANNEL_SEL_QUERY_TXPWR])) {
           platform_log(MAP_LIBRARY,LOG_ERR, "%s : %d Input Parameters Missing\n", __FUNCTION__, __LINE__);
          goto Failure;
    }


    if (map_get_oper_class_channel_list(tb[MAP_AGENT_CHANNEL_SEL_QUERY_OPCLASSLIST], &monitor_evt) < 0) {
        platform_log(MAP_LIBRARY,LOG_ERR, "%s %d, ubus failure to decode ch_list in channel sel req \n",__func__, __LINE__);
        goto Failure;
    }

    if(monitor_evt == NULL) 
        goto Failure;

    if(!platform_get_mac_from_string(blobmsg_get_string(tb[MAP_AGENT_CHANNEL_SEL_QUERY_ALMAC]), monitor_evt->al_mac)) {
        platform_log(MAP_LIBRARY,LOG_ERR, "%s %d, ubus failure to decode al_mac in  channel sel req \n",__func__, __LINE__);
        goto Failure;
    }

    if(!platform_get_mac_from_string(blobmsg_get_string(tb[MAP_AGENT_CHANNEL_SEL_QUERY_RADID]), monitor_evt->radio_id)) {
        platform_log(MAP_LIBRARY,LOG_ERR, "%s %d, ubus failure to decode radid in  channel sel req \n",__func__, __LINE__);
        goto Failure;
    }

    monitor_evt->txpower = (uint8_t)blobmsg_get_u32(tb[MAP_AGENT_CHANNEL_SEL_QUERY_TXPWR]);

    monitor_evt->type = MAP_MONITOR_SEND_CHANNEL_SEL_REQ_DETAIL;
    monitor_evt->async_status_response = 0;
    if (!plt_hmwr_ctx->cli_pending_response) monitor_evt->async_status_response = 1;
    /* Notify event to main thread */
    if(event_notify_main_thread((void*)plt_hmwr_ctx->monitor_q_hdle,(void*)monitor_evt) < 0) {
         platform_log(MAP_LIBRARY,LOG_ERR,"%s event notification failed \n", __FUNCTION__);
         goto Failure;
     }

     defer_cli(ctx, req);
     return PLATFORM_UBUS_STATUS_OK;

Failure:
    blob_buf_init (&buff, 0);
    blobmsg_add_string (&buff, "Status", "Failure");
    blobmsg_add_u32(&buff,"Mtype:",0);
    blobmsg_add_u32(&buff,"Mid:",0);
    platform_send_reply(ctx, req, buff.head);
    platform_log(MAP_LIBRARY,LOG_ERR, "%s : %d -- Param Incorrect\n", __FUNCTION__, __LINE__);

    /* Free the allocated memory if, any */
    if(monitor_evt != NULL) {
         free(monitor_evt);
     }

    blob_buf_free(&buff);
    return -1;
}


static int map_monitor_cli_channel_selection_request_callback(void *ctx, void *obj, void *req, const char *method, struct blob_attr *msg)
{
        struct blob_attr *tb[MAP_TARGET_MAX];
        struct blob_buf buff = {};
	char* tmp_str;
	char dbg_msg[64] = {0};
        map_monitor_evt_t *monitor_evt = NULL;
        uint8_t           *target_al_mac = NULL;

	blobmsg_parse(send_query, ARRAY_SIZE(send_query), tb, blob_data(msg), blob_len(msg));
	tmp_str = blobmsg_get_string(tb[MAP_TARGET_MAC]);
        if(NULL == tmp_str) {
            goto Failure;
        }

	snprintf(dbg_msg, ARRAY_SIZE(dbg_msg)-1, "%s", tmp_str);
	platform_log(MAP_LIBRARY,LOG_DEBUG,"%s : %d ubus object call back, parameter %s\n", __FUNCTION__, __LINE__, dbg_msg);
        /* 
         * send Channel_selection 
         */


        monitor_evt = (map_monitor_evt_t*) calloc(1, sizeof(map_monitor_evt_t));
        if(NULL != monitor_evt) {

            target_al_mac = (uint8_t *) calloc (MAC_ADDR_LEN, sizeof(uint8_t));
	    if (NULL == target_al_mac) {
	        platform_log(MAP_LIBRARY,LOG_ERR,"%s Mac addr memory allocation failed \n", __FUNCTION__);
                goto Failure;
            }

            monitor_evt->evt = MAP_MONITOR_SEND_CHANNEL_SELECTION_REQUEST_CALL;

            if(0 == platform_get_mac_from_string(tmp_str, target_al_mac))
                goto Failure;

            monitor_evt->evt_data = (void *)target_al_mac;
            monitor_evt->async_status_response = 0;
            if (!plt_hmwr_ctx->cli_pending_response) monitor_evt->async_status_response = 1;
            /* Notify event to main thread */
            if(event_notify_main_thread((void*)plt_hmwr_ctx->monitor_q_hdle,(void*)monitor_evt)) 
            {
                platform_log(MAP_LIBRARY,LOG_ERR,"%s event notification failed \n", __FUNCTION__);
                goto Failure;
            }
        }
        else {
            platform_log(MAP_LIBRARY,LOG_ERR,"%s memory allocation failed \n", __FUNCTION__);
            goto Failure;
        }

            defer_cli(ctx, req);
            return PLATFORM_UBUS_STATUS_OK;

Failure:
       blob_buf_init (&buff, 0);
       blobmsg_add_string (&buff, "Status", "Failure");
       blobmsg_add_u32(&buff,"Mtype:",0);
       blobmsg_add_u32(&buff,"Mid:",0);
   
       platform_send_reply(ctx, req, buff.head);
       blob_buf_free(&buff);

       free(monitor_evt);
       free(target_al_mac);
	
       return 0;
}

static int map_monitor_cli_dump_controller_callback(void *ctx, void *obj, void *req, const char *method, struct blob_attr *msg)
{
        map_monitor_evt_t *monitor_evt = NULL;
	struct blob_buf buff = {};

	platform_log(MAP_LIBRARY,LOG_DEBUG, "%s : %d MONITOR TASK CALLBACK\n", __FUNCTION__, __LINE__);

        monitor_evt = (map_monitor_evt_t*) malloc(sizeof(map_monitor_evt_t));
        memset(monitor_evt, 0, sizeof(map_monitor_evt_t));

        if(NULL != monitor_evt) {
            monitor_evt->evt = MAP_MONITOR_DUMP_CONTROLLER_INFO;
            monitor_evt->evt_data = NULL;

            /* Notify event to main thread */
	    if(event_notify_main_thread((void*)plt_hmwr_ctx->monitor_q_hdle,(void*)monitor_evt)) 
	    {				
	 		free(monitor_evt);
			platform_log(MAP_LIBRARY,LOG_ERR,"%s event notification failed \n", __FUNCTION__);
	    }
        }
        else {
            platform_log(MAP_LIBRARY,LOG_ERR,"%s memory allocation failed \n", __FUNCTION__);
            return -1;
        }

        blob_buf_init (&buff, 0);
        blobmsg_add_string (&buff, "CONTROLLER INFO", "Initiation started");
        platform_send_reply(ctx, req, buff.head);
        platform_log(MAP_LIBRARY,LOG_DEBUG, "%s : %d exiting\n", __FUNCTION__, __LINE__);
        blob_buf_free(&buff);

        return PLATFORM_UBUS_STATUS_OK;
}

static int map_monitor_cli_autoconfig_renew_callback(void *ctx, void *obj, void *req, const char *method, struct blob_attr *msg)
{
	map_monitor_evt_t *monitor_evt = NULL;
	struct blob_buf buff = {};
    struct blob_attr *tb[MAP_RENEW_MAX];
    uint8_t *supported_freq = NULL;

	platform_log(MAP_LIBRARY,LOG_DEBUG, "%s : %d MONITOR TASK CALLBACK\n", __FUNCTION__, __LINE__);
    if(ctx == NULL || req ==NULL || msg == NULL)
        return -1;

    blobmsg_parse(send_autoconfig_renew, ARRAY_SIZE(send_autoconfig_renew), tb, blob_data(msg), blob_len(msg));
    if ((NULL == tb[MAP_SUP_FREQ_BAND])) {
        platform_log(MAP_LIBRARY,LOG_ERR, "%s : %d Input Parameters Missing\n", __FUNCTION__, __LINE__);
        goto Fail;
    }

    supported_freq = (uint8_t *) calloc (1, sizeof(uint8_t));
    if (NULL == supported_freq) {
        platform_log(MAP_LIBRARY,LOG_ERR,"%s memory allocation failed \n", __FUNCTION__);
            goto Fail;
    }

    *supported_freq = (uint8_t) blobmsg_get_u32(tb[MAP_SUP_FREQ_BAND]);
	monitor_evt = (map_monitor_evt_t*) malloc(sizeof(map_monitor_evt_t));
	memset(monitor_evt, 0, sizeof(map_monitor_evt_t));

	if(NULL != monitor_evt) {
		monitor_evt->evt = MAP_MONITOR_SEND_AUTOCONFIG_RENEW;
		monitor_evt->evt_data = (void*)supported_freq;
                monitor_evt->async_status_response = 0;
                if (!plt_hmwr_ctx->cli_pending_response) monitor_evt->async_status_response = 1;
                /* Notify event to main thread */
		if(event_notify_main_thread((void*)plt_hmwr_ctx->monitor_q_hdle,(void*)monitor_evt)) 
		{				
			free(monitor_evt);
			platform_log(MAP_LIBRARY,LOG_ERR,"%s event notification failed \n", __FUNCTION__);
			goto Fail;
		}
	}
	else {
		platform_log(MAP_LIBRARY,LOG_ERR,"%s memory allocation failed \n", __FUNCTION__);
		goto Fail;
	}

        defer_cli(ctx, req);
	return PLATFORM_UBUS_STATUS_OK;

  Fail:
        free(supported_freq);
        blob_buf_init (&buff, 0);
        blobmsg_add_string (&buff, "Status", "Failure");
        blobmsg_add_u32(&buff,"Mtype:",0);
        blobmsg_add_u32(&buff,"Mid:",0);

	platform_send_reply(ctx, req, buff.head);
	platform_log(MAP_LIBRARY,LOG_DEBUG, "%s : %d exiting\n", __FUNCTION__, __LINE__);
	blob_buf_free(&buff);
  return -1;
}

static int map_monitor_cli_send_steer_policy_config_callback (void *ctx, void *obj, void *req, const char *method, struct blob_attr *msg)
{
    struct blob_buf buff = {};
    const char * err_str = NULL;
    struct blob_attr *tb[MAP_CTRL_STEERING_POLICY_MAX];
    struct blob_attr *list_item = NULL;
    map_steering_policy_config_cmd_t *policy_config = NULL;
    map_monitor_evt_t *monitor_evt = NULL;
    char* tmp_str;    
    int ret = 0;    

    platform_log(MAP_LIBRARY,LOG_DEBUG, "%s : %d\n", __FUNCTION__, __LINE__);
    blobmsg_parse(send_steer_policy_config_policy, ARRAY_SIZE(send_steer_policy_config_policy), tb, blob_data(msg), blob_len(msg));
    if ((NULL == tb[MAP_CTRL_STEERING_POLICY_AL_MAC]) || (NULL == tb[MAP_CTRL_STEERING_POLICY_RADIO_COUNT]) || (NULL == tb[MAP_CTRL_STEERING_POLICY_BTM_DISALLOW_COUNT])
        || (NULL == tb[MAP_CTRL_STEERING_POLICY_RADIO_LIST])) {
        platform_log(MAP_LIBRARY,LOG_ERR, "%s : %d Input Parameters Missing\n", __FUNCTION__, __LINE__);
        err_str = "MANDATORY PARAMS MISSING";
        goto PARAM_ERR;
    }

    policy_config = UBUS_CMD_CALLOC(map_steering_policy_config_cmd_t,1); 
    if(NULL == policy_config)
    {
        platform_log(MAP_LIBRARY,LOG_ERR, "%s : %dCalloc failed\n", __FUNCTION__, __LINE__);
        err_str = "OUT OF MEMORY";
        goto PARAM_ERR;
    }
    
    tmp_str = blobmsg_get_string(tb[MAP_CTRL_STEERING_POLICY_AL_MAC]);
    if((NULL != tmp_str) && ('\0' != tmp_str[0])) {
        ret = platform_get_mac_from_string(tmp_str,&policy_config->al_mac[0]);
        if(ret == 0)
        {
            err_str = "AL MAC";
            goto PARAM_ERR;
        }
    } else {
        err_str = "AL MAC PARSE";
        goto PARAM_ERR;
    }

    int btm_list_sta_cnt = 0;

    if(tb[MAP_CTRL_STEERING_POLICY_BTM_DISALLOW_LIST]) {
        if(blobmsg_type(tb[MAP_CTRL_STEERING_POLICY_BTM_DISALLOW_LIST])==BLOBMSG_TYPE_ARRAY) {
            btm_list_sta_cnt = blobmsg_check_array(tb[MAP_CTRL_STEERING_POLICY_BTM_DISALLOW_LIST], BLOBMSG_TYPE_STRING);
            platform_log(MAP_LIBRARY,LOG_DEBUG, "%s : %d btm disallaowed sta count from list %d\n", __FUNCTION__, __LINE__,btm_list_sta_cnt);
        } else {
            platform_log(MAP_LIBRARY,LOG_ERR, "%s : %d ubus parse policy not valid\n", __FUNCTION__, __LINE__);
            err_str = "BTM DISALLOW LIST";
            goto PARAM_ERR;
        }
    }

    policy_config->btm_disalllowed_sta_cnt = (uint8_t)blobmsg_get_u32(tb[MAP_CTRL_STEERING_POLICY_BTM_DISALLOW_COUNT]);
    if (policy_config->btm_disalllowed_sta_cnt != btm_list_sta_cnt) {
        platform_log(MAP_LIBRARY,LOG_ERR, "%s %d, Mismatch!! array size %d No of stations in the list %d\n",__func__, __LINE__, btm_list_sta_cnt, policy_config->btm_disalllowed_sta_cnt);
        err_str = "BTM LIST STA CNT MISMATCH";
        goto PARAM_ERR;
    }

    int rem = 0;
    int cnt = 0;
    if(btm_list_sta_cnt > 0) {      
        policy_config->btm_disalllowed_sta_list = (uint8_t (*)[MAC_ADDR_LEN]) calloc(btm_list_sta_cnt, sizeof(uint8_t [MAC_ADDR_LEN]));
        blobmsg_for_each_attr(list_item, tb[MAP_CTRL_STEERING_POLICY_BTM_DISALLOW_LIST], rem) {
           tmp_str = blobmsg_get_string(list_item);           
           if((NULL != tmp_str) && (tmp_str[0] != '\0')) {
               platform_log(MAP_LIBRARY,LOG_DEBUG, "%s %d, btm disallowed sta_mac %s \n",__func__, __LINE__, tmp_str);
               if(!platform_get_mac_from_string(tmp_str, (uint8_t *)policy_config->btm_disalllowed_sta_list[cnt])) {
                   platform_log(MAP_LIBRARY,LOG_ERR, "%s %d, unassocc Failure\n",__func__, __LINE__);
                   err_str = "BTM STA LIST";
                   goto PARAM_ERR;
               }
               cnt++;
           } else {
               err_str = "BTM STA LIST PARSE";
               goto PARAM_ERR;
           }
        }
    }
    
    int local_list_sta_cnt = 0;
    if(tb[MAP_CTRL_STEERING_POLICY_LOCAL_DISALLOW_LIST]) {
        if(blobmsg_type(tb[MAP_CTRL_STEERING_POLICY_LOCAL_DISALLOW_LIST])==BLOBMSG_TYPE_ARRAY) {
            local_list_sta_cnt = blobmsg_check_array(tb[MAP_CTRL_STEERING_POLICY_LOCAL_DISALLOW_LIST], BLOBMSG_TYPE_STRING);
            platform_log(MAP_LIBRARY,LOG_DEBUG, "%s : %d local disallaowed sta count from list %d\n", __FUNCTION__, __LINE__,local_list_sta_cnt);
        } else {
            platform_log(MAP_LIBRARY,LOG_ERR, "%s : %d ubus parse policy not valid\n", __FUNCTION__, __LINE__);
            err_str = "LOCAL DISALLOW STA LIST";
            goto PARAM_ERR;
        }
    }
    
    policy_config->local_disalllowed_sta_cnt = (uint8_t)blobmsg_get_u32(tb[MAP_CTRL_STEERING_POLICY_LOCAL_DISALLOW_COUNT]);
    if (policy_config->local_disalllowed_sta_cnt != local_list_sta_cnt) {
        platform_log(MAP_LIBRARY,LOG_ERR, "%s %d, Mismatch!! array size %d No of stations in the list %d\n",__func__, __LINE__, local_list_sta_cnt, policy_config->local_disalllowed_sta_cnt);
        err_str = "LOCAL LIST STA CNT MISMATCH";
        goto PARAM_ERR;
    }

    if(local_list_sta_cnt > 0) {
        rem = 0;
        cnt = 0;
        policy_config->local_disallowed_sta_list = (uint8_t (*)[MAC_ADDR_LEN]) calloc(local_list_sta_cnt, sizeof(uint8_t[6]));
        blobmsg_for_each_attr(list_item, tb[MAP_CTRL_STEERING_POLICY_LOCAL_DISALLOW_LIST], rem) {
           tmp_str = blobmsg_get_string(list_item);           
           if((NULL != tmp_str) && (tmp_str[0] != '\0')) {
               platform_log(MAP_LIBRARY,LOG_DEBUG, "%s %d, local disalowed sta_mac %s \n",__func__, __LINE__, tmp_str);
               if(!platform_get_mac_from_string(tmp_str, (uint8_t *)&policy_config->local_disallowed_sta_list[cnt])) {
                   platform_log(MAP_LIBRARY,LOG_ERR, "%s %d, unassocc Failure\n",__func__, __LINE__);
                    err_str = "LOCAL STA LIST";
                    goto PARAM_ERR;
               }
               cnt++;
           } else {
               err_str = "LOCAL STA LIST PARSE";
               goto PARAM_ERR;
           }
        }
    }
    int size = 0;
    policy_config->radio_count = (uint8_t)blobmsg_get_u32(tb[MAP_CTRL_STEERING_POLICY_RADIO_COUNT]);

    size = blobmsg_check_array(tb[MAP_CTRL_STEERING_POLICY_RADIO_LIST], BLOBMSG_TYPE_TABLE);
    if(size <= 0 || size >MAX_RADIOS_PER_AGENT) {
        platform_log(MAP_LIBRARY,LOG_ERR, "%s %d, no of radios in list out of range\n",__func__, __LINE__);
        err_str = "RADIO LIST";
        goto PARAM_ERR;
    }

    if(size != policy_config->radio_count) {
        platform_log(MAP_LIBRARY,LOG_ERR, "%s %d, radio count %d radios in list %d \n",__func__, __LINE__, policy_config->radio_count, size);
        err_str = "RADIO CNT MISMATCH";
        goto PARAM_ERR;
    }

    /* Go over the array of tables */
    rem = 0;
    cnt = 0;
    struct blob_attr *list_item_attr;
    blobmsg_for_each_attr(list_item_attr, tb[MAP_CTRL_STEERING_POLICY_RADIO_LIST], rem) {
        struct blob_attr *list_item_param_attr;
        int              list_item_rem;

        /* go over members of a table entry in the table array*/
        blobmsg_for_each_attr(list_item_param_attr, list_item_attr, list_item_rem) {
            if (blobmsg_type(list_item_param_attr)==BLOBMSG_TYPE_STRING && !strcmp(blobmsg_name(list_item_param_attr), "ruid")) {
                tmp_str = blobmsg_get_string(list_item_param_attr);                
                if((NULL != tmp_str) && (tmp_str[0] != '\0')) {
                    platform_log(MAP_LIBRARY,LOG_DEBUG, "%s %d, radio %d ruid %s \n",__func__, __LINE__, cnt, tmp_str); 
                    if(!platform_get_mac_from_string(tmp_str, (uint8_t *)policy_config->radio_list[cnt].radio_mac)) {
                        platform_log(MAP_LIBRARY,LOG_ERR, "%s %d, radio %d ruid Failure\n",__func__, __LINE__,cnt);
                         err_str = "RADIO RUID LIST";
                         goto PARAM_ERR;
                    }           
                } else {
                    err_str = "RADIO RUID LIST PARSE";
                    goto PARAM_ERR;
                }
            }

            if (blobmsg_type(list_item_param_attr)==BLOBMSG_TYPE_INT32 && !strcmp(blobmsg_name(list_item_param_attr), "steerpolicy")) {
                policy_config->radio_list[cnt].steering_policy = (uint8_t)blobmsg_get_u32(list_item_param_attr);
                platform_log(MAP_LIBRARY,LOG_DEBUG, "%s %d, radio %d steering_policy 0x%x\n",__func__, __LINE__, cnt, policy_config->radio_list[cnt].steering_policy);          
            }

            if (blobmsg_type(list_item_param_attr)==BLOBMSG_TYPE_INT32 && !strcmp(blobmsg_name(list_item_param_attr), "chutilthres")) {
                policy_config->radio_list[cnt].chnlutil_threshold= (uint8_t)blobmsg_get_u32(list_item_param_attr);
                platform_log(MAP_LIBRARY,LOG_DEBUG, "%s %d, radio %d chutilthres 0x%x\n",__func__, __LINE__, cnt, policy_config->radio_list[cnt].chnlutil_threshold);           
            }

            if (blobmsg_type(list_item_param_attr)==BLOBMSG_TYPE_INT32 && !strcmp(blobmsg_name(list_item_param_attr), "rcpithres")) {
                policy_config->radio_list[cnt].rcpi_threshold= (uint8_t)blobmsg_get_u32(list_item_param_attr);
                platform_log(MAP_LIBRARY,LOG_DEBUG, "%s %d, radio %d rcpithres 0x%x\n",__func__, __LINE__, cnt, policy_config->radio_list[cnt].rcpi_threshold);         
            }               
        }
        cnt++;
    }
    
    monitor_evt = (map_monitor_evt_t*) malloc(sizeof(map_monitor_evt_t));   
    if(NULL != monitor_evt) {
        memset(monitor_evt, 0, sizeof(map_monitor_evt_t));  
        monitor_evt->evt = MAP_MONITOR_SEND_STEER_POLICY_CONFIG_CALL;
        monitor_evt->evt_data = (void*)policy_config;
        monitor_evt->async_status_response = 0;
        if (!plt_hmwr_ctx->cli_pending_response) monitor_evt->async_status_response = 1;
        /* Notify event to main thread */
        if(event_notify_main_thread((void*)plt_hmwr_ctx->monitor_q_hdle,(void*)monitor_evt)) 
        {
            free(policy_config->btm_disalllowed_sta_list);
            free(policy_config->local_disallowed_sta_list);
            free(policy_config);
            free(monitor_evt);
            platform_log(MAP_LIBRARY,LOG_ERR,"%s event notification failed \n", __FUNCTION__);
        }
        defer_cli(ctx, req);
        return PLATFORM_UBUS_STATUS_OK;
    } else {
        free(policy_config->btm_disalllowed_sta_list);
        free(policy_config->local_disallowed_sta_list);
        if(NULL != policy_config)
            free(policy_config);
        platform_log(MAP_LIBRARY,LOG_ERR, "%s : %d memory allocated failed\n", __FUNCTION__, __LINE__);
    }


PARAM_ERR:

    if(NULL != policy_config) {
        free(policy_config->btm_disalllowed_sta_list);
        free(policy_config->local_disallowed_sta_list);
        free(policy_config);
    }

    blob_buf_init (&buff, 0);
    blobmsg_add_string (&buff, "Status", "Failure");
    blobmsg_add_u32(&buff,"Mtype:",0);
    blobmsg_add_u32(&buff,"Mid:",0);

    platform_send_reply(ctx, req, buff.head);
    platform_log(MAP_LIBRARY,LOG_ERR, "%s : %d -- %s Param Incorrect\n", __FUNCTION__, __LINE__,err_str);
    blob_buf_free(&buff);

    return -1;

}

static int map_monitor_cli_send_policy_config_callback (void *ctx, void *obj, void *req, const char *method, struct blob_attr *msg)
{
	struct blob_buf buff = {};
	const char * err_str = NULL;
	struct blob_attr *tb[MAP_CTRL_POLICY_MAX];
	map_policy_config_cmd_t *policy_config = NULL;
	map_monitor_evt_t *monitor_evt = NULL;
	char* tmp_str;
	struct blob_attr *list_item = NULL;
	int ret = 0;
	int rem = 0;
	int idx = 0;

	blobmsg_parse(send_policy_config_policy, ARRAY_SIZE(send_policy_config_policy), tb, blob_data(msg), blob_len(msg));
	if (!tb[MAP_CTRL_POLICY_DST_MAC]) {
		platform_log(MAP_LIBRARY,LOG_ERR, "%s : %d Input Parameters Missing\n", __FUNCTION__, __LINE__);
		return PLATFORM_UBUS_STATUS_INVALID_ARGUMENT;
	}

	policy_config = UBUS_CMD_CALLOC(map_policy_config_cmd_t,1);	
	if(NULL == policy_config)
	{
		platform_log(MAP_LIBRARY,LOG_ERR, "%s : %dCalloc failed\n", __FUNCTION__, __LINE__);
		return PLATFORM_UBUS_STATUS_ERROR;
	}
	
	tmp_str = blobmsg_get_string(tb[MAP_CTRL_POLICY_DST_MAC]);
	ret = platform_get_mac_from_string(tmp_str,&policy_config->dst_mac[0]);
	if(ret == 0)
	{
		err_str = "DST MAC";
		goto PARAM_ERR;
	}

	if(tb[MAP_CTRL_POLICY_STA_COUNT]) {
		policy_config->station_count = blobmsg_get_u32(tb[MAP_CTRL_POLICY_STA_COUNT]);
		tmp_str = blobmsg_get_string(tb[MAP_CTRL_POLICY_STAMAC]);
		ret = platform_get_mac_from_string(tmp_str,&policy_config->sta_mac[0][0]);
		if(ret == 0)
		{
			err_str = "STA MAC";
			goto PARAM_ERR;
		}
	}
	if(tb[MAP_CTRL_POLICY_RADIO_COUNT]) {
		policy_config->radio_count= blobmsg_get_u32(tb[MAP_CTRL_POLICY_RADIO_COUNT]);
		blobmsg_for_each_attr(list_item, tb[MAP_CTRL_POLICY_RADIOMAC], rem) {
		  if((idx) == MAX_RADIOS_PER_AGENT)
		  {
		    platform_log(MAP_LIBRARY,LOG_ERR,"Max radio per agent is %d only the first %d radios are taken \n",idx,idx);
		    policy_config->radio_count=MAX_RADIOS_PER_AGENT;
		    goto PARAM_BREAK;
		  }
		  tmp_str = blobmsg_get_string(list_item);
		  ret = platform_get_mac_from_string(tmp_str,&policy_config->radio_mac[idx++][0]);
		  if(ret == 0)
	    {
		    err_str = "RADIO MAC";
		    goto PARAM_ERR;
	    }
		}
	}
	PARAM_BREAK:

	monitor_evt = (map_monitor_evt_t*) malloc(sizeof(map_monitor_evt_t));	
	if(NULL != monitor_evt) {
		memset(monitor_evt, 0, sizeof(map_monitor_evt_t));	
		monitor_evt->evt = MAP_MONITOR_SEND_POLICY_CONFIG_CALL;
		monitor_evt->evt_data = (void*)policy_config;
                monitor_evt->async_status_response = 0;
                if (!plt_hmwr_ctx->cli_pending_response) monitor_evt->async_status_response = 1;
		/* Notify event to main thread */
		if(event_notify_main_thread((void*)plt_hmwr_ctx->monitor_q_hdle,(void*)monitor_evt)) 
		{
			free(policy_config);
			free(monitor_evt);
			platform_log(MAP_LIBRARY,LOG_ERR,"%s event notification failed \n", __FUNCTION__);
		}
	} else {
		if(NULL != policy_config)
			free(policy_config);
		platform_log(MAP_LIBRARY,LOG_ERR, "%s : %d memory allocated failed\n", __FUNCTION__, __LINE__);
	}

        defer_cli(ctx, req);
       return PLATFORM_UBUS_STATUS_OK;
PARAM_ERR:

	if(NULL != policy_config)
	    free(policy_config);

	blob_buf_init (&buff, 0);
        blobmsg_add_string (&buff, "Status", "Failure");
        blobmsg_add_u32(&buff,"Mtype:",0);
        blobmsg_add_u32(&buff,"Mid:",0);

	platform_send_reply(ctx, req, buff.head);
	platform_log(MAP_LIBRARY,LOG_ERR, "%s : %d -- %s Param Incorrect\n", __FUNCTION__, __LINE__,err_str);
    blob_buf_free(&buff);

    return -1;

}

static int map_monitor_cli_send_higher_layer_data_msg_callback(void *ctx, void *obj, void *req, const char *method, struct blob_attr *msg)
{
    struct blob_buf buff = {};
    const char *err_str = NULL;
    struct blob_attr *tb[MAP_HIGHLAYER_DATAMSG_MAX];
    higherlayer_info_t *hl_data = NULL;
    map_monitor_evt_t *monitor_evt = NULL;
    char *tmp_str = NULL;
    int tmp_int;
    int i = 0, alloc_len = 0;

    hl_data = (higherlayer_info_t *)calloc (sizeof(higherlayer_info_t), 1);

    if (NULL == hl_data) {
        platform_log(MAP_LIBRARY,LOG_ERR,"%s higher layer data info memory allocation failed \n", __FUNCTION__);
        goto HL_CB_ERR;
    }

    blobmsg_parse(send_higherlayer_data_msg,ARRAY_SIZE(send_higherlayer_data_msg),tb, blob_data(msg), blob_len(msg));
    
    if(!tb[MAP_HIGHLAYER_AGENT_MAC])
    {
        err_str = "Mandatory Param almac missing";
        goto HL_CB_ERR;
    }
    
    if(tb[MAP_HIGHLAYER_PROTO]) {
        hl_data->protocol = blobmsg_get_u32(tb[MAP_HIGHLAYER_PROTO]);
    }

    if(tb[MAP_HIGHLAYER_REPEAT_CNT])  {
        hl_data->repeat_cnt = blobmsg_get_u32(tb[MAP_HIGHLAYER_REPEAT_CNT]);
    }
    else {
        hl_data->repeat_cnt = 1; /* Default to 1 to accept whatever in payload, if repeat_cnt is not specified by user */
    }

    if(tb[MAP_HIGHLAYER_AGENT_MAC]) {
        tmp_str = blobmsg_get_string(tb[MAP_HIGHLAYER_AGENT_MAC]);
    }
    if (NULL == tmp_str)
    {
        err_str = "AL MAC";
        goto HL_CB_ERR;
    } else {
        tmp_int = platform_get_mac_from_string(tmp_str,hl_data->dest_mac);
        if(tmp_int == -1)
        {
            err_str = "AL MAC";
            goto HL_CB_ERR;
        }
    }

    if(tb[MAP_HIGHLAYER_PAYLOAD_PATTERN])
    {
        tmp_str = blobmsg_get_string(tb[MAP_HIGHLAYER_PAYLOAD_PATTERN]);
        if(tmp_str) {
            tmp_int = strlen(tmp_str);
            alloc_len = ((tmp_int -(tmp_int/2)) > MAP_HIGHLAYER_PAYLOAD_MAX_LEN) ? MAP_HIGHLAYER_PAYLOAD_MAX_LEN : (tmp_int -(tmp_int/2)); 
            /* Reduce the length to half, logic to have valid half length in case of odd original value */
            hl_data->payload_len = alloc_len;

            hl_data->payload_pattern = malloc(sizeof(uint8_t) * alloc_len);
            
            if (hl_data->payload_pattern == NULL) {
               platform_log(MAP_LIBRARY,LOG_ERR,"%s: payload memory allocation failure \n", __FUNCTION__);
               goto HL_CB_ERR;
            }
            
            for (i=0; i< alloc_len; i++) {
                sscanf(&tmp_str[i*2], "%02hhx", &hl_data->payload_pattern[i]);
            }

/* REPEAT pattern for repeat count times */
            if(hl_data -> repeat_cnt > 1) {
                int old_payload_len = hl_data->payload_len;
                tmp_int = ((hl_data->payload_len * hl_data->repeat_cnt) > MAP_HIGHLAYER_PAYLOAD_MAX_LEN) ? 
                    MAP_HIGHLAYER_PAYLOAD_MAX_LEN : (hl_data->payload_len * hl_data->repeat_cnt);
                hl_data->payload_pattern = realloc(hl_data->payload_pattern, (sizeof(uint8_t) * tmp_int));
                if (hl_data->payload_pattern == NULL) {
                    platform_log(MAP_LIBRARY,LOG_ERR,"%s: payload memory allocation failure\n",__FUNCTION__);
                    goto HL_CB_ERR;
                }

                hl_data->payload_len = tmp_int;

                for (i = 1, tmp_int = old_payload_len; i < hl_data->repeat_cnt && tmp_int < MAP_HIGHLAYER_PAYLOAD_MAX_LEN; i++)
                {
                    if((tmp_int + old_payload_len) < MAP_HIGHLAYER_PAYLOAD_MAX_LEN) {
                        memcpy(&(hl_data->payload_pattern[old_payload_len * i]), hl_data->payload_pattern, old_payload_len);
                        tmp_int += old_payload_len;
                    }
                    else {
                        memcpy(&(hl_data->payload_pattern[old_payload_len * i]),  hl_data->payload_pattern,
                                (MAP_HIGHLAYER_PAYLOAD_MAX_LEN - tmp_int));
                        tmp_int = MAP_HIGHLAYER_PAYLOAD_MAX_LEN;
                    }
                }
            }

        }

    }

    monitor_evt = (map_monitor_evt_t*) malloc(sizeof(map_monitor_evt_t));
    if(NULL != monitor_evt) {
        memset(monitor_evt, 0, sizeof(map_monitor_evt_t));
        monitor_evt->evt = MAP_MONITOR_HIGHLAYER_DATA_EVENT;
        monitor_evt->evt_data = (void*)hl_data;
        monitor_evt->async_status_response = 0;
        if (!plt_hmwr_ctx->cli_pending_response) monitor_evt->async_status_response = 1;
        /* Notify event to main thread */
        if(event_notify_main_thread((void*)plt_hmwr_ctx->monitor_q_hdle,(void*)monitor_evt))
        {
            platform_log(MAP_LIBRARY,LOG_ERR,"%s event notification failed \n", __FUNCTION__);
            goto HL_CB_ERR;
        }
    } else {
        platform_log(MAP_LIBRARY,LOG_ERR, "%s : %d memory allocation failed\n", __FUNCTION__, __LINE__);
        goto HL_CB_ERR;
    }

    defer_cli(ctx, req);
    return PLATFORM_UBUS_STATUS_OK;

HL_CB_ERR:
    if (NULL != hl_data)
    {
        if(hl_data->payload_pattern != NULL) {
            free(hl_data->payload_pattern);
            hl_data->payload_pattern = NULL;
        }
        free(hl_data);
        hl_data = NULL;
     
    }
    if (NULL != monitor_evt)
    {
        free(monitor_evt);
        monitor_evt = NULL;
    }
    if (err_str) {
        blob_buf_init (&buff, 0); 
        blobmsg_add_string (&buff, "Status", "Failure");
        blobmsg_add_u32(&buff,"Mtype:",0);
        blobmsg_add_u32(&buff,"Mid:",0);
        platform_send_reply(ctx,   req, buff.head);
        platform_log(MAP_LIBRARY,LOG_ERR, "%s : %d -- %s Param Incorrect\n", __FUNCTION__, __LINE__,err_str);
        blob_buf_free(&buff);
        return PLATFORM_UBUS_STATUS_INVALID_ARGUMENT;
    }
    else {
        return -1;
    }
}

static int map_monitor_cli_send_clicap_query_callback(void *ctx, void *obj, void *req, const char *method, struct blob_attr *msg)
{
        struct blob_buf buff = {};
        const char * err_str = NULL;
        struct blob_attr *tb[MAP_CLIENT_CAPABILITY_MAX];
        char* tmp_str;
        client_info_t *client_info = NULL;
        map_monitor_evt_t *monitor_evt = NULL;

        client_info = (client_info_t *) calloc (1, sizeof(client_info_t));
        if (NULL == client_info) {
            platform_log(MAP_LIBRARY,LOG_ERR,"%s Client info memory allocation failed \n", __FUNCTION__);
            goto Failure;
        }

        monitor_evt = (map_monitor_evt_t*) malloc(sizeof(map_monitor_evt_t));
        if(NULL != monitor_evt) {
            memset(monitor_evt, 0, sizeof(map_monitor_evt_t));

            monitor_evt->evt = MAP_MONITOR_SEND_CLIENT_CAPABILITY_QUERY;

            blobmsg_parse(send_client_capability_query, ARRAY_SIZE(send_client_capability_query), tb, blob_data(msg), blob_len(msg));
            tmp_str = blobmsg_get_string(tb[MAP_STA_MAC]);
            if(NULL == tmp_str) {
                err_str = "STA MAC";
                goto Failure;
            }

            if(0 == platform_get_mac_from_string(tmp_str,client_info->client_mac))
                goto Failure;

            blobmsg_parse(send_query, ARRAY_SIZE(send_query), tb, blob_data(msg), blob_len(msg));
            tmp_str = blobmsg_get_string(tb[MAP_STA_BSSID]);
            if(NULL == tmp_str) {
                err_str = "STA BSSID";
                goto Failure;
            }

            if(0 == platform_get_mac_from_string(tmp_str,client_info->bssid))
                goto Failure;

            blobmsg_parse(send_query, ARRAY_SIZE(send_query), tb, blob_data(msg), blob_len(msg));
            tmp_str = blobmsg_get_string(tb[MAP_AGENT_MAC]);
            if(NULL == tmp_str) {
                err_str = "AGENT MAC";
                goto Failure;
            }

            if(0 == platform_get_mac_from_string(tmp_str,client_info->agent_mac))
                goto Failure;

            monitor_evt->evt_data = (void *)client_info;
            monitor_evt->async_status_response = 0;
            if (!plt_hmwr_ctx->cli_pending_response) monitor_evt->async_status_response = 1;
            /* Notify event to main thread */
			if(event_notify_main_thread((void*)plt_hmwr_ctx->monitor_q_hdle,(void*)monitor_evt)) 
			{
				free(client_info);
				free(monitor_evt);
				platform_log(MAP_LIBRARY,LOG_ERR,"%s event notification failed \n", __FUNCTION__);
			}
        }
        else {
            platform_log(MAP_LIBRARY,LOG_ERR,"%s memory allocation failed \n", __FUNCTION__);
            goto Failure;
        }

        defer_cli(ctx, req);
        return PLATFORM_UBUS_STATUS_OK;

Failure:
        if (client_info != NULL)
            free(client_info);

        if (monitor_evt != NULL)
            free(monitor_evt);

        blob_buf_init (&buff, 0);
        blobmsg_add_string (&buff, "Status", "Failure");
        blobmsg_add_u32(&buff,"Mtype:",0);
        blobmsg_add_u32(&buff,"Mid:",0);
        platform_send_reply(ctx, req, buff.head);
        platform_log(MAP_LIBRARY,LOG_ERR, "%s : %d -- %s Param Incorrect\n", __FUNCTION__, __LINE__,err_str);
        blob_buf_free(&buff);

        return -1;
}

static int map_monitor_cli_dump_agent_callback(void *ctx, void *obj, void *req, const char *method, struct blob_attr *msg)
{	
	const char * err_str = NULL;		
	map_monitor_evt_t *monitor_evt = NULL;		
	struct blob_buf buff = {};		
	platform_log(MAP_LIBRARY,LOG_DEBUG, "%s : %d MONITOR TASK CALLBACK\n", __FUNCTION__, __LINE__);		
	monitor_evt = (map_monitor_evt_t*) malloc(sizeof(map_monitor_evt_t));				
	if(NULL != monitor_evt) {			
		memset(monitor_evt, 0, sizeof(map_monitor_evt_t));	
		monitor_evt->evt = MAP_MONITOR_DEBUG_AGENT_INFO;			
		monitor_evt->evt_data = NULL;			
		/* Notify event to main thread */
		if(event_notify_main_thread((void*)plt_hmwr_ctx->monitor_q_hdle,(void*)monitor_evt)) 
		{
			free(monitor_evt);
			platform_log(MAP_LIBRARY,LOG_ERR,"%s event notification failed \n", __FUNCTION__);
		}	
	}		
	else {			
		platform_log(MAP_LIBRARY,LOG_ERR,"%s memory allocation failed \n", __FUNCTION__);			
		goto Failure;	
	}

	blob_buf_init (&buff, 0);		
	blobmsg_add_string (&buff, "AGENT INFO", "Initiation started");		
	platform_send_reply(ctx, req, buff.head);		
	platform_log(MAP_LIBRARY,LOG_DEBUG, "%s : %d exiting\n", __FUNCTION__, __LINE__);		
    blob_buf_free(&buff);
	
    return UBUS_STATUS_OK;

Failure:		
	blob_buf_init (&buff, 0);		
        blobmsg_add_string (&buff, "Status", "Failure");
        blobmsg_add_u32(&buff,"Mtype:",0);
        blobmsg_add_u32(&buff,"Mid:",0);
	platform_send_reply(ctx, req, buff.head);		
	platform_log(MAP_LIBRARY,LOG_ERR, "%s : %d -- %s Param Incorrect\n", __FUNCTION__, __LINE__,err_str);		
    blob_buf_free(&buff);
	
    return -1;
}

static int map_fill_sta_list(struct blob_attr *list_attr, client_acl_data_t *acl_data)
{
    char* tmp_str;
    uint8_t i = 0;
    int list_attr_size = 0;
    struct blob_attr *list_array_attr;

    if(acl_data == NULL)
       return -EINVAL;

    blobmsg_for_each_attr(list_array_attr, list_attr, list_attr_size) {
        tmp_str = blobmsg_get_string(list_array_attr);
        if(NULL != tmp_str) {
            if(0 == platform_get_mac_from_string(tmp_str,acl_data->sta_list[i++].sta_mac))
                return -1;
        }
        else
        {
            platform_log(MAP_LIBRARY,LOG_ERR, "%s : %d tmp_str is NULL\n", __FUNCTION__, __LINE__);
            return -1;
        }
    }

    return 0;
}

static int map_monitor_cli_send_acl_request_callback(void *ctx, void *obj, void *req, const char *method, struct blob_attr *msg)
{
    struct blob_buf buff = {};
    const char * err_str = NULL;
    char* tmp_str;
    uint8_t len                   = 0;
    uint8_t sta_count              = 0;
    uint8_t block = -1;
    uint8_t size = 0;
    struct blob_attr *tb[MAP_ACL_MAX];
    map_monitor_evt_t *monitor_evt = NULL;
    client_acl_data_t *acl_data    = NULL;

    blobmsg_parse(send_cli_acl_req, MAP_ACL_MAX, tb, blob_data(msg), blob_len(msg));

    if ((!tb[MAP_ACL_ALMAC]) || (!tb[MAP_ACL_STA_BSSID]) || (!tb[MAP_ACL_ACTION]) || (!tb[MAP_ACL_VALIDITY_PERIOD]) 
          || (!tb[MAP_ACL_STA_COUNT]) || (!tb[MAP_ACL_STA_MAC])) {
       platform_log(MAP_LIBRARY,LOG_ERR, "%s : %d Input Parameters Missing\n", __FUNCTION__, __LINE__);
        err_str = "PARAMETER MISSING";
       goto Failure;
    }

    sta_count = (uint8_t )blobmsg_get_u32(tb[MAP_ACL_STA_COUNT]);  //get sta count

    if (sta_count <= 0)
    {
        platform_log(MAP_LIBRARY,LOG_ERR, "Invalid sta count");
        err_str = "STA COUNT";
        goto Failure;
    }

    size = blobmsg_check_array(tb[MAP_ACL_STA_MAC], BLOBMSG_TYPE_STRING); //Check no of sta's with sta count
    if(size != sta_count)
    {
        err_str = "COUNT MISMATCH WITH STA LIST";
        goto Failure;
    }
 
    block = (uint8_t )blobmsg_get_u32(tb[MAP_ACL_ACTION]); // Check for valid action..block or unblock
    if ((0 != block) && (1 != block))
    {
        err_str = "INVALID BLOCK ACTION";
        goto Failure;
    }

    len = sizeof(client_acl_data_t) + (sta_count *  sizeof(station_list_t));
    acl_data = (client_acl_data_t *) calloc (1, len);

    if (NULL == acl_data)
    {
        platform_log(MAP_LIBRARY,LOG_ERR,"Calloc Failed for acl_data");
        goto Failure;
    }

    acl_data->sta_count = sta_count;
    acl_data->block = block;

    tmp_str = blobmsg_get_string(tb[MAP_ACL_ALMAC]);
    if(NULL == tmp_str) {
        err_str = "AL MAC";
        goto Failure;
    }

    if(0 == platform_get_mac_from_string(tmp_str,acl_data->al_mac))
        goto Failure;

    tmp_str = blobmsg_get_string(tb[MAP_ACL_STA_BSSID]);
    if(NULL == tmp_str) {
        err_str = "BSSID";
        goto Failure;
    }

    if(0 == platform_get_mac_from_string(tmp_str,acl_data->bssid))
        goto Failure;

    acl_data->validity_period = (uint16_t) blobmsg_get_u32(tb[MAP_ACL_VALIDITY_PERIOD]);

    if (map_fill_sta_list(tb[MAP_ACL_STA_MAC], acl_data) < 0) {
        platform_log(MAP_LIBRARY,LOG_ERR, "%s %d, ubus failure to decode sta list in client association control request \n",__func__, __LINE__);
        err_str = "STATION LIST";
        goto Failure;
    }

    monitor_evt = (map_monitor_evt_t*)calloc(1,sizeof(map_monitor_evt_t));
    if(NULL == monitor_evt)
    {
        platform_log(MAP_LIBRARY,LOG_ERR,"%s Memory allocation failed \n", __FUNCTION__);
        goto Failure;
    }

    monitor_evt->evt = MAP_MONITOR_SEND_CLIENT_ACL_REQUEST;
    monitor_evt->evt_data = (void *)acl_data;
    monitor_evt->async_status_response = 0;
    if (!plt_hmwr_ctx->cli_pending_response) monitor_evt->async_status_response = 1;
    /* Notify event to main thread */
    if(event_notify_main_thread((void*)plt_hmwr_ctx->monitor_q_hdle,(void*)monitor_evt) < 0) {
         platform_log(MAP_LIBRARY,LOG_ERR,"%s event notification failed \n", __FUNCTION__);
         goto Failure;
     }

     defer_cli(ctx, req);
     return PLATFORM_UBUS_STATUS_OK;

Failure:
        if (acl_data != NULL)
            free(acl_data);

        if (monitor_evt != NULL)
            free(monitor_evt);

        blob_buf_init (&buff, 0);
        blobmsg_add_string (&buff, "Status", "Failure");
        blobmsg_add_u32(&buff,"Mtype:",0);
        blobmsg_add_u32(&buff,"Mid:",0);
        platform_send_reply(ctx, req, buff.head);
        platform_log(MAP_LIBRARY,LOG_ERR, "%s : %d -- %s Param Incorrect\n", __FUNCTION__, __LINE__,err_str);
       blob_buf_free(&buff);

        return -1;
}

int map_async_cli_completion_cb(void *ctx, map_cli_async_resp_t *resp)
{
    struct blob_buf buff = {};

    if (plt_hmwr_ctx->cli_pending_response) {
        if (resp != NULL) {
            blob_buf_init (&buff, 0);
            blobmsg_add_string (&buff, "Status", resp->status);
            blobmsg_add_u32(&buff,"Mtype:",resp->msg_type);
            blobmsg_add_u32(&buff,"Mid:",resp->mid);

            ubus_send_reply(ctx, &plt_hmwr_ctx->ubus_response, buff.head);
            blob_buf_free(&buff);
        }
        ubus_complete_deferred_request(ctx, &plt_hmwr_ctx->ubus_response, 0);
        plt_hmwr_ctx->cli_pending_response = 0;
    } 
    return 0;
}

int map_send_async_ubus_response(void *ctx, void *resp)
{
    if (plt_hmwr_ctx->cli_pending_response) {
        if (resp != NULL) {
            struct blob_buf * buf = (struct blob_buf *)resp;
            ubus_send_reply(ctx, &plt_hmwr_ctx->ubus_response, buf->head);
            blob_buf_free(buf);
            free(buf);
        } else {
            struct blob_buf err = {};
            blob_buf_init (&err, 0);
            blobmsg_add_string (&err, "Error", NULL);
            ubus_send_reply(ctx, &plt_hmwr_ctx->ubus_response, err.head);
            blob_buf_free(&err);
        }
        ubus_complete_deferred_request(ctx, &plt_hmwr_ctx->ubus_response, 0);
        plt_hmwr_ctx->cli_pending_response = 0;
    }
    return 0;
}

/** @brief This is the ubus event handler
 *
 *  This UBUS handler will be triggered on specific registered events.
 *  This will inturn trigger the appropriate callback from monitor thread.
 *
 *  @param ctx - UBUS context
 *  @param ev - UBUS event handler
 *  @param type - the pattern that triggered the event
 *  @param msg - the data passed with the event
 *  @return void
 */
static void handle_event(struct ubus_context *ctx, struct ubus_event_handler *ev,
                                const char *type, struct blob_attr *msg)
{
	int index = -1;

	platform_log(MAP_LIBRARY,LOG_DEBUG,"Number of events is :%d",gnum_events);
	/* Iterate through the platform event table and trigger the application
	callback for the pattern */
	index = get_platform_event_index(type);
	if(index >=0)
	{
		platform_log(MAP_LIBRARY,LOG_DEBUG,"Event Index is :%d",index);
		if((NULL != platform_ubus_event_table[index].platform_event_handler) && (UBUS_REGISTERED == platform_ubus_event_table[index].registered))
		{
			platform_ubus_event_table[index].platform_event_handler((void *)ctx, (void *)ev, type, msg);
		}
		else
		{
			platform_log(MAP_LIBRARY,LOG_ERR,"%s Event %s not registered for\n",__FUNCTION__, type);
		}
	}
	else
	{
		platform_log(MAP_LIBRARY,LOG_ERR,"Invalid Event %s",__FUNCTION__);
	}
}

/** @brief This is the ubus method handler
 *
 *  This UBUS handler will be triggered on calling these methods like from CLI.
 *  This will inturn trigger the appropriate callback from monitor thread.
 *
 *  @param ctx - UBUS context
 *  @param obj - UBUS object
 *  @param req - UBUS request data
 *  @param method - method
 *  @param msg - the data
 *  @return int
 */
static int handle_method (struct ubus_context *ctx, struct ubus_object *obj,
    						struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
	int ret = PLATFORM_UBUS_STATUS_ERROR ,index = -1;

	platform_log(MAP_LIBRARY,LOG_DEBUG,"Number of methods is :%d",gnum_methods);

	/* Iterate through the platform method table and trigger the application
	callback for the pattern */
	index = get_platform_method_index(method);
	if(index >=0)
	{
		platform_log(MAP_LIBRARY,LOG_DEBUG,"Method Index is :%d",index);
		if((NULL != platform_ubus_method_table[index].platform_method_handler) && (UBUS_REGISTERED == platform_ubus_method_table[index].registered))
		{
			ret = platform_ubus_method_table[index].platform_method_handler((void *)ctx, (void *)obj, (void *)req, method, msg);
		}
		else
		{
			platform_log(MAP_LIBRARY,LOG_ERR,"%s Method %s not registered for\n",__FUNCTION__, method);
		}
	}
	else
	{
		platform_log(MAP_LIBRARY,LOG_ERR,"Invalid Method %s",__FUNCTION__);
	}

	return ret;
}

/** @brief This is the ubus event handler
 *
 *  This UBUS handler will be triggered on specific registered events.
 *  This will inturn trigger the appropriate callback from monitor thread.
 *
 *  @param ctx - UBUS context
 *  @param ev - UBUS event handler
 *  @param type - the pattern that triggered the event
 *  @param msg - the data passed with the event
 *  @return void
 */


static int map_monitor_cli_get_version(struct ubus_context *ctx, struct ubus_object *obj,
                                                struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
	int ret = PLATFORM_UBUS_STATUS_OK;

	char version[MAX_VERSION_LEN]={0};

	struct blob_buf buff = {};

	blob_buf_init (&buff, 0);

	platform_log(MAP_LIBRARY,LOG_DEBUG,"querying version from %s \n",__FUNCTION__);

	platform_get_version ( version );

	blobmsg_add_string (&buff, "version", version );			

	ubus_send_reply (ctx, req, buff.head);

	blob_buf_free(&buff);

	return ret;
}


/** @brief This is an API to connect to UBUS.
 *
 *  This generic API will be called by monitor thread when it
 *  needs to establish a new connection to UBUS.
 *
 *  @param path
 *  @return IPC pointer as void
 */
void * mon_platform_connect(const char *path, void *mon_q_hdle, bool is_controller, void** rpc_ctx)
{	
	int ret = PLATFORM_UBUS_STATUS_ERROR;
	struct ubus_object *uobj = NULL;
        struct ubus_method *umethod = NULL;
	platform_homeware_ctx_t *platform_ctx = NULL;

	/* Input parameters check */
	if(NULL == mon_q_hdle)
	{
		platform_log(MAP_LIBRARY,LOG_ERR,"%s Invalid eventing mechanism %d\n",__FUNCTION__,__LINE__);
		return NULL;
	}

	platform_ctx = calloc(1,sizeof(*platform_ctx));
	if(NULL != platform_ctx)
	{
		platform_ctx->is_controller = is_controller;		
	}
	else
	{
		platform_log(MAP_LIBRARY,LOG_ERR,"%s calloc failed %d\n",__FUNCTION__,__LINE__);
		return NULL;
	}
	
	platform_ctx->monitor_q_hdle = mon_q_hdle;
	platform_ctx->ubus_ctx = ubus_connect(path);
	if(NULL != platform_ctx->ubus_ctx) {
		ubus_add_uloop(platform_ctx->ubus_ctx);
	}
	else 
	{
	    platform_log(MAP_LIBRARY,LOG_ERR,"ubus_connect failed %s\n",__FUNCTION__);
		return NULL;
	}

	/* Check if it is controller or agent */
	if(is_controller)
	{
		uobj = &ubus_object_ctrl;
		umethod = ubus_method_ctrl;
		platform_ubus_event_table = platform_ubus_event_table_ctrl;
		gnum_events = sizeof(platform_ubus_event_table_ctrl)/sizeof(platform_ubus_event_t);
	}
	else
	{
		uobj = &ubus_object_agent;
		umethod = ubus_method_agent;
		platform_ubus_event_table = platform_ubus_event_table_agent;
		gnum_events = sizeof(platform_ubus_event_table_agent)/sizeof(platform_ubus_event_t);
	}

	/* UBUS add object */
	ret = ubus_add_object(platform_ctx->ubus_ctx , uobj);
	platform_log(MAP_LIBRARY,LOG_DEBUG,"Return value for ubus add object :%d",ret);
	/* Update in static context pointer */
	plt_hmwr_ctx = platform_ctx;
        *rpc_ctx = (void*) platform_ctx->ubus_ctx;
	
	return (void *)platform_ctx;	
}

/** @brief This is an API to register an event to UBUS.
 *
 *  This generic API will be called by monitor thread when it
 *  needs to register any event.
 *
 *  @param ctx - UBUS context
 *  @param event_hanlde - function pointer to application callback
 *  @param type - pattern which specifies the event
 *  @return int
 */
int mon_platform_register_event(void *ctx, const char *type)
{
	int ret = PLATFORM_UBUS_STATUS_ERROR, index;
	platform_homeware_ctx_t *platform_ctx = NULL;

	/* Context should be UBUS context*/
	platform_ctx = (platform_homeware_ctx_t*)ctx;

	platform_log(MAP_LIBRARY,LOG_DEBUG,"Register event type :%s",type);
	platform_log(MAP_LIBRARY,LOG_DEBUG,"Number of events :%d",gnum_events);

	/* Input parameters check */
	if ((NULL == platform_ctx) || (NULL == type) || ('\0' == *type) || (NULL == platform_ctx->ubus_ctx))
	{
		platform_log(MAP_LIBRARY,LOG_ERR,"invalid arguments for %s",__FUNCTION__);
	}
	else
	{
		/* Register the callback for the particular pattern in the global platform event table
		Also register the actual ubus event callback so that it can inturn trigger application callback */
		index = get_platform_event_index(type);
		/*If pattern exists */
		if(index >= 0)
		{
			/* Update the global platform event table*/
			platform_ubus_event_table[index].registered = UBUS_REGISTERED;
			/* Actual UBUS register event */
			ret = ubus_register_event_handler(platform_ctx->ubus_ctx, &ubus_event_handle, type);
			platform_log(MAP_LIBRARY,LOG_DEBUG,"Return value for ubus event register :%d",ret);
		}
		/* if no pattern match is found, then platform table has not been updated correctly */
		else
		{
			platform_log(MAP_LIBRARY,LOG_ERR,"invalid Event Pattern for %s",__FUNCTION__);
		}
	}

	if(ret > PLATFORM_UBUS_STATUS_OK)
	{
		return -ret;
	}
	return ret;
}

/** @brief This is an API to register an method of the UBUS object (controller/agent).
 *
 *  This generic API will be called by monitor thread when it
 *  needs to register a method. The objects and the methods supported are static.
 *  BUt the monitor thread can use it to register callbacks for the supported methods
 *
 *  @param ctx - UBUS context
 *  @param method - pattern which specifies method name like "steer"
 *  @param is_controller - boolean value TRUE if controller, FALSE if agent
 *  @return int
 */
int mon_platform_register_method(void *ctx, const char *method)
{
	int ret = PLATFORM_UBUS_STATUS_ERROR, i , index;
	struct ubus_object *uobj;
	struct ubus_method *umethod;
	platform_homeware_ctx_t *platform_ctx = NULL;

	/* Input parameters check */
	if ((ctx == NULL) || (NULL == method) || ('\0' == *method))
	{
		platform_log(MAP_LIBRARY,LOG_ERR,"invalid arguments for %s",__FUNCTION__);
		return ret;
	}
	
	/* Context should be platform context*/
	platform_ctx = (platform_homeware_ctx_t*)ctx;

	/* Check if it is controller or agent */
	if(MAP_MONITOR_CONTROLLER == platform_ctx->is_controller)
	{
		uobj = &ubus_object_ctrl;
		umethod = ubus_method_ctrl;
	}
	else
	{
		uobj = &ubus_object_agent;
		umethod = ubus_method_agent;
	}

	/* Register the callback for the particular pattern in the global platform methodS table
	Also update the policy and npolicy of the pattern in the UBUS object
	Also register the actual ubus event callback so that it can inturn trigger application callback */
	for(i=0;i<uobj->n_methods;i++)
	{
		/*If pattern exists */
		if(strcmp(method, umethod[i].name) == 0)
		{
			/* additionally just check that the same pattern exists in the global platform Method as well */
			index = get_platform_method_index(method);
			if(index >= 0)
			{
				/* Enable registered cli methods in global table */
				platform_ubus_method_table[index].registered = UBUS_REGISTERED;
				ret = PLATFORM_UBUS_STATUS_OK;
			}
			else
			{
				platform_log(MAP_LIBRARY,LOG_ERR,"invalid method Pattern for %s",__FUNCTION__);
			}
			break;
		}
	}

	/* if no pattern match is found, then platform table has not been updated correctly */
	if( i == uobj->n_methods)
	{
		platform_log(MAP_LIBRARY,LOG_ERR,"invalid Method Pattern for %s",__FUNCTION__);
	}

	return ret;
}


/** @brief This is an API to free the UBUS connection.
 *
 *  This generic API will be called by monitor thread when it
 *  needs to free the existing UBUS connection.
 *
 *  @param ctx - UBUS context
 *  @return void
 */
void mon_platform_shutdown(void *ctx)
{
	platform_homeware_ctx_t *platform_ctx = (platform_homeware_ctx_t*)ctx;

	/* Check for NULL */
	if (platform_ctx != NULL)		
	{
		if(NULL != platform_ctx->ubus_ctx)
		{
			ubus_free(platform_ctx->ubus_ctx);
		}
		free(platform_ctx);
		/* To ensure any other access using a copy of the address to faile, clearing it off */
		platform_ctx = NULL;
	}
}


