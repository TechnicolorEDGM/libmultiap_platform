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

#ifndef AGENT_PLATFORM_H
#define AGENT_PLATFORM_H

#if 0
#include <stdint.h>
#include <time.h>
#include "platform_map.h"

#define MAX_RADIOS 4
//#define MAX_BSS_PER_RADIO 8
#define MAX_STATIONS 64

typedef enum _map_radio_states {
    MAP_RADIO_ON                            = 0x0001, /* 0000 0000 0000 0001 */
    MAP_RADIO_FREQUENCY_SUPPORTED           = 0x0002, /* 0000 0000 0000 0010 */
    MAP_RADIO_CONFIGURED                    = 0x0004, /* 0000 0000 0000 0100 */
    MAP_RADIO_M1_SENT                       = 0x0008, /* 0000 0000 0000 1000 */
    MAP_RADIO_M1_RECEIVED                   = 0x0010, /* 0000 0000 0001 0000 */
    MAP_RADIO_M2_SENT                       = 0x0020, /* 0000 0000 0010 0000 */
    MAP_RADIO_FREQUENCY_UNSUPPORTED_BY_CTRL = 0x8000, /* 1000 0000 0000 0000 */
}map_radio_states_t;

static inline void set_radio_state_bit(uint16_t *radio_state, uint16_t bit) {
    *radio_state = (*radio_state) | bit;
}

static inline void reset_radio_state_bit(uint16_t *radio_state, uint16_t bit) {
    *radio_state = (*radio_state) & (~bit);
}

static inline int is_radio_state_bit_set(uint16_t radio_state, uint16_t bit) {
    if (bit == (radio_state & bit))
        return 1;
    return 0;
}

/* Set radio state bit*/
#define set_radio_state_on(radio_state) (set_radio_state_bit(radio_state,MAP_RADIO_ON))
#define set_radio_state_freq_supported(radio_state) {\
                                                      set_radio_state_bit(radio_state,MAP_RADIO_FREQUENCY_SUPPORTED);\
                                                      reset_radio_state_bit(radio_state,MAP_RADIO_FREQUENCY_UNSUPPORTED_BY_CTRL);\
                                                    }
#define set_radio_state_configured(radio_state) {\
                                                  set_radio_state_bit(radio_state,MAP_RADIO_CONFIGURED);\
                                                  reset_radio_state_bit(radio_state,MAP_RADIO_M1_SENT);\
                                                }
#define set_radio_state_M1_sent(radio_state) (set_radio_state_bit(radio_state,MAP_RADIO_M1_SENT))
#define set_radio_state_M1_receive(radio_state) (set_radio_state_bit(radio_state,MAP_RADIO_M1_RECEIVED))
#define set_radio_state_M2_sent(radio_state) (set_radio_state_bit(radio_state,MAP_RADIO_M2_SENT))
#define set_radio_state_freq_supported_by_ctrl(radio_state) (set_radio_state_bit(radio_state,MAP_RADIO_FREQUENCY_UNSUPPORTED_BY_CTRL))

/*Reset radio state bit*/
#define set_radio_state_off(radio_state) (reset_radio_state_bit(radio_state,MAP_RADIO_ON))
#define set_radio_state_freq_unsupported(radio_state) (reset_radio_state_bit(radio_state,MAP_RADIO_FREQUENCY_SUPPORTED))
#define set_radio_state_unconfigured(radio_state) {\
                                                    reset_radio_state_bit(radio_state,MAP_RADIO_CONFIGURED);\
                                                    reset_radio_state_bit(radio_state,MAP_RADIO_M1_SENT);\
                                                  }
#define set_radio_state_freq_unsupported_by_ctrl(radio_state) (reset_radio_state_bit(radio_state,MAP_RADIO_FREQUENCY_UNSUPPORTED_BY_CTRL))

/*Get if radio state is set or not*/
#define is_radio_on(radio_state) (is_radio_state_bit_set(radio_state,MAP_RADIO_ON))
#define is_radio_freq_supported(radio_state) (is_radio_state_bit_set(radio_state,MAP_RADIO_FREQUENCY_SUPPORTED))
#define is_radio_configured(radio_state) (is_radio_state_bit_set(radio_state,MAP_RADIO_CONFIGURED))
#define is_radio_M1_sent(radio_state) (is_radio_state_bit_set(radio_state,MAP_RADIO_M1_SENT))
#define is_radio_M1_received(radio_state) (is_radio_state_bit_set(radio_state,MAP_RADIO_M1_RECEIVED))
#define is_radio_M2_sent(radio_state) (is_radio_state_bit_set(radio_state,MAP_RADIO_M2_SENT))
#define is_radio_freq_unsupported_by_ctrl(radio_state) (is_radio_state_bit_set(radio_state,MAP_RADIO_FREQUENCY_UNSUPPORTED_BY_CTRL))

typedef union _state_info{
	struct{
		uint32_t admin_state:1;
		uint32_t oper_state:1;
		uint32_t fronthaul:1;
		uint32_t backhaul:1;
		uint32_t configured:1;
		uint32_t reserved:27;
		};
	uint32_t radio_bss_state;
}state_info;

/*
Below Structures better be grouped as per TLV type for easy reconstruction and data gathering
Need to define structures for the channel info
Need to define structures for different radio capabilities
Need to define structures for regulatory info 
*/
#define MAX_CHANNEL         54
#define MAX_OPERATING_CLASS 32
#define MAX_CHANNEL_IN_OPERATING_CLASS 20
#define MAX_STA_PER_BSS     64

typedef struct non_operating_channels_s {
        uint8_t op_class;
        uint8_t count;
        uint8_t ch[MAX_CHANNEL];
} non_operating_channels_t;

typedef struct op_class_s {
    uint8_t op_class;
    uint8_t eirp;
	uint8_t pref;
  	uint8_t reason;
	uint8_t static_non_operable_count;
	uint8_t static_non_operable_channel[MAX_CHANNEL_IN_OPERATING_CLASS];
	/* Typically the channel list - agent and controller is only for temporarily non-operable channels i.e PREF_0
	For other cases, the default value by itself is 15, so no need to maintain it. For effieciency, just keep count as 0
	if pref is 15 */
	/* List of channels for which agent specified preference */
	uint8_t agent_channel_count;
	uint8_t agent_channel[MAX_CHANNEL_IN_OPERATING_CLASS];
	/* List of channels for which controller specified preference besides the agent channels */
	uint8_t cntlr_channel_count;
	uint8_t cntrl_channel[MAX_CHANNEL_IN_OPERATING_CLASS];
	/* We are considering only 2 values for now - PREF_0 and PREF_15 */
} op_class_t;


typedef struct sta_info {
        uint8_t  stations[MAC_ADDR_SIZE]; 
        time_t   assoc_time;
        uint8_t  inuse;
} sta_info_t;

typedef struct _bss_info{
        char       iface[MAX_IFACE_NAME_LEN];
        #define MAP_BSS_TYPE_WPS_ENABLED   1
        #define MAP_FRONTHALL_BSS   1
        #define MAP_BACKHALL_BSS    2
        uint8_t    bss_type;
        uint8_t    configured;
        uint8_t    wps_state;
	char       ssid_name[MAX_WIFI_SSID_LEN];
	char       bss_mac[MAC_ADDR_SIZE];
	state_info bss_state;
        uint16_t      sta_count;
        sta_info_t    sta_info[MAX_STA_PER_BSS];
}bss_info;

typedef struct channel_set {
    uint8_t ch[MAX_CHANNEL];
    uint8_t count;
} channel_set;

typedef struct _radio_data{
	char radio_name[MAX_IFACE_NAME_LEN];
        char if_name[MAX_IFACE_NAME_LEN];
	uint8_t radio_mac[6];
	unsigned int id;
	radio_type type;
        uint16_t map_radio_state; /* OR'ed Values. Refer enum map_radio_states_t */
        int supported_bandwidth;

        #define STD_80211_B    0
        #define STD_80211_G    1
        #define STD_80211_A    2
        #define STD_80211_N    3
        #define STD_80211_AC   4
        #define STD_80211_AN   5
        #define STD_80211_ANAC 6
        #define STD_80211_AX   7

        uint8_t supported_standard;

        int bandwidth_capability;
        uint8_t max_tx_streams;
        uint8_t max_rx_streams;
        uint8_t sgi_support;
        uint8_t su_beamformer_capable;
        uint8_t mu_beamformer_capable;
        channel_set current_ch;
        uint8_t op_class_count;
        op_class_t op_class[MAX_OPERATING_CLASS];
	state_info radio_state;
        uint8_t      bss_count;
	bss_info bssinfo[MAX_BSS_PER_RADIO];
	uint8_t transmit_power_limit;
	uint8_t current_op_channel;
        void    *wsc_data;
}radio_data;

typedef struct _radio_info{
	unsigned int num_radio;
	radio_data radio_config[MAX_RADIOS];
}radio_info;

typedef struct _agent_radio_metric_t{
	uint8_t radioId[MAC_ADDR_LEN];
	uint8_t reporting_rssi_threshold;
	uint8_t reporting_rssi_margin_override;
	uint8_t channel_utilization_reporting_threshold;
	uint8_t associated_sta_policy;
}agent_radio_metric_t;

typedef struct _agent_radio_steering_t{
	uint8_t radioId[MAC_ADDR_LEN];
	uint8_t steering_policy;
	uint8_t channel_utilization_threshold;
	uint8_t rssi_steering_threshold;
}agent_radio_steering_t;

/* Todo steering disallowed stations need to be maintained as a list*/
typedef struct map_agent_steering_policy_config {
    uint8_t number_of_local_steering_disallowed;
	uint8_t local_steering_macs[MAX_STATIONS][MAC_ADDR_LEN];
	uint8_t number_of_btm_steering_disallowed;
	uint8_t btm_steering_macs[MAX_STATIONS][MAC_ADDR_LEN];
	uint8_t number_of_radio;
    agent_radio_steering_t radio_policy[MAX_RADIOS];
} map_agent_steering_policy_config_t;

typedef struct map_agent_metric_policy_config {
    uint8_t metric_reporting_interval;
	uint8_t number_of_radio;
    agent_radio_metric_t radio_policy[MAX_RADIOS];
} map_agent_metric_policy_config_t;

//This is a master structure for the policy configuration 
//This structure needs to be maintaned seperately to be lockless
typedef struct _policy_config{
	unsigned int reserved;
	map_agent_metric_policy_config_t metric_policy_config;
	map_agent_steering_policy_config_t steering_policy_config;
}policy_config;

// This is the master structure which holds all the static / One time configs.
typedef struct _multiap_agent_data{
	unsigned int bh_radioid;			//Lets Fix radio ID 0 to be backhaul(BH) allways as the topology doesnt allow more than one BH
	uint8_t controller_mac[MAC_ADDR_LEN];
        char controller_ifname[MAX_IFACE_NAME_LEN];
        radio_info radioconfig;
	policy_config policycfg;
}multiap_agent_data;

#endif
#endif //AGENT_PLATFORM_H

#ifdef __cplusplus
}
#endif


