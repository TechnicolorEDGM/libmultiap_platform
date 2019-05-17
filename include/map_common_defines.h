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

#ifndef MAP_COMMON_DEFINES_H
#define MAP_COMMON_DEFINES_H

#include <stdio.h>
#include <stdint.h>

#if _HOST_IS_LITTLE_ENDIAN_ == 1
#define host_to_le16(n) ((uint16_t) (n))
#elif _HOST_IS_BIG_ENDIAN == 1
#define host_to_le16(n) (bswap_16(n))
#endif

// Add all the macros in here
#define MAX_RADIO_ID              6
#define MAX_IF_NAME               20
#define MAX_IFACE_NAME_LEN        17 /* Length = 16 + 1 for Null character at the end */
#define MAX_INTERFACE_COUNT       24
#define MAX_RADIO_NAME_LEN        32
#define MAX_IFACE_NAME_LIST       128
#define MAC_ADDR_LEN              6
#define MAX_MAC_STRING_LEN        18   // sizeof("00:00:00:00:00:00")
#define MAX_TIMER_ID_STRING_LENGTH  50 // including NULL char

#define MAX_BSS_PER_RADIO         8
#define MAX_RADIOS_PER_AGENT      4
#define MAX_ACCESS_CATEGORIES     4
#define MAX_WIFI_SSID_LEN         33 /* Length = 32 + 1 for Null character at the end */
#define MAX_SSID_LEN              33	/* Length = 32 + 1 for adding NULL character at the end */ 
#define MAX_WIFI_PASSWORD_LEN     65 /* Length = 64 + 1 for Null character at the end */
#define MAX_SECURITY_MODE_STR_LEN 129 //"none wpa-wpa2-psk wep wpa-wpa2 wpa2-psk wpa2 wpa-psk wpa"
#define MAX_FREQUENCY_BANDS_STR_LEN 65 //"radio_2G,radio_5Gu,radio_5Gl"
#define MAX_AUTH_TYPE_LEN         25
#define MAX_MANUFACTURER_NAME_LEN 65 /* Length = 64 (WPS spec) + 1 for adding NULL character at the end */

#define MAX_BH_IFACE_TYPE_STR_LEN 9
/* Flags for MultiAp extension subelement  */
#define MAP_TEAR_DOWN	    0x10	/* Bit 4 */
#define MAP_FRONTHAUL_BSS	0x20	/* Bit 5 */
#define MAP_BACKHAUL_BSS	0x40	/* Bit 6 */
#define MAP_BACKHAUL_STA	0x80	/* Bit 7 */
#define MAX_WIFI_RADIO_NAME_LEN     64

#define HASH_KEY_LEN            22  // sizeof("ALE:00:00:00:00:00:00")
#define MAC_ADDR_START_OFFSET   4

#define MAX_TARGET_CHAN_LEN     5
#define MAX_CHANNEL 54
#define MAX_CHANNEL_IN_OPERATING_CLASS 24
#define MAX_OPERATING_CLASS 32
#define MAX_STA_PER_BSS     128
#define MAX_STATIONS        (MAX_RADIOS_PER_AGENT * 128)
#define MAX_VERSION_LEN 10

#define MULTIAP_AGENT 100
#define MULTIAP_CONTROLLER 102

#define ONE_Gbps 1000


#define PREF_SCORE_0			0
#define PREF_SCORE_15			15

#define PREF_REASON_UNSPECFIED                 0
#define PREF_REASON_RADAR_DETECT               7
#define PREF_REASON_EXT_NETWORK_INTERFERENCE   3

#define MAX_OPERATING_CLASS_COUNT_FOR_2G_RADIO 4
#define MAX_OPERATING_CLASS_COUNT_FOR_5G_RADIO 16

#define TLV_TYPE_FIELD    1
#define TLV_LENGTH_FIELD 2

#define STD_80211_B    0
#define STD_80211_G    1
#define STD_80211_A    2
#define STD_80211_N    3
#define STD_80211_AC   4
#define STD_80211_AN   5
#define STD_80211_ANAC 6
#define STD_80211_AX   7

#define MAP_BSS_TYPE_WPS_ENABLED   1	

#define WIFI_AC_BE 0  /* Best effort Access class */
#define WIFI_AC_BK 1  /* Background Access class */
#define WIFI_AC_VO 2  /* Voice Access class */
#define WIFI_AC_VD 3  /* Video Access class */

#define MAP_ASSOC_STA_LINK_METRICS_INCLUSION_POLICY (1<<6)
#define MAP_ASSOC_STA_TRAFFIC_STA_INCLUSION_POLICY  (1<<7)

#define MAX_NODES_PER_CUMLATIVE_STATS 64
#define MAX_CUM_BSS_STATS              3
#define MAX_CUM_STA_STATS              3
#define MAX_AVAIL_CUM_STATS            (MAX_CUM_BSS_STATS + MAX_CUM_STA_STATS)

#define wifi_esp_ac_mask(element) (element & ((1<<0) | (1<<1)))
#define wifi_esp_data_format_mask(element)     (element & ((1<<3) | (1<<4)))
#define wifi_esp_ba_window_mask(element)       (element & ((1<<5) | (1<<6) | (1<<7)))


#define set_esp_access_category(element) (element & ((1<<0) | (1<<1)))
#define set_esp_data_format(element) (element << 3)
#define set_esp_ba_window(element) (element << 5)

// Use below keys prepended with ALE MAC address of the agent
#define POLICY_CONFIG_RETRY_ID      "-POLICY-CONFIG"
#define AP_CAPS_QUERY_RETRY_ID      "-AP-CAPS-QUERY"
#define CHAN_PREF_QUERY_RETRY_ID    "-AP-CHAN-PREF-QUERY"
#define CHAN_SELEC_REQ_RETRY_ID     "-AP-CHAN-SELC_REQ"
#define TOPOLOGY_QUERY_RETRY_ID     "-TOPOLOGY-QUERY"

// Use below keys prepended with STA MAC address
#define CLIENT_CAPS_QUERRY_RETRY_ID "-CLIENT-CAPS-QUERRY"

static inline void GET_RETRY_ID( uint8_t *mac,
                                 const char* retry_type,
                                 char* retry_id) {
    snprintf((char*)retry_id, MAX_TIMER_ID_STRING_LENGTH, "%02x:%02x:%02x:%02x:%02x:%02x%s",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],retry_type);
}

#define MAP_RETRY_STATUS_SUCCESS     0
#define MAP_RETRY_STATUS_TIMEOUT   (-1)
#define MAP_RETRY_STATUS_CANCELLED (-2)

/* 802.11 Estimated service parameter data format */

enum {
    NO_AGGREGATION,
    AMSDU       = 0x01,
    AMPDU       = 0x02,
    AMSDU_AMPDU = 0x03,
};

enum {
    NO_BLOCK_ACK = 0,
    BLK_ACK_TWO_BYTE_WNDOW_SIZE,
    BLK_ACK_FOUR_BYTE_WNDOW_SIZE,
    BLK_ACK_SIX_BYTE_WNDOW_SIZE,
    BLK_ACK_EIGHT_BYTE_WNDOW_SIZE,
    BLK_ACK_SIXTEEN_BYTE_WNDOW_SIZE,
    BLK_ACK_THIRTY_TWO_BYTE_WNDOW_SIZE,
    BLK_ACK_SIXTYFOUR_BYTE_WNDOW_SIZE,
};

#define MAX_TOTAL_CHANNELS 39 //25 ch for 5GHZ and 14 ch for 2.4Ghz
// beacon measurement related macros
#define MEASUREMENT_SUBTYPE_BEACON_REPORT 5
#define BEACON_REPORT_ELEMENT_SIZE        sizeof(map_beacon_report_element_t)
#define BEACON_REPORT_ELEMENT_HDR_SIZE    2
#define BEACON_REPORT_START_TIME_SIZE     8
#define MAX_AP_REPORT_CHANNELS            32
#define MAX_REPORTS_PER_TLV               32

#define MAX_TLVS_BEACON_METRICS_REPORT    2
#define MAX_BEACON_METRICS_RESPONSE_RETRY 2

#define BEACON_QUERY_MAX_RESPONSE_TIME    5 /* seconds before we expect a platform response */
#define UNASSOC_QUERY_MAX_RESPONSE_TIME   10 /* seconds before we expect a platform response */

enum {
    BEACON_QUERY_STATE_RESPONSE_SENT = 0,
    BEACON_QUERY_STATE_ACK_SENT = 1,
};

enum {

    MEASUREMENT_REQUEST_ELEMENTID = 38,
    MEASUREMENT_REPORT_ELEMENTID = 39,
    MAX_ELEMENTID                = 255,
};


/* Steering related macros */
#define STEERING_REQUEST_MODE_BIT (1<<7)
enum {
    REQUEST_MODE_STEERING_OPPORTUNITY = 0,
    REQUEST_MODE_STEERING_MANDATE     = 1,
};

#define BTM_DISSOC_IMMINENT_BIT (1<<6)
#define BTM_ABRIDGED_BIT        (1<<5)

/* Beacon report status code (se*/
/* Beacon metrics report response status. bit 7 and bit 6 */
#define BEACON_REPORT_STATUS_CODE_SUCCESS     0x00
#define BEACON_REPORT_STATUS_CODE_NO_REPORT   0x40
#define BEACON_REPORT_STATUS_CODE_NO_SUPPORT  0x80
#define BEACON_REPORT_STATUS_CODE_UNSPECIFIED 0xc0

// Use it only in do while loop
#define ERROR_EXIT(status) {status = -1; break;}
#define NULL_EXIT(ptr) {ptr = NULL; break;}

//Use for structs that are memcopied to/from 1905 payload
#define STRUCT_PACKED __attribute__ ((packed))


/*Link metrics macros */
////////////////////////////////////////////////////////////////////////////////
// Media types as detailed in "Table 6-12"
////////////////////////////////////////////////////////////////////////////////
#define MEDIA_IEEE_802_3U_FAST_ETHERNET       (0x0000)
#define MEDIA_IEEE_802_3AB_GIGABIT_ETHERNET   (0x0001)
#define MEDIA_IEEE_802_11B_2_4_GHZ            (0x0100)
#define MEDIA_IEEE_802_11G_2_4_GHZ            (0x0101)
#define MEDIA_IEEE_802_11A_5_GHZ              (0x0102)
#define MEDIA_IEEE_802_11N_2_4_GHZ            (0x0103)
#define MEDIA_IEEE_802_11N_5_GHZ              (0x0104)
#define MEDIA_IEEE_802_11AC_5_GHZ             (0x0105)
#define MEDIA_IEEE_802_11AD_60_GHZ            (0x0106)
#define MEDIA_IEEE_802_11AF_GHZ               (0x0107)
#define MEDIA_IEEE_1901_WAVELET               (0x0200)
#define MEDIA_IEEE_1901_FFT                   (0x0201)
#define MEDIA_MOCA_V1_1                       (0x0300)
#define MEDIA_UNKNOWN                         (0xFFFF)

#define TX_LINK_METRICS_ONLY         (0x00)
#define RX_LINK_METRICS_ONLY         (0x01)
#define BOTH_TX_AND_RX_LINK_METRICS  (0x02)

#define TLV_TRANSMITTER_LINK_METRIC 9
#define TLV_RECEIVER_LINK_METRIC 10



#endif // MULTIAP_COMMON_DEFINES

#ifdef __cplusplus
}
#endif
