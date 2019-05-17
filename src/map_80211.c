/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/
/* This file contains functions to parse 80211 frames.  It is based on
   code from hostapd (e.g ieee802_11_parse_elems)
*/
/*#######################################################################
#                       HEADER (INCLUDE) SECTION                        #
########################################################################*/
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <syslog.h>
#include <arpa/inet.h> /* htons */

#include "map_80211.h"
#include "platform_utils.h"
#include "map_data_model.h"

/*#######################################################################
#                       DEFINES                                         #
########################################################################*/

#ifndef BIT
#define BIT(x) (1 << (x))
#endif

/* Runtime check - compiler will optimize this... */
#define IS_BIG_ENDIAN() (htonl(1) == 1)

#define IEEE80211_IE_HDR_LEN            2

/* Fixed part of body size */
#define BODY_ASSOC_REQ_FIXED_SIZE       4
#define BODY_REASSOC_REQ_FIXED_SIZE    10

/* Fixed part of frame size */
#define IEEE80211_HDRLEN               24
#define FRAME_ASSOC_REQ_FIXED_SIZE     (BODY_ASSOC_REQ_FIXED_SIZE   + IEEE80211_HDRLEN)
#define FRAME_REASSOC_REQ_FIXED_SIZE   (BODY_REASSOC_REQ_FIXED_SIZE + IEEE80211_HDRLEN)

/* Assoc/reassoc frame types */
#define IEEE80211_FC_TYPE_MGMT         0
#define IEEE80211_FC_STYPE_ASSOC_REQ   0
#define IEEE80211_FC_STYPE_REASSOC_REQ 2
#define IEEE80211_FC_GET_TYPE(fc)      (((fc) & 0x000c) >> 2)
#define IEEE80211_FC_GET_STYPE(fc)     (((fc) & 0x00f0) >> 4)


/* Information element Id's */
#define IEEE80211_EID_SSID              0
#define IEEE80211_EID_HT_CAP           45
#define IEEE80211_EID_RRM_ENABLED_CAP  70
#define IEEE80211_EID_EXT_CAP         127
#define IEEE80211_EID_VHT_CAP         191
#define IEEE80211_EID_VENDOR_SPECIFIC 221

#define IEEE80211_EID_HT_CAP_LEN              sizeof(ieee80211_ht_cap)
#define IEEE80211_EID_RRM_ENABLED_CAP_LEN     5
#define IEEE80211_EID_EXT_CAP_MIN_LEN         3
#define IEEE80211_EID_VHT_CAP_LEN             sizeof(ieee80211_vht_cap)
#define IEEE80211_EID_VENDOR_SPECIFIC_MIN_LEN 3

/* Fixed capabiltiy bits */
#define IEEE80211_CAP_RRM BIT(12)

/* RRM Enabled Capabilities IE */
/* Byte 1 */
#define IEEE80211_RRM_CAPS_BEACON_REQUEST_PASSIVE BIT(4)
#define IEEE80211_RRM_CAPS_BEACON_REQUEST_ACTIVE  BIT(5)

/* Ext cap */
/* Byte 3 */
#define IEEE80211_EXT_CAPS_BTM BIT(3)

/* HT Cap */
#define IEEE80211_HT_CAP_INFO_SUPP_CHANNEL_WIDTH_SET      BIT(1)
#define IEEE80211_HT_CAP_INFO_SHORT_GI20MHZ               BIT(5)
#define IEEE80211_HT_CAP_INFO_SHORT_GI40MHZ               BIT(6)

/* VHT Cap */
#define IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_160MHZ          BIT(2)
#define IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_160_80PLUS80MHZ BIT(3)
#define IEEE80211_VHT_CAP_SHORT_GI_80                     BIT(5)
#define IEEE80211_VHT_CAP_SHORT_GI_160                    BIT(6)

/* MAP IE */
#define WFA_OUI_BYTE_0                   0x50
#define WFA_OUI_BYTE_1                   0x6F
#define WFA_OUI_BYTE_2                   0x9A
#define WFA_VENDOR_IE_MIN_LEN            4
#define WFA_EID_MAP                      27
#define WFA_SUB_EID_MAP_EXTENSION        6
#define WFA_SUB_EID_MAP_EXTENSION_LEN    1
#define MAP_EXTENSION_BACKHAUL_STA_FLAG  0x80


/*#######################################################################
#                       TYPEDEF                                         #
########################################################################*/
typedef struct ieee802_11_elems {
    uint8_t *ssid;
    uint8_t *ht_cap;
    uint8_t *rrm_enabled_cap;
    uint8_t *ext_cap;
    uint8_t *vht_cap;
    uint8_t *map;

    uint8_t ssid_len;
    uint8_t ht_cap_len;
    uint8_t rrm_enabled_cap_len;
    uint8_t ext_cap_len;
    uint8_t vht_cap_len;
    uint8_t map_len;
} ieee802_11_elems;

typedef struct {
    uint16_t ht_cap_info;
    uint8_t  a_mpdu_params;
    uint8_t  supported_mcs_set[16];
    uint16_t ht_extended_cap;
    uint32_t tx_bf_capability_info;
    uint8_t  asel_cap;
} STRUCT_PACKED ieee80211_ht_cap;

typedef struct {
    uint32_t vht_cap_info;
    struct {
        uint16_t rx_map;
        uint16_t rx_highest;
        uint16_t tx_map;
        uint16_t tx_highest;
    } vht_supported_mcs_set;
} STRUCT_PACKED ieee80211_vht_cap;

/*#######################################################################
#                       HELP FUNCTIONS ENDIAN CONVERSION                #
########################################################################*/
/* Could be done by just including endian.h but that is not portable
   (see mess in hostapd common.h)
*/
static inline uint16_t map_swap_16(uint16_t v)
{
    return ((v & 0xff) << 8) | (v >> 8);
}

static inline uint32_t map_swap_32(uint32_t v)
{
    return ((v & 0xff) << 24) | ((v & 0xff00) << 8) |
           ((v & 0xff0000) >> 8) | (v >> 24);
}

static inline uint16_t map_le_to_host16(uint16_t v)
{
    return IS_BIG_ENDIAN() ? map_swap_16(v) : v;
}

static inline uint32_t map_le_to_host32(uint32_t v)
{
    return IS_BIG_ENDIAN() ? map_swap_32(v) : v;
}

/*#######################################################################
#                       HELP FUNCTIONS                                  #
########################################################################*/
static int parse_ies(ieee802_11_elems *elems, uint8_t *ies, int len)
{
    uint8_t *pos  = ies;
    int      left = len;
    int      ok = 1;

    memset(elems, 0, sizeof(ieee802_11_elems));

    while (left >= 2) {
        uint8_t id   = *pos++;
        uint8_t elen = *pos++;
        left -= 2;

        if (elen > left) {
            // FRV: do not complain, attempt to use so far found IE's
            // platform_log(MAP_LIBRARY,LOG_ERR, "parse_ies: frame failed (id=%d elen=%d left=%d)", id, elen, left);
            // ok = 0;
            break;
        }

        switch(id) {
            case IEEE80211_EID_SSID:
                if (NULL == elems->ssid) {
                    elems->ssid = pos;
                    elems->ssid_len = elen;
                }
            break;
            case IEEE80211_EID_HT_CAP:
                if (NULL == elems->ht_cap && elen == IEEE80211_EID_HT_CAP_LEN) {
                    elems->ht_cap = pos;
                    elems->ht_cap_len = elen;
                }
            break;
            case IEEE80211_EID_RRM_ENABLED_CAP:
                if (NULL == elems->rrm_enabled_cap && elen == IEEE80211_EID_RRM_ENABLED_CAP_LEN) {
                    elems->rrm_enabled_cap = pos;
                    elems->rrm_enabled_cap_len = elen;
                }
            break;
            case IEEE80211_EID_EXT_CAP:
                if (NULL == elems->ext_cap && elen >= IEEE80211_EID_EXT_CAP_MIN_LEN) {
                    elems->ext_cap = pos;
                    elems->ext_cap_len = elen;
                }
            break;
            case IEEE80211_EID_VHT_CAP:
                if (NULL == elems->vht_cap && elen == IEEE80211_EID_VHT_CAP_LEN) {
                    elems->vht_cap = pos;
                    elems->vht_cap_len = elen;
                }
            break;
            case IEEE80211_EID_VENDOR_SPECIFIC:
                /* Check on WFA OUI */
                if (elen >= IEEE80211_EID_VENDOR_SPECIFIC_MIN_LEN &&
                    pos[0] == WFA_OUI_BYTE_0 &&
                    pos[1] == WFA_OUI_BYTE_1 &&
                    pos[2] == WFA_OUI_BYTE_2) {
                    if (NULL == elems->map && elen >= WFA_VENDOR_IE_MIN_LEN &&
                        pos[3] == WFA_EID_MAP) {
                        elems->map = pos;
                        elems->map_len = elen;
                    }
                }
            default:
            break;
        }

        left -= elen;
        pos  += elen;
    }

    if (left) {
        // FRV: do not complain, attempt to use so found IE's
        // platform_log(MAP_LIBRARY,LOG_ERR, "FRV: parse assoc frame failed (left=%d)", left);
        // ok = 0;  Attempt to use correct IE
    }

    return ok;
}

static int parse_ies_check_ssid(ieee802_11_elems *elems, uint8_t *ies, int len, uint8_t *match_ssid, int match_ssid_len)
{
    int ok = parse_ies(elems, ies, len);

    if (ok) {
        if (NULL == elems->ssid || elems->ssid_len != match_ssid_len || memcmp(elems->ssid, match_ssid, match_ssid_len)) {
            ok = 0;
        }
    }

    return ok;

}

static int parse_ies_check_ssid_offset(ieee802_11_elems *elems, uint8_t *body, int body_len, int offset, uint8_t *match_ssid, int match_ssid_len)
{
    return (body_len > offset) &&
           parse_ies_check_ssid(elems, body + offset, body_len - offset, match_ssid, match_ssid_len);
}

static int vht_mcs_map_to_ss(uint32_t map)
{
    int nss = 1;

    if        ((map & 0xc000) != 0xc000) {
        nss = 8;
    } else if ((map & 0x00c0) != 0x00c0) {
        nss = 4;
    } else if ((map & 0x0030) != 0x0030) {
        nss = 3;
    } else if ((map & 0x000c) != 0x000c) {
        nss = 2;
    }

    return nss;
}

static int ht_mcs_set_to_ss(uint8_t *mcs_set)
{
    int nss = 1;

    if        (mcs_set[3]) {
        nss = 4;
    } else if (mcs_set[2]) {
        nss = 3;
    } else if (mcs_set[1]) {
        nss = 2;
    }

    return nss;
}
/*#######################################################################
#                       FUNCTIONS                                       #
########################################################################*/
int map_80211_parse_assoc_body(map_sta_capability_t *caps, uint8_t *body, int body_len, bool is_5g, uint8_t *match_ssid, int match_ssid_len)
{
    ieee802_11_elems  elems     = {0};
    uint16_t          fixed_cap = 0;

    /* There are 5 options:
       - contains the complete body and is an assoc
       - contains the complete body and is a reassoc
       - contains the IE only (BRCM)
       - contains the complete frame and is an assoc  (NG-182051 - Arcadyan interop)
       - contains the complete frame and is a reassoc (NG-182051 - Arcadyan interop)
    */

    do {
        /* Body */
        if (parse_ies_check_ssid_offset(&elems, body, body_len, BODY_ASSOC_REQ_FIXED_SIZE, match_ssid, match_ssid_len)) {
            platform_log(MAP_LIBRARY,LOG_DEBUG, "%s: assoc request body", __FUNCTION__);
            fixed_cap = map_le_to_host16(*(uint16_t*)body);
            break;
        }
        if (parse_ies_check_ssid_offset(&elems, body, body_len, BODY_REASSOC_REQ_FIXED_SIZE, match_ssid, match_ssid_len)) {
            platform_log(MAP_LIBRARY,LOG_DEBUG, "%s: reassoc request body", __FUNCTION__);
            fixed_cap = map_le_to_host16(*(uint16_t*)body);
            break;
        }

        /* IE only */
        if (parse_ies_check_ssid_offset(&elems, body, body_len, 0, match_ssid, match_ssid_len)) {
            platform_log(MAP_LIBRARY,LOG_DEBUG, "%s: body contains IE only", __FUNCTION__);
            break;
        }

        /* Frame */
        if (body_len >= IEEE80211_HDRLEN) {
            uint16_t frame_control = map_le_to_host16(*(uint16_t*)body);
            int      type          = IEEE80211_FC_GET_TYPE(frame_control);
            int      sub_type      = IEEE80211_FC_GET_STYPE(frame_control);
            if (type == IEEE80211_FC_TYPE_MGMT && sub_type == IEEE80211_FC_STYPE_ASSOC_REQ &&
                parse_ies_check_ssid_offset(&elems, body, body_len, FRAME_ASSOC_REQ_FIXED_SIZE, match_ssid, match_ssid_len)) {
                platform_log(MAP_LIBRARY,LOG_DEBUG, "%s: assoc request frame", __FUNCTION__);
                fixed_cap = map_le_to_host16(*(uint16_t*)(body + IEEE80211_HDRLEN));
                break;
            }
            if (type == IEEE80211_FC_TYPE_MGMT && sub_type == IEEE80211_FC_STYPE_REASSOC_REQ &&
                parse_ies_check_ssid_offset(&elems, body, body_len, FRAME_REASSOC_REQ_FIXED_SIZE, match_ssid, match_ssid_len)) {
                platform_log(MAP_LIBRARY,LOG_DEBUG, "%s: reassoc request frame", __FUNCTION__);
                fixed_cap = map_le_to_host16(*(uint16_t*)(body + IEEE80211_HDRLEN));
                break;
            }
        }

        platform_log(MAP_LIBRARY,LOG_ERR, "%s: could not parse body", __FUNCTION__);
    } while(0);

    /* Fill in capability */
    memset(caps, 0, sizeof(map_sta_capability_t));

    /* Defaults (can be changed later) */
    caps->max_tx_spatial_streams = 1;
    caps->max_rx_spatial_streams = 1;
    caps->max_bandwidth = 20;

    /* Standard (ignore 11B) */
    if (is_5g && elems.vht_cap) {
        caps->supported_standard = STD_80211_AC;
    } else if (elems.ht_cap) {
        caps->supported_standard = STD_80211_N;
    } else if (is_5g) {
        caps->supported_standard = STD_80211_A;
    } else {
        caps->supported_standard = STD_80211_G;
    }

    /* VHT (5G only) and HT CAP - see dapi_fill_bssinfo_from_ie in hostapd */
    if (is_5g && elems.vht_cap) {
        ieee80211_vht_cap *vht_cap      = (ieee80211_vht_cap *)elems.vht_cap;
        uint32_t           vht_cap_info = map_le_to_host32(vht_cap->vht_cap_info);

        caps->max_bandwidth          = vht_cap_info & (IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_160MHZ | IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_160_80PLUS80MHZ) ? 160 : 80;
        caps->sgi_support            = vht_cap_info & (IEEE80211_VHT_CAP_SHORT_GI_80 | IEEE80211_VHT_CAP_SHORT_GI_160) ? 1 : 0;
        caps->max_tx_spatial_streams = vht_mcs_map_to_ss(map_le_to_host32(vht_cap->vht_supported_mcs_set.tx_map));
        caps->max_rx_spatial_streams = vht_mcs_map_to_ss(map_le_to_host32(vht_cap->vht_supported_mcs_set.rx_map));

    } else if (elems.ht_cap) {
        ieee80211_ht_cap *ht_cap      = (ieee80211_ht_cap *)elems.ht_cap;
        uint16_t          ht_cap_info = map_le_to_host16(ht_cap->ht_cap_info);

        caps->max_bandwidth = ht_cap_info & IEEE80211_HT_CAP_INFO_SUPP_CHANNEL_WIDTH_SET ? 40 : 20;
        caps->sgi_support   = ht_cap_info & (IEEE80211_HT_CAP_INFO_SHORT_GI20MHZ | IEEE80211_HT_CAP_INFO_SHORT_GI40MHZ) ? 1 : 0;
        caps->max_tx_spatial_streams = ht_mcs_set_to_ss(ht_cap->supported_mcs_set);  /* ?? - actually gives rx set */
        caps->max_rx_spatial_streams = ht_mcs_set_to_ss(ht_cap->supported_mcs_set);
    }

    /* 11K */
    /* Support when either mentioned in fixed cap or the RRM IE is present */
    caps->dot11k_support = fixed_cap & IEEE80211_CAP_RRM ? 1 : 0;
    if (elems.rrm_enabled_cap) {
        caps->dot11k_support = 1;
        caps->dot11k_brp_support = elems.rrm_enabled_cap[0] & IEEE80211_RRM_CAPS_BEACON_REQUEST_PASSIVE ? 1 : 0;
        caps->dot11k_bra_support = elems.rrm_enabled_cap[0] & IEEE80211_RRM_CAPS_BEACON_REQUEST_ACTIVE  ? 1 : 0;
    }

    /* 11V */
    if (elems.ext_cap) {
        caps->dot11v_btm_support = elems.ext_cap[2] & IEEE80211_EXT_CAPS_BTM ? 1 : 0;
    }

    /* MAP */
    if (elems.map) {
        /* Check for MAP extension sub element */
        if (elems.map_len >= WFA_VENDOR_IE_MIN_LEN + IEEE80211_IE_HDR_LEN + WFA_SUB_EID_MAP_EXTENSION_LEN) {
            if (elems.map[4]==WFA_SUB_EID_MAP_EXTENSION && elems.map[5]==WFA_SUB_EID_MAP_EXTENSION_LEN) {
                caps->backhaul_sta = elems.map[6] & MAP_EXTENSION_BACKHAUL_STA_FLAG ? 1 : 0;
            }
        }
    }

    return 0;
}
