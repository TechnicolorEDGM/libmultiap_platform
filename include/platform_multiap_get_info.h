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

#ifndef PLATFORM_MULTIAP_GET_INFO_H
#define PLATFORM_MULTIAP_GET_INFO_H


#include "platform_map.h"
#include "map_data_model.h"


#define MAX_CHANNEL_SET 54
#define MAX_CLASS_TABLE 32

#define MAX_COUNTRY_STR_LEN 32
#define MAX_COUNTRY_LEN 32

typedef struct _wifi_eirp_set {
    uint8_t country[MAX_COUNTRY_STR_LEN];
    uint8_t eirp;
} wifi_eirp_set;

typedef struct _wifi_channel_set {
    uint8_t ch[MAX_CHANNEL_SET];
    uint8_t length;
} wifi_channel_set;

typedef struct _wifi_op_class_table {
    uint8_t op_class;
    wifi_channel_set set;
    uint8_t ch_freq;
    uint8_t bw;
    wifi_eirp_set eirp[MAX_COUNTRY_LEN];
    uint8_t eirp_count;
} wifi_op_class_table;

typedef struct _wifi_op_class_array { 
    uint8_t array[MAX_CLASS_TABLE];
    uint8_t length;
} wifi_op_class_array;

typedef enum _map_radio_states {
    MAP_RADIO_ON                              = 0x0001, /* 0000 0000 0000 0001 */
    MAP_RADIO_FREQUENCY_SUPPORTED             = 0x0002, /* 0000 0000 0000 0010 */
    MAP_RADIO_CONFIGURED                      = 0x0004, /* 0000 0000 0000 0100 */
    MAP_RADIO_M1_SENT                         = 0x0008, /* 0000 0000 0000 1000 */
    MAP_RADIO_M1_RECEIVED                     = 0x0010, /* 0000 0000 0001 0000 */
    MAP_RADIO_M2_SENT                         = 0x0020, /* 0000 0000 0010 0000 */
    MAP_RADIO_UNASSOC_MEASUREMENT_IN_PROGRESS = 0x0040, /* 0000 0000 0100 0000 */
    MAP_RADIO_UNASSOC_MEASUREMENT_SUPPORTED   = 0x0080, /* 0000 0000 1000 0000 */
    MAP_RADIO_POLICY_CONFIG_UPDATED           = 0x0100, /* 0000 0001 0000 0000 */
    MAP_RADIO_CHANNEL_SELECTION_SENT          = 0x0200, /* 0000 0010 0000 0000 */
    MAP_RADIO_FREQUENCY_UNSUPPORTED_BY_CTRL   = 0x8000, /* 1000 0000 0000 0000 */
}map_radio_states_t;

typedef enum _map_bss_states {
    MAP_BSS_ON                             = 0x0001, /* 0000 0000 0000 0001 */
    MAP_BSS_CONFIGURED                     = 0x0002, /* 0000 0000 0000 0010 */
    MAP_BSS_WPS_SSUPPORTED                 = 0x0004, /* 0000 0000 0000 0100 */
    MAP_RADIO_TEARDOWN_BIT                 = 0x0008, /* 0000 0000 0000 1000 */
    MAP_BSS_TEARDOWN_BIT                   = 0x0010, /* 0000 0000 0001 0000 */
    MAP_BSS_FRONTHAUL_BIT                  = 0x0020, /* 0000 0000 0010 0000 */
    MAP_BSS_BACKHAUL_BIT                   = 0x0040, /* 0000 0000 0100 0000 */
}map_bss_states_t;

typedef enum _map_sta_states {
    MAP_STA_CONNECTED           = 0x00, // By default when the sta is created it will be in connected state
    MAP_STA_STEER_IN_PROGRESS   = 0x01,
    MAP_STA_STEER_COMPLETED     = 0x02,
    MAP_STA_DISCONNECTED        = 0x04,
} map_sta_states_t;

static inline void set_state_bit(uint16_t *state, uint16_t bit) {
    *state = (*state) | bit;
}

static inline void reset_state_bit(uint16_t *state, uint16_t bit) {
    *state = (*state) & (~bit);
}

static inline int is_state_bit_set(uint16_t state, uint16_t bit) {
    if (bit == (state & bit))
        return 1;
    return 0;
}

static const uint16_t MUTUALLY_EXCLUSIVE_RADIO_STATES =  (MAP_RADIO_CONFIGURED | MAP_RADIO_M1_SENT | \
                                                        MAP_RADIO_M1_RECEIVED | MAP_RADIO_M2_SENT);

/* Set radio state bit*/


#define set_radio_state_on(radio_state) (set_state_bit(radio_state,MAP_RADIO_ON))

#define set_radio_state_freq_supported(radio_state) {\
                                                      set_state_bit(radio_state,MAP_RADIO_FREQUENCY_SUPPORTED);\
                                                      reset_state_bit(radio_state,MAP_RADIO_FREQUENCY_UNSUPPORTED_BY_CTRL);\
                                                    }
#define set_radio_state_configured(radio_state) {\
                                                  reset_state_bit(radio_state, MUTUALLY_EXCLUSIVE_RADIO_STATES);\
                                                  set_state_bit(radio_state,MAP_RADIO_CONFIGURED);\
                                                }
#define set_radio_state_M1_sent(radio_state) { \
                                                reset_state_bit(radio_state, MUTUALLY_EXCLUSIVE_RADIO_STATES);\
                                                set_state_bit(radio_state,MAP_RADIO_M1_SENT); \
                                             }

#define set_radio_state_M1_receive(radio_state) { \
                                                   reset_state_bit(radio_state, MUTUALLY_EXCLUSIVE_RADIO_STATES);\
                                                   set_state_bit(radio_state,MAP_RADIO_M1_RECEIVED); \
                                                }

#define set_radio_state_M2_sent(radio_state) { \
                                                reset_state_bit(radio_state, MUTUALLY_EXCLUSIVE_RADIO_STATES);\
                                                set_state_bit(radio_state,MAP_RADIO_M2_SENT); \
                                             }

#define set_radio_state_policy_config_updated(radio_state) (set_state_bit(radio_state,MAP_RADIO_POLICY_CONFIG_UPDATED))
#define set_radio_state_channel_selection_sent(radio_state) (set_state_bit(radio_state,MAP_RADIO_CHANNEL_SELECTION_SENT))
#define set_radio_state_freq_supported_by_ctrl(radio_state) (reset_state_bit(radio_state,MAP_RADIO_FREQUENCY_UNSUPPORTED_BY_CTRL))

/*Reset radio state bit*/
#define set_radio_state_off(radio_state) (reset_state_bit(radio_state,MAP_RADIO_ON))
#define set_radio_state_freq_unsupported(radio_state) (reset_state_bit(radio_state,MAP_RADIO_FREQUENCY_SUPPORTED))
#define set_radio_state_unconfigured(radio_state) {\
                                                    reset_state_bit(radio_state,MAP_RADIO_CONFIGURED);\
                                                    reset_state_bit(radio_state,MAP_RADIO_M1_SENT);\
                                                  }
#define set_radio_state_freq_unsupported_by_ctrl(radio_state) (set_state_bit(radio_state,MAP_RADIO_FREQUENCY_UNSUPPORTED_BY_CTRL))
#define set_unassoc_measurement_inprogress(radio_state) (set_state_bit(radio_state,MAP_RADIO_UNASSOC_MEASUREMENT_IN_PROGRESS))
#define set_unassoc_measurement_supported(radio_state) (set_state_bit(radio_state,MAP_RADIO_UNASSOC_MEASUREMENT_SUPPORTED))
#define clear_unassoc_measurement(radio_state) (reset_state_bit(radio_state,MAP_RADIO_UNASSOC_MEASUREMENT_IN_PROGRESS))

/*Get if radio state is set or not*/
#define is_radio_on(radio_state) (is_state_bit_set(radio_state,MAP_RADIO_ON))
#define is_radio_freq_supported(radio_state) (is_state_bit_set(radio_state,MAP_RADIO_FREQUENCY_SUPPORTED))
#define is_radio_configured(radio_state) (is_state_bit_set(radio_state,MAP_RADIO_CONFIGURED))
#define is_radio_M1_sent(radio_state) (is_state_bit_set(radio_state,MAP_RADIO_M1_SENT))
#define is_radio_M1_received(radio_state) (is_state_bit_set(radio_state,MAP_RADIO_M1_RECEIVED))
#define is_radio_M2_sent(radio_state) (is_state_bit_set(radio_state,MAP_RADIO_M2_SENT))
#define is_policy_config_updated(radio_state) (is_state_bit_set(radio_state,MAP_RADIO_POLICY_CONFIG_UPDATED))
#define is_channel_selection_sent(radio_state) (is_state_bit_set(radio_state,MAP_RADIO_CHANNEL_SELECTION_SENT))
#define is_radio_freq_unsupported_by_ctrl(radio_state) (is_state_bit_set(radio_state,MAP_RADIO_FREQUENCY_UNSUPPORTED_BY_CTRL))
#define is_unassoc_measurement_inprogress(radio_state) (is_state_bit_set(radio_state,MAP_RADIO_UNASSOC_MEASUREMENT_IN_PROGRESS))
#define is_unassoc_measurement_supported(radio_state) (is_state_bit_set(radio_state,MAP_RADIO_UNASSOC_MEASUREMENT_SUPPORTED))


/* Set BSS State bit */
#define set_bss_state_on(bss_state) (set_state_bit(bss_state,MAP_BSS_ON))
#define set_bss_state_configured(bss_state) (set_state_bit(bss_state,MAP_BSS_CONFIGURED))
#define set_bss_state_wps_supported(bss_state) (set_state_bit(bss_state,MAP_BSS_WPS_SSUPPORTED))
#define set_bss_state_fronthaul(bss_state) (set_state_bit(bss_state,MAP_BSS_FRONTHAUL_BIT))
#define set_bss_state_backhaul(bss_state) (set_state_bit(bss_state,MAP_BSS_BACKHAUL_BIT))

/* Reset BSS State bit */
#define set_bss_state_off(bss_state) (reset_state_bit(bss_state,MAP_BSS_ON))
#define set_bss_state_unconfigured(bss_state) (reset_state_bit(bss_state,MAP_BSS_CONFIGURED))
#define set_bss_state_wps_unsupported(bss_state) (reset_state_bit(bss_state,MAP_BSS_WPS_SSUPPORTED))



/*Get if bss state is set or not*/
#define is_bss_on(bss_state) (is_state_bit_set(bss_state,MAP_BSS_ON))
#define is_bss_wps_supported(bss_state) (is_state_bit_set(bss_state,MAP_BSS_WPS_SSUPPORTED))
#define is_bss_configured(bss_state) (is_state_bit_set(bss_state,MAP_BSS_CONFIGURED))
#define is_bss_fronthaul(bss_state) (is_state_bit_set(bss_state,MAP_BSS_FRONTHAUL_BIT))
#define is_bss_backhaul(bss_state) (is_state_bit_set(bss_state,MAP_BSS_BACKHAUL_BIT))

// Get the frequency type from operating class.
int8_t get_frequency_type(uint8_t op_class, uint8_t *freq_type, uint16_t *band_type_5G);
void get_operating_class(wifi_channel_set * set, uint8_t bw, char * country, wifi_op_class_array * op_class);

void get_non_operating_ch(uint8_t op_class, wifi_channel_set * non_op_ch, wifi_channel_set * set );

int is_matching_channel_in_opclass(uint8_t op_class, uint8_t channel);

void dump_op_class_array(wifi_op_class_array * op_class);

void dump_ch_set_array(wifi_channel_set * s);

void dump_channel_set(int i);

void dump_table();

int get_operating_class_basic(uint8_t channel);

void get_primary_channel_for_midfreq(uint8_t *channel, uint8_t bw);

uint8_t get_mid_freq(uint8_t channel, uint8_t opclass, uint8_t bw);

int get_bw_from_operating_class(uint8_t op_class, uint8_t *bw);

int get_channel_set_for_rclass(uint8_t rclass, wifi_channel_set *ch_set);

#endif

#ifdef __cplusplus
}
#endif
