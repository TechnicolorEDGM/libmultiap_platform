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

#ifndef MAP_80211_H
#define MAP_80211_H
#include <stdint.h>
#include <stdbool.h>
#include "map_data_model.h"

/** @brief This will parse the assoc/reassoc body
 *
 *  @param caps Pointer where to store the resulting capabilities
 *  @param body Assoc or re-assoc body (starting from fixed parameters or from IE)
 *  @param body_len Length of body
 *  @param is_5g Indicate if station is connected to 5G or not
 *  @param match_ssid SSID used to validate body
 *  @param match_ssid_len Length of SSID used to validate body
 *  @return The status code 0-success, -ve for failure
 */

int map_80211_parse_assoc_body(map_sta_capability_t *caps, uint8_t *body, int body_len, bool is_5g, uint8_t *match_ssid, int match_ssid_len);

#endif

#ifdef __cplusplus
}
#endif
