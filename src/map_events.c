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

#include <stdint.h>
#include <syslog.h>
#include "map_events.h"
#include "platform_map.h"

#define ARRAY_SIZE(array,type) (sizeof(array)/sizeof(type))

uint8_t map_get_event_priority(uint8_t map_event) {
    uint8_t event_priority;

    switch (map_event)
    {
        /* Stack the High priority events here.
           Normal priority events will fall back to default case. */
        case MAP_MONITOR_STATION_EVT:
        case MAP_MONITOR_WIRELESS_SSID_RADIO_EVT:
        case MAP_MONITOR_WIRED_LINK_EVENT:
        {
            event_priority =  MAP_HIGH_PRIORITY_EVENT;
            break;
        }
        default:
            event_priority =  MAP_NORMAL_PRIORITY_EVENT;
    }

    return event_priority;
}