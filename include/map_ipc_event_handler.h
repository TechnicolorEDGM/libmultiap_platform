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

#ifndef MAP_IPC_EVENT_HANDLER_H
#define MAP_IPC_EVENT_HANDLER_H

#include <stdint.h>
#include <uv.h>
#include "map_events.h"

// Event handler callback
typedef int8_t (*map_handle_event_cb)(map_monitor_evt_t *event);

// Array of this structure will be used to map the event to respective callback
typedef struct map_event_dispatcher_s
{
    uint8_t             map_event;
    map_handle_event_cb event_cb;
} map_event_dispatcher_t;


/** @brief Initalize IPC event handler module
 *
 *  @param  : uv_loop,
 *          : array of event dispatcher
 *          : array length
 *  @return: 1 - Failure, 0 - Success
 */
int8_t init_map_ipc_handler(uv_loop_t *loop, map_event_dispatcher_t *dispatcher, uint8_t event_count);

#endif

#ifdef __cplusplus
}
#endif

