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

#ifndef MONITOR_TASK_H
#define MONITOR_TASK_H

#include "platform_map.h"
#include "mon_platform.h"
#include "map_events.h"
#include "map_ipc_event_publisher.h"

/** @brief This is an API to create the monitor thread
 *
 *  This API will be called by agent and controller to communicate 
 *	through the bus
 *
 *  @param uv_event mechanism for notifying events to mainthread
 *  @param is_controller wheather invoking controller.
 *  @return int 
 */
int map_monitor_thread_init(void *uv_event, bool is_controller);


/** @brief This is an API to join the monitor thread
 *
 *  This API will be called by agent and controller to clean up after 
 *	monitor thread terminates
 *
 *  @return int 
 */
int map_monitor_thread_cleanup();

/** @brief This is an API used by MAP agent/controller to free the dynamic mem allocated for event
 *
 *  This API will be called by agent and controller to free up dynamic memory,
 *	allocated for the vent structure and its satellite structures
 *
 *  @param data_ptr pointer to the monitor event structure or cum_stats structure
 *
 */
void map_monitor_free_evt_mem(void *data_ptr);

#endif

#ifdef __cplusplus
}
#endif

