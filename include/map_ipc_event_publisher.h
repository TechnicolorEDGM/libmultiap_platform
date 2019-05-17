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

#ifndef MAP_IPC_EVENT_PUBLISHER_H
#define MAP_IPC_EVENT_PUBLISHER_H

#include <stdint.h>
#include "arraylist.h"
#include "map_events.h"

// TODO: This queue should not be exposed out of this model
// To support legacy implementation this is implementation.
// Remove it ASAP
array_list_t* map_get_main_thread_event_queue();

/** @brief Initalize IPC event notifier module
 *
 * Initialize the socket pair and event queue.
 *  @param : None
 *  @return: 1 - Failure, 0 - Success
 */
int8_t map_init_ipc_event_notifier();

/** @brief Get the main thread socket discriptor from socket pair.
 *
 *  @param : None
 *  @return: socket file descriptor
 */
int map_get_main_thread_sockfd();

/** @brief Get the monitor thread socket discriptor from socket pair.
 *
 *  @param : None
 *  @return: socket file descriptor
 */
int map_get_monitor_thread_sockfd();

/** @brief Cleanup IPC event notifier module
 *
 *  @param : None
 *  @return: None
 */
void map_cleanup_ipc_event_notifier();

//int8_t map_notify_monitor_thread(map_monitor_cmd_t *cmd);

/** @brief This API used to send event from main thread to monitor thread.
 *
 *  @param : Pointer to event data map_monitor_cmd_t
 *  @return: 1 - Failure, 0 - Success
 */
int map_monitor_send_cmd(map_monitor_cmd_t cmd);

/** @brief This API used to send event from monitor thread to main thread.
 *
 *  @param : Pointer to event data map_monitor_evt_t
 *  @return: 1 - Failure, 0 - Success
 */
int8_t map_notify_main_thread(map_monitor_evt_t *event);

#endif

#ifdef __cplusplus
}
#endif