/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

#include <stdint.h>
#include <uv.h>
#include <sys/socket.h>
#include <unistd.h>
#include <syslog.h>

#include "map_ipc_event_handler.h"
#include "map_ipc_event_publisher.h"
#include "map_events.h"
#include "monitor_task.h"
#include "platform_map.h"



static map_event_dispatcher_t *map_event_dispatcher_list = NULL;
static uint8_t map_events_count = 0;
static uv_poll_t ipc_event_poll_handle;

void map_ipc_event_dispatcher(uv_poll_t* handle, int status, int events);

int8_t init_map_ipc_handler(uv_loop_t *loop, map_event_dispatcher_t *dispatcher, uint8_t event_count) {
    /* Validate input arguments */
    if( (NULL == dispatcher) || (event_count == 0) ||  (event_count > MAP_LAST_EVENT) ) {
        platform_log(MAP_LIBRARY,LOG_ERR, "Invalid dispatcher loaded");
        return -1;
    }

    if(map_get_main_thread_sockfd() != -1) {
        uv_poll_init(loop, &ipc_event_poll_handle, map_get_main_thread_sockfd());
        uv_poll_start(&ipc_event_poll_handle, (UV_READABLE|UV_DISCONNECT), map_ipc_event_dispatcher);

        map_event_dispatcher_list = dispatcher;
        map_events_count          = event_count;

        return 0;
    }

    platform_log(MAP_LIBRARY,LOG_ERR, "Invalid main thread socket fd");
    return -1;
}

map_handle_event_cb map_get_event_callback(map_monitor_evt_t *event) {
    map_handle_event_cb map_event_cb = NULL;

    if(event == NULL || NULL == map_event_dispatcher_list)
        return map_event_cb;

    for (uint8_t i = 0; i < map_events_count; ++i) {
        if(map_event_dispatcher_list[i].map_event == event->evt){

            if(map_event_dispatcher_list[i].event_cb){
                map_event_cb = map_event_dispatcher_list[i].event_cb;
                break;
            }
            else {
                platform_log(MAP_LIBRARY,LOG_ERR, "%s Invalid Event callback", __FUNCTION__);
                break;
            }
        }
    }
    return map_event_cb;
}

/* TODO: Added as a temporary function here.
 This API should be replaced with map_monitor_free_evt_mem to a different file */
void map_cleanup_event_memory(map_monitor_evt_t *event) {
    if(event && event->evt_data) {
        free(event->evt_data);
    }
}

void map_dispatch_events(map_monitor_evt_t *event) {
    if(NULL == event) {
        platform_log(MAP_LIBRARY,LOG_ERR, "%s Invalid input arguments", __FUNCTION__);
        return;
    }
    
    map_handle_event_cb map_event_cb = map_get_event_callback(event);
    if(map_event_cb){

        /* Dispatch the event to the respective callback */
        map_event_cb(event);

        /* Free event data */
        map_cleanup_event_memory(event);
    }
    else
        platform_log(MAP_LIBRARY,LOG_ERR, "%s Failed to dispatch Event : %d", __FUNCTION__, event->evt);

}

void map_ipc_event_dispatcher(uv_poll_t* handle, int status, int events) {
    if((status < 0) || (events & UV_DISCONNECT)) {
        uv_poll_stop(handle);
    }
    else if(events & UV_READABLE) {
        map_monitor_evt_t event = {MAP_LAST_EVENT, 0, NULL};
        ssize_t byte_count = 0;

        /* Receive the event from socket */
        byte_count = recv(map_get_main_thread_sockfd(), &event, sizeof(map_monitor_evt_t), MSG_DONTWAIT);

        /* Validate the length and event type */
        if( (byte_count == sizeof(map_monitor_evt_t)) && is_valid_ipc_event(&event) )  {

            /* Dispatch the events to the respective callback */
            map_dispatch_events(&event);
        }
        else {
            platform_log(MAP_LIBRARY,LOG_ERR, "%s Invalid event length received in socket %d", __FUNCTION__, byte_count);
        }
    }
    else {
        platform_log(MAP_LIBRARY,LOG_ERR, "%s Error on socket poll" , __FUNCTION__);
    }
}
