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
#include <sys/socket.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include "map_ipc_event_publisher.h"
#include "map_events.h"
#include "platform_map.h"

#define SOCK_PAIR_COUNT                 2
#define MONITOR_THREAD_SOCK_FD_INDEX    0
#define MAIN_THREAD_SOCK_FD_INDEX       1
#define INVALID_SOCK_FD                -1

static int map_ipc_sockets[SOCK_PAIR_COUNT] = {INVALID_SOCK_FD,INVALID_SOCK_FD};

inline int map_get_main_thread_sockfd() {
    return map_ipc_sockets[MAIN_THREAD_SOCK_FD_INDEX];
}

inline int map_get_monitor_thread_sockfd() {
    return map_ipc_sockets[MONITOR_THREAD_SOCK_FD_INDEX];
}

array_list_t* map_get_main_thread_event_queue() {
    static array_list_t *event_queue = NULL;
    if(NULL == event_queue) {
        /* Create Atomic queue which will be shared from monitor thread to main thread */
        event_queue = new_array_list(eListTypeAtomic);

        if(NULL == event_queue) {
             platform_log(MAP_LIBRARY,LOG_ERR, "%s %d Failed to get event queue \n", __func__, __LINE__);            
        }
    }
    return event_queue;
}

inline uint8_t is_valid_command(map_monitor_cmd_t *cmd) {
    if( cmd && (cmd->cmd > MAP_MONITOR_MIN_CMD) && (cmd->cmd < MAP_MONITOR_MAX_CMD) && 
        ((cmd->subcmd > MAP_MONITOR_MIN_SUBCMD) && (cmd->subcmd < MAP_MONITOR_MAX_SUBCMD)))
        return 1;
    return 0;
}

int8_t map_init_ipc_event_notifier() {

    /* Create socket pair for IPC between Monitor thread and main thread */
    if(socketpair(AF_LOCAL, SOCK_DGRAM, 0, map_ipc_sockets) < 0) {
        platform_log(MAP_LIBRARY,LOG_ERR, "%s Failed to open socket pair with error : %d (%s)\n", __FUNCTION__, errno, strerror(errno));
        return -1;
    }

    platform_log(MAP_LIBRARY,LOG_INFO, "socker pair fd[0] : %d , fd[1] : %d", map_ipc_sockets[0], map_ipc_sockets[1]);

    /* Ensure main thread event queue is created properly */
    if(NULL == map_get_main_thread_event_queue()) {
        platform_log(MAP_LIBRARY,LOG_ERR, "%s Failed to create main thread event queue",__FUNCTION__);
        return -1;
    }

    return 0;
}

void map_cleanup_ipc_event_notifier() {
    close(map_get_main_thread_sockfd());
    close(map_get_monitor_thread_sockfd());
    return;
}

int map_monitor_send_cmd(map_monitor_cmd_t event_cmd) {
    map_monitor_cmd_t *cmd = &event_cmd; /* TODO: After API rename remove it
    int8_t map_notify_monitor_thread(map_monitor_cmd_t *cmd) {*/
    ssize_t byte_count = 0;

    if(NULL == cmd || !is_valid_command(cmd)){
        platform_log(MAP_LIBRARY,LOG_ERR,"%s Invalid command CMD: %d, SUBCMD : %d \n", __FUNCTION__, cmd->cmd, cmd->subcmd);
        return -1;
    }

    /* Write the the data into socket*/
    byte_count = write(map_get_main_thread_sockfd(), cmd, sizeof(map_monitor_cmd_t));

    /* Ensure the complete write*/
    if(byte_count != sizeof(map_monitor_cmd_t)) {
        platform_log(MAP_LIBRARY,LOG_ERR,"%s Failed to send CMD: %d, SUBCMD : %d, byte_count : %d \n", __FUNCTION__,cmd->cmd, cmd->subcmd, byte_count);
        return -1;
    }
    
    return 0;
}

int8_t map_notify_main_thread(map_monitor_evt_t *event) {
    int8_t status = 0;
    ssize_t byte_count = 0;
    do
    {
        if(NULL == event) {
            platform_log(MAP_LIBRARY,LOG_ERR, "%s Invalid Input parameter!", __FUNCTION__ );
            status = -1;
            break;
        }

        /* Get the event priority the select IPC medium */
        uint8_t event_priority = map_get_event_priority(event->evt);
        platform_log(MAP_LIBRARY,LOG_INFO, "Sending Event to main thread : %d", event->evt);
        platform_log(MAP_LIBRARY,LOG_INFO, "Event data                   : %p", event->evt_data);
        platform_log(MAP_LIBRARY,LOG_INFO, "priority                     : %d", event_priority);

        /* Send high priority events via socker */
        if( MAP_HIGH_PRIORITY_EVENT == event_priority) {
            /* Write the the data into socket */
            byte_count = write(map_get_monitor_thread_sockfd(), event, sizeof(map_monitor_evt_t));

            // Ensure the complete write
            if(byte_count != sizeof(map_monitor_evt_t)) {
                platform_log(MAP_LIBRARY,LOG_ERR,"%s Failed to notify main thread :byte_count Actual(%d) Sent(%d)",\
                                        __FUNCTION__, sizeof(map_monitor_evt_t), byte_count); 
                status = -1;
                break;
            }
        }
        /* Normal priority events should be sent via event queue  */
        else {
            if(insert_last_object(map_get_main_thread_event_queue(), event) < 0) {
                platform_log(MAP_LIBRARY,LOG_ERR, "%s Failed to insert obj into event queue", __FUNCTION__);
                status = -1;
                break;
            }
        }
    } while (0);

    return status;
}
