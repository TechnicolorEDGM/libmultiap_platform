/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

#include "map_timer_handler.h"
#include "map_common_defines.h"
#include "platform_utils.h"
#include "arraylist.h"

#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <syslog.h>
#include <uv.h>

#define TIMER_RUNNING 1
#define TIMER_STOPPED 0


uv_timer_t g_timer_handle;
static uint16_t g_timer_frequency_ms = 0;

array_list_t* registered_callbacks[MAX_PRIO] =  {0};
uint8_t current_timer_state = TIMER_STOPPED;

static uint8_t  start_timer();
static uint8_t  stop_timer();
static int32_t  get_callback_list_size();

int compare_timer_node(void* timer_data, void* timer_id);

void timer_callback(uv_timer_t *handle);

int8_t map_init_timer_handler(uv_loop_t  *loop, uint16_t frequency_sec)
{

    for (uint8_t i = TIMER_PRIO_HIGH; i < MAX_PRIO; ++i)
    {
        registered_callbacks[i] = new_array_list(eListTypeDefault);
        if(registered_callbacks[i] == NULL)
        {
            platform_log(MAP_LIBRARY,LOG_ERR, " %s Failed to create new array list for timer callback.\n",__func__);
            return -1;
        }
    }

    g_timer_frequency_ms = frequency_sec * 1000;
    uv_timer_init(loop, &g_timer_handle);
    start_timer();
    return 0;
}

int8_t map_timer_register_callback( uint16_t  frequency_sec,
                            const char *timer_id, 
                            void    *args,
                            uint8_t (*cb)(char* timer_id, void*)) {
    int8_t status = 0;
    timer_cb_data_t *timer_data = NULL;

    do
    {
        if(cb == NULL || frequency_sec == 0 || timer_id == NULL) {
            ERROR_EXIT(status)
        }

        size_t str_len = strlen(timer_id);
        if(str_len >= MAX_TIMER_ID_STRING_LENGTH) {
            ERROR_EXIT(status)
        }

        // If there is already a timer registered with the same ID
        // return error
        if(is_timer_registered(timer_id)) {
            ERROR_EXIT(status)
        }

        timer_data = calloc(1,sizeof(timer_cb_data_t));
        if(timer_data == NULL) {
            ERROR_EXIT(status)
        }

        timer_data->frequency_sec = frequency_sec;
        timer_data->callback      = cb;
        timer_data->args          = args;
        timer_data->callback      = cb;
        strncpy(timer_data->timer_id, timer_id, str_len);
        NULL_TERMINATE(timer_data->timer_id, str_len)

        if(push_object(registered_callbacks[TIMER_PRIO_HIGH], (void*)timer_data) == -1) {
            platform_log(MAP_LIBRARY,LOG_ERR,"%s Failed to register timer callback \n",__func__);
            free(timer_data);
            ERROR_EXIT(status)
        }

    } while (0);

    return status;
}

uint8_t is_timer_registered(const char *timer_id) {
    for (uint8_t prio_index = 0; prio_index < MAX_PRIO; ++prio_index)
    {
        void *obj = find_object(registered_callbacks[prio_index], (void*)timer_id, compare_timer_node);
        if(obj)
            return 1;
    }
    return 0;
}

void* get_timer_cb_args(const char* timer_id) {
    void *obj = NULL;
    for (uint8_t prio_index = 0; prio_index < MAX_PRIO; ++prio_index) {
        void *obj = find_object(registered_callbacks[prio_index], (void*)timer_id, compare_timer_node);
        if(obj)
            return ((timer_cb_data_t*)obj)->args;
    }
    // Return NULL;
    return obj;
}

int8_t map_timer_unregister_callback(const char* timer_id) {
    int8_t status = 0;
    timer_cb_data_t *timer_data = NULL;

    do
    {
        if(timer_id == NULL) {
            ERROR_EXIT(status)
        }

        size_t str_len = strlen(timer_id);
        if(str_len >= MAX_TIMER_ID_STRING_LENGTH) {
            ERROR_EXIT(status)
        }

        for (uint8_t prio_index = 0; prio_index < MAX_PRIO; ++prio_index) {
            timer_data = find_object(registered_callbacks[prio_index], (void*)timer_id, compare_timer_node);
            if(timer_data){
                timer_data->unregistered = 1;
                break;
            }
        }

        if(NULL == timer_data){
            platform_log(MAP_LIBRARY, LOG_ERR, "%s Timer with ID %s isn't registered yet", __func__, timer_id);
            status = -1;
            break;
        }

    } while (0);

    return status;
}


int8_t cleanup_timer_handler() {

    stop_timer();

    for (uint8_t i = 0; i < MAX_PRIO; ++i) {
        empty_list(registered_callbacks[i]);
    }
    return 0;
}

/* This API 
    => Will be called by UV timer every one sec
    => Iterates through all the registered timers
    => Executes timer callback if expired
    => Removes unregistered timers from the list
*/
void timer_callback(uv_timer_t *handle) {

    for (uint8_t prio_index = 0; prio_index < MAX_PRIO; ++prio_index) {
        int32_t num_timer = list_get_size(registered_callbacks[prio_index]);

        while(num_timer--) {
            timer_cb_data_t *timer_data = pop_object(registered_callbacks[prio_index]);
            if(NULL == timer_data) {
                continue;
            }

            // Remove unregistered timer
            if(timer_data->unregistered) {
                platform_log(MAP_LIBRARY, LOG_DEBUG, "%s Removing unregistered timer from list : %s", __func__, timer_data->timer_id);
                free(timer_data);
                continue;
            }

            // Increment timer tick
            timer_data->ticks++;

            // Check if timer expired
            if(timer_data->ticks == timer_data->frequency_sec) {

                if(timer_data->callback) {

                    // Execute expired timer callback
                    uint8_t unregistered = timer_data->callback(timer_data->timer_id, timer_data->args);

                    // Check return value based unregister triggered.
                    if(unregistered) {
                        platform_log(MAP_LIBRARY, LOG_DEBUG, "%s Removing unregistered timer from list : %s", __func__, timer_data->timer_id);
                        free(timer_data);
                        continue;
                    }
                }

                // Reset the timer tick
                timer_data->ticks = 0;
            }

            // Add the processed timer at the end of the list
            if(insert_last_object(registered_callbacks[prio_index], timer_data)){
                platform_log(MAP_LIBRARY, LOG_ERR, "%s Failed to re-add timer_id : %s", __func__ ,timer_data->timer_id);
                free(timer_data);
            }
        }
    }
}

static uint8_t start_timer()
{
    if(current_timer_state  == TIMER_STOPPED)
    {
        platform_log(MAP_LIBRARY,LOG_DEBUG,"\nStarting the timer\n");
        uv_timer_start(&g_timer_handle, timer_callback, g_timer_frequency_ms, g_timer_frequency_ms);
        current_timer_state = TIMER_RUNNING;
    }
    return 0;
}

static uint8_t stop_timer()
{
    if((current_timer_state  == TIMER_RUNNING) && (get_callback_list_size() == 0))
    {
        platform_log(MAP_LIBRARY,LOG_DEBUG,"\nStopping the timer\n");
        uv_timer_stop(&g_timer_handle);
        current_timer_state = TIMER_STOPPED;
    }
    return 0;
}

static int32_t get_callback_list_size() {
    int32_t count = 0;
    for (uint8_t i = 0; i < MAX_PRIO; ++i) {
        count += list_get_size(registered_callbacks[i]);
    }
    return count;
}

int compare_timer_node(void* timer_data, void* timer_id) {
    if(timer_data && timer_id) {
        if (strncmp(((timer_cb_data_t*)timer_data)->timer_id, (char*)timer_id, MAX_TIMER_ID_STRING_LENGTH) == 0) {
            return 1;
        }
    }
    return 0;
}
