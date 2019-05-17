/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

#include "map_retry_handler.h"
#include "map_common_defines.h"
#include "platform_utils.h"
#include "arraylist.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <syslog.h>

#define CASTO_RETRY(p)  ((map_retry_handler_t*)p)
#define CASTO_MID(p)    ((uint16_t*)p)

#define CONTINUE_RETRY_TIMER    0
#define UNREGISTER_RETRY_TIMER  1

static array_list_t* retry_list = NULL;

// Helper APIs
uint8_t map_retry_timer_cb(char* timer_id, void* retry_obj);
int compare_mid(void* retry_obj, void* mid_to_find);
int compare_retry_id(void* retry_object, void* retry_id_to_find);
static inline void cleanup_retry_obj(map_retry_handler_t *retry_obj, int status, void *compl_user_data);
static uint8_t max_retry_check_and_cleanup(map_retry_handler_t *retry_obj);

static void call_retry_cb(map_retry_handler_t *retry_obj) {
    map_handle_t handle = {{0},{0}, 0, NULL,NULL, 0, retry_obj};

    // Reset the MID
    retry_obj->retry_id = 0;

    if(-1 == retry_obj->retry_cb(&handle, retry_obj->args)) {
        platform_log(MAP_LIBRARY,LOG_ERR, "Retry callback returned error for retry ID %s.\n", retry_obj->timer_id);
    }
    // Catch the mid sent in retry cb
    retry_obj->retry_id = handle.mid;
}

int8_t init_map_retry_handler() {
    retry_list = new_array_list(eListTypeDefault);
    if(retry_list == NULL) {
        platform_log(MAP_LIBRARY,LOG_ERR, " %s Failed to create new array list for retry module.\n",__func__);
        return -1;
    }
    return 0;
}

int8_t map_register_retry( const char*     retry_id,
                           uint8_t         retry_intervel,
                           uint8_t         max_retry_count,
                           void           *args,
                           map_compl_cb_t  compl_cb,
                           map_retry_cb_t  retry_cb) {
    int8_t status = 0;
    map_retry_handler_t *retry_obj = NULL;
    do
    {
        // Input args check
        if(retry_id == NULL || retry_cb == NULL || retry_intervel == 0) {
            platform_log(MAP_LIBRARY,LOG_ERR, "%s Invalid input args. \n",__func__);
            ERROR_EXIT(status)
        }
        size_t str_len = strlen(retry_id);
        if(str_len >= MAX_TIMER_ID_STRING_LENGTH) {
            ERROR_EXIT(status)
        }

        if(is_timer_registered(retry_id)) {
            platform_log(MAP_LIBRARY,LOG_DEBUG, "%s Retry instance(%s) already running.\n",__func__, retry_id);
            ERROR_EXIT(status)
        }

        retry_obj = calloc(1, sizeof(map_retry_handler_t));
        if(retry_obj == NULL) {
            platform_log(MAP_LIBRARY,LOG_ERR, "%s calloc failed. \n",__func__);
            ERROR_EXIT(status)
        }
        
        strncpy(retry_obj->timer_id, retry_id, MAX_TIMER_ID_STRING_LENGTH);
        retry_obj->timer_id[MAX_TIMER_ID_STRING_LENGTH-1] = '\0';
        retry_obj->retry_intervel = retry_intervel;
        retry_obj->max_retry_count = max_retry_count;
        retry_obj->compl_cb = compl_cb;
        retry_obj->retry_cb = retry_cb;
        retry_obj->args = args;

        // Update the retry mid array list
        if(-1 == push_object(retry_list, retry_obj)) {
            platform_log(MAP_LIBRARY,LOG_ERR, "Failed to insert to Retry list : %s", retry_id);
            ERROR_EXIT(status)
        }

        // Register this retry with the periodic timer handler
        if(-1 == map_timer_register_callback(retry_intervel, retry_id, retry_obj, map_retry_timer_cb)) {
            platform_log(MAP_LIBRARY,LOG_ERR, "Failed to register the timer for : %s", retry_id);
            pop_object(retry_list); // Remove the mid Mapping
            ERROR_EXIT(status)
        }

        // Call the first retry callback immediatly
        call_retry_cb(retry_obj);

    } while (0);

    // Cleanup upon failure
    if(-1 == status) {
        free(retry_obj);
    }
    return status;
}

uint8_t map_retry_timer_cb(char* timer_id, void* retry_obj) {

    // Validate the input parameters
    if(timer_id == NULL || retry_obj == NULL || CASTO_RETRY(retry_obj)->retry_cb == NULL) {
        platform_log(MAP_LIBRARY,LOG_ERR, "%s Failed to call retry cb.\n", __func__);
        return UNREGISTER_RETRY_TIMER; // Unregister during error case
    }

    // Call the Retry callback
    call_retry_cb(retry_obj);

    // Max retry check
    return max_retry_check_and_cleanup(CASTO_RETRY(retry_obj));
}

int8_t update_retry_handler(uint16_t mid, void *compl_user_data) {

    map_retry_handler_t *retry_obj = CASTO_RETRY(remove_object(retry_list, &mid, compare_mid));

    // We ain't interested in this CMDU. Nothing to do.
    if(retry_obj == NULL)
        return 0;

    int8_t ret = map_timer_unregister_callback(retry_obj->timer_id);
    if(ret == -1)
        platform_log(MAP_LIBRARY,LOG_ERR, "%s Retry handler cleanup failed for Retry ID: %s.\n", 
                                                                __func__, retry_obj->timer_id);

    platform_log(MAP_LIBRARY,LOG_DEBUG, "%s Retry Timer completed for : %s.\n", __func__, retry_obj->timer_id);

    cleanup_retry_obj(retry_obj, MAP_RETRY_STATUS_SUCCESS, compl_user_data);

    return 0;
}

int8_t restart_retry_timer(const char* retry_id) {
    int8_t status = -1;
    if(retry_id && (MAX_TIMER_ID_STRING_LENGTH > strlen(retry_id))) {
        map_retry_handler_t *retry_obj = CASTO_RETRY(find_object(retry_list, (void *)retry_id, compare_retry_id));
        if(retry_obj){
            retry_obj->retry_count = 0;
            return 0;
        }
    }
    return status;
}

int8_t cleanup_retry_args(int status, void *args, void *compl_user_data) {
    free(args);
    return 0;
}

int compare_mid(void* retry_object, void* mid_to_find) {
    if(*CASTO_MID(mid_to_find) == CASTO_RETRY(retry_object)->retry_id)
        return 1;
    return 0;
}

int compare_retry_id(void* retry_object, void* retry_id_to_find) {
    if(strncmp((char*)retry_id_to_find,CASTO_RETRY(retry_object)->timer_id,MAX_TIMER_ID_STRING_LENGTH) == 0)
        return 1;
    return 0;
}

static inline void cleanup_retry_obj(map_retry_handler_t *retry_obj, int status, void *compl_user_data) {
        if(retry_obj->compl_cb != NULL) {
           retry_obj->compl_cb(status, retry_obj->args, compl_user_data);
        }
        free(retry_obj);
}

static uint8_t max_retry_check_and_cleanup(map_retry_handler_t *retry_obj) {
    // Update the retry count
    retry_obj->retry_count++;

    // Check for max retry count
    if( retry_obj->max_retry_count != 0 &&
        retry_obj->retry_count == retry_obj->max_retry_count) {
        // Max retry count achived stop retry timer 
        // Completion CB should cleanup all the resource passed by user
        remove_object(retry_list, (void *)retry_obj->timer_id, compare_retry_id);
        cleanup_retry_obj(retry_obj, MAP_RETRY_STATUS_TIMEOUT, NULL);
        return UNREGISTER_RETRY_TIMER;
    }
    return CONTINUE_RETRY_TIMER;
}

int8_t map_unregister_retry(const char* retry_id)
{
    int8_t status = 0;
    do
    {
        map_retry_handler_t *retry_obj = CASTO_RETRY(remove_object(retry_list, (void *)retry_id, compare_retry_id));

        if(retry_obj == NULL)
            ERROR_EXIT(status)

        int8_t ret = map_timer_unregister_callback(retry_id);
        if(ret == -1)
        {
            platform_log(MAP_LIBRARY,LOG_ERR, "%s Retry handler cleanup failed for Retry ID: %s.\n",__func__, retry_obj->timer_id);
            ERROR_EXIT(status)
        }

        platform_log(MAP_LIBRARY,LOG_DEBUG, "%s Retry Timer removed for : %s.\n", __func__, retry_obj->timer_id);
        cleanup_retry_obj(retry_obj, MAP_RETRY_STATUS_CANCELLED, NULL);
    } while(0);
    return status;
}
