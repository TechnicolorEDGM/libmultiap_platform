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

#ifndef MULTIAP_TIMER_HANDLER_H
#define MULTIAP_TIMER_HANDLER_H

#include "map_common_defines.h"
#include <stdio.h>
#include <uv.h>

#define TIMER_FREQUENCY_ONE_SEC     1

typedef enum timer_prio {
    TIMER_PRIO_HIGH,
    MAX_PRIO, // Keeping this as sigle priority
//    TIMER_PRIO_NORMAL, // Priority is not used for now. In future if requirement comes it will be used.
} timer_priority_e;

typedef struct timer_cb_data {
    char        timer_id[MAX_TIMER_ID_STRING_LENGTH];
    uint16_t    frequency_sec;
    uint16_t    ticks;
    uint8_t     unregistered;
    void        *args;
    uint8_t (*callback)(char* timer_id, void *arg);
} timer_cb_data_t;

#define NULL_TERMINATE(str, pos) {str[pos] = '\0';}

/*
 *  @brief Delete all the nodes from array_list_t
 */
#define empty_list(list) for(void* obj = NULL; (NULL != (obj = pop_object(list))); free(obj))

/** @brief Initializes the UV timer module
 *
 *  This will initalize the UV timer resources
 *
 *  @param loop : A valid pointer to uv_loop_t
 *  @return -1 or error, 0 on success
 */
int8_t map_init_timer_handler(uv_loop_t  *loop, uint16_t frequency_sec);

/** @brief Register timer callback 
 *
 *  This will register a new timer call back
 *
 *  @param
 *    frequency_ms    - Frequency of the callback
 *    timer_id        - pointer to char will be filled unique timer id for later usage.
 *
 *    timer_priority  - High priority callbacks will be called processed first
 *                          and then the normal priority callbacks.
 *    cb              - Function call back (with below signature) to be called upon timer expiry
 *                          int8_t (*cb)(uint16_t timer_id, void*)
 *
 *  @return -1 or error, 0 on success
 */
int8_t map_timer_register_callback(   uint16_t     frequency_sec,
                            const char   *timer_id ,
                            void         *args,
                            uint8_t (*cb)(char* timer_id, void*));


/** @brief Check if the timer id is registered.
 *
 *  This API will identify if the timer ID is registed already or not.   
 *
 *  @param
 *    timer_id        - pointer to char will be unique timer that we are searching for.
 *
 *
 *  @return 1 if exists or 0 if not
 */
uint8_t is_timer_registered(const char   *timer_id);

/** @brief Un-register timer callback 
 *
 *  This will remove the already registered callback
 *
 *  @param
 *    timer_id        - unique timer ID used during map_timer_register_callback
 *
 *  @return Pointer to args passed during map_timer_register_callback
 */
int8_t map_timer_unregister_callback(const char *timer_id);

/** @brief 
 *
 *  This API should only be called before calling unregister
 *  
 *  @return Pointer to args passed during map_timer_register_callback
 */
void* get_timer_cb_args(const char *timer_id);
/** @brief Cleanup all the timer resources
 *
 *  This API should only be called upon exiting the controller/Agent
 *
 *  @return -1 or error, 0 on success
 */
int8_t cleanup_timer_handler();

#endif // MULTIAP_TIMER_HANDLER_H

#ifdef __cplusplus
}
#endif
