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

#ifndef MULTIAP_RETRY_HANDLER_H
#define MULTIAP_RETRY_HANDLER_H

#include "map_timer_handler.h"
#include "map_common_defines.h"
#include <stdio.h>
#include <stdint.h>

typedef struct multiap_handle_s map_handle_t;
typedef struct retry_handler_s map_retry_handler_t;
typedef int32_t handle_1905_t;

typedef int8_t (*map_compl_cb_t)(int status, void* args, void *compl_user_data);
typedef int8_t (*map_retry_cb_t)(map_handle_t* handle, void* args);

struct retry_handler_s
{
    char            timer_id[MAX_TIMER_ID_STRING_LENGTH];
    uint16_t        retry_id;
    uint8_t         retry_intervel;
    uint8_t         max_retry_count;
    uint8_t         retry_count;
    map_compl_cb_t  compl_cb;
    map_retry_cb_t  retry_cb;
    void           *args;
};

struct multiap_handle_s {
    uint8_t             dest_addr[MAC_ADDR_LEN]; // TODO : Remove this 
    char                src_iface_name[MAX_IFACE_NAME_LEN]; // TODO : Remove this
    handle_1905_t       handle_1905;             // TODO : Remove this 
    void                *data;
    void                *recv_cmdu;
    uint16_t            mid;
    map_retry_handler_t *retry_handle;
};

/** @brief Initializes the Retry timer module
 *
 *  @param : None
 *  @return -1 or error, 0 on success
 */
int8_t init_map_retry_handler();

/** @brief Register new retry timer callback
 *
 *  
 *
 *  @param : 
 *    retry_id        : Unique retry ID
 *    message_id      : Message ID of the 1905 message sent during retry
 *    retry_intervel  : Peroidicity of the retry
 *    max_retry_count : Maximum allowed retry count
 *                      0   - Infinite retry
 *                      >0  - max retry count
 *    args            : This will be passed as an argument to retry_cb
 *    compl_cb        : retry completion callback.
 *                      Handle args cleanup during completion cb.
 *    retry_cb        : Retry callback to be registered
 *
 *  @return -1 or error, 0 on success
 */
int8_t map_register_retry( const char*     retry_id,
                           uint8_t         retry_intervel,
                           uint8_t         max_retry_count,
                           void           *args,
                           map_compl_cb_t  compl_cb,
                           map_retry_cb_t  retry_cb);

/** @brief Remove existig retry timer
 *
 *
 *
 *  @param :
 *    retry_id        : Unique retry ID
 *  @return -1 or error, 0 on success
 */
int8_t map_unregister_retry(const char* retry_id);

/** @brief Timer callback called from retry timer.
 *
 *  @param : 
 *    timer_id        : Unique timer ID
 *    args            : Pointer to map_retry_handler_t
 *
 *  @return 1 - during the last timer retry
 *          0 - To continue retry
 */
uint8_t map_retry_handler(char* timer_id, void* args);

/** @brief Retry completion check API
 *
 *  @param : 
 *    mid           : Message id of CMDU received
 *    compl_user_data: Userdata provided with completed callback
 *
 *  @return -1 - Error case
 *           0 - Success Case
 */
int8_t update_retry_handler(uint16_t mid, void *compl_user_data);

/** @brief Restart the retry timer
 *
 *  @param : 
 *    mid           : Message id of CMDU received
 *    compl_user_data: Userdata provided with completed callback
 *
 *  @return -1 - Error case
 *           0 - Success Case
 */
int8_t restart_retry_timer(const char* retry_id);

/** @brief This API should be called from retry callback to update the new mid
 *
 *  @param : 
 *    mid : Double pointer to the mid
 *    map_retry_handler_t : Pointer to the retry object
 *
 *  @return - NONE
 */
inline void UPDATE_MID_TO_RETRY(map_retry_handler_t *handle, uint16_t **mid) {
    if(handle && mid)
        *mid = &(handle->retry_id);
}

/** @brief Default completion callback
 *
 *  @param : 
 *    status           : Status after retry ends
 *    args             : Args provided when registering retry
 *    compl_user_data  : User data provided with completed callback
 *
 *  @return -1 - Error case
 *           0 - Success Case
 */
int8_t cleanup_retry_args(int status, void *args, void *compl_user_data);

#endif // MULTIAP_CONTROLLER_TIMER_HANDLER_H

#ifdef __cplusplus
}
#endif
