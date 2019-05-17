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

#ifndef MULTIAP_CONTROLLER_DATA_MODEL_DUMPER_H
#define MULTIAP_CONTROLLER_DATA_MODEL_DUMPER_H

#include <stdio.h>
#include "hashmap.h"
#include "arraylist.h"
#include "map_common_defines.h"
#include "map_data_model.h"


/** @brief Initializes the dumper
 *
 *  @param pointer to data model Hash table 
 *  @return -1 or error, 0 on success
 */
void init_dumper(hash_map_t* data_model);

/** @brief This will dump the agent info tree on the terminal
 *
 * It prints all the agents data in the below hierarchy
 *
 *  Agent Info
 *          |_ Radio info
 *                      |_ BSS info
 *  @param None
 *  @return Node
 */
void print_agent_info_tree();

/** @brief This will dump the agent info on the terminal
 *
 * It prints the agent data in the below hierarchy
 *
 *  Agent Info
 *          |_ Radio info
 *                      |_ BSS info
 *  @param None
 *  @return Node
 */
void print_agent_info(map_ale_info_t *ale);

/** @brief This will dump list of STA mac and its associated BSS ID.
 *
 * 
 *
 *  Prints the table in below format 
 *          ---------------------
 *          | STA MAC |  BSS ID |
 *          ---------------------
 *  @param None
 *  @return Node
 */
void print_sta_bss_mapping();

/** @brief Prints Radio capabilities
 *
 *  @param list   : map_radio_info_t
 *  @return void
 */
void map_print_radio_caps(map_radio_info_t*);

/** @brief Prints channel preference data of ALE
 *
 *  @param list   : map_radio_info_t
 *  @return void
 */
void print_opclass_in_radio(map_radio_info_t *radio);

/** @brief Prints all the key in data model
 *
 *  @param list   : None
 *  @return void
 */
void dump_hash_keys();

#endif // MULTIAP_CONTROLLER_DATA_MODEL_H

#ifdef __cplusplus
}
#endif
