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

#ifndef PLATFORM_LIB_TEST_H
#define PLATFORM_LIB_TEST_H

#include <libubox/ustream.h>
#include <uci_blob.h>
#include "libubus.h"

void print_blob_info(const struct blob_attr *msg, int cnt, int acnt);
void print_api_result(int cmd, const char* cmdstr, const char* subcmd, void* capi, void* output, int status);
void print_cumulative_sta_stats(void* config, void* capi, int status);
void print_cumulative_bss_stats(void* config, void* capi, int status);
void print_get_config(int cmd, const char* cmdstr, const char* subcmd, void* capi, void* output, int status);
void print_bss_state_info(int cmd, const char* cmdstr, const char* subcmd, void* capi, void* output, int status);
void print_set_ieee_wifi_params(int cmd, const char* cmdstr, const char* subcmd, void* capi, void* output, int status);
void print_set_steer(int cmd, const char* cmdstr, const char* subcmd, void* capi, void* output, int status);
void print_autoconfig_result(void *data);

#endif

#ifdef __cplusplus
}
#endif

