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

#ifndef PLATFORM_LIB_CAPI_UTIL_H
#define PLATFORM_LIB_CAPI_UTIL_H

#include <sys/time.h>
#include <unistd.h>
#include <libubox/ustream.h>
#include <uci.h>
#include <uci_blob.h>
#include "libubus.h"
#include <libtransformer.h>
#include "platform_map.h"
#include "mon_platform.h"

#define MAX_INTERFACES_LIST_LEN 128
#define MAX_AP_NAME_LEN 20
#define MAX_SSID_COUNT 16


typedef struct {
	char interface_name[MAX_IFACE_NAME_LEN];
	char bssid[MAX_MAC_STRING_LEN];
	char ap_name[MAX_AP_NAME_LEN];
	char radio_name[RADIO_NAME_LEN];
} wireless_ssid_info_t;


typedef struct{
	int count;
	wireless_ssid_info_t infolist[MAX_SSID_COUNT];
}ssid_info_list_t;


typedef struct {
	char ssid[MAX_SSID_LEN];
	char interface_name[MAX_IFACE_NAME_LEN];
	char bssid[MAX_MAC_STRING_LEN];
	int admin_state;
	int oper_state;
	char ap_name[MAX_AP_NAME_LEN];
	char radio_name[RADIO_NAME_LEN];
} ssid_info_t;


typedef struct{
	int count;
	ssid_info_t infolist[MAX_SSID_COUNT];
}ssid_list_t;


typedef struct _inout_t
{
	void* inptr;
	void* outptr;
}inout_t;


struct ubus_context* get_ubus_context(void);
bool get_uci_config(char *package, char *section, char* option, char* result, int resultlen);
bool set_uci_config(char *package, char *section, char* option, char* result);
bool is_string_in_line(char* line, char* substring);
char* get_interface_for_radio(const char* radio_name);
char* get_mac_string(uint8_t mac[], char *macstring);
struct uci_context* get_uci_context(void);
void write_loaded_values_to_transformer();

bool invoke_ubus_command(void *ctx, char* ubuspath, char* ubuscmd, struct blob_buf *inputbuf, struct blob_attr **msgptr);
bool invoke_ubus_command_ex(void *ctx, char* ubuspath, char* ubuscmd, struct blob_buf *inputbuf, char* inputname,
								ubus_data_handler_t callbackfn, void* cbdata);

int read_value_from_transformer(const char* path, char* value, int length);
int write_value_to_transformer(const char* path, const char* value, bool commitflag);

#endif

#ifdef __cplusplus
}
#endif

