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

#ifndef PLATFORM_UTILS_H
#define PLATFORM_UTILS_H

#include <stdint.h>
#include <sys/time.h>

#define PATH_NAME_MAX	10

#define PRINT_BUF_SIZE 1024

#define UUID_SIZE 16

#define MAX_FUNCTION_NAME_LEN 64

#define ENTRY_TIME(m) map_lib_platform_measure_time_entry(__FUNCTION__, m, 1);
#define EXIT_TIME(m) map_lib_platform_measure_time_exit(__FUNCTION__, m, 1);

typedef enum _log_levels{
        MAP_LIBRARY,
        MAP_IEEE1905,
        MAP_AGENT,
        MAP_CONTROLLER,
        MAP_VENDOR_IPC,
}log_levels;

typedef struct timing_measurement {
   char function_name[MAX_FUNCTION_NAME_LEN];
   struct timeval entry_time;
   struct timeval exit_time;
} timing_measurement_t;

uint64_t get_clock_diff_secs(struct timespec new_time, struct timespec old_time);

uint64_t get_clock_diff_milli_secs(struct timespec new_time, struct timespec old_time);

struct timespec get_current_time();
int hexstream_to_bytestream(char * str, uint8_t **byte_ptr, uint16_t *length);

int platform_get_mac_from_string(char * value, uint8_t *mac);

int compare_macaddr(void *mac1, void *mac2);

void platform_get_wds_underlying_if(const char *wdsif, char *underlyingif, int length);

int platform_str_to_int(char *string, uint8_t * data);

void* platform_get_mon_context(void);

void platform_hexstr_to_charstr(char *hexstring, char *charstr);

void platform_log(int module,int level,const char *format,...)__attribute__((format(printf,3,4)));

int event_notify_main_thread(void *monitor_q_hdle, void *monitor_event);

void map_lib_platform_measure_time_entry(const char *function_name, timing_measurement_t * time_values, uint8_t delta);

void map_lib_platform_measure_time_exit(const char *function_name, timing_measurement_t * time_values, uint8_t delta);

void platform_get_version ( char*  version );


#endif //PLATFORM_UTILS_H

#ifdef __cplusplus
}
#endif


