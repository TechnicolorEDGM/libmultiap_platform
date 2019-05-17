/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "platform_map.h"
#include <sys/time.h>

volatile unsigned int log_std_out=0;
volatile unsigned int library_log_level = 0;
volatile unsigned int ieee1905_log_level = 0;
volatile unsigned int controller_log_level = 0;
volatile unsigned int agent_log_level = 0;
volatile unsigned int vendor_ipc_log_level = 0;

static char gversion[MAX_VERSION_LEN] = "1.00.00";

uint64_t get_clock_diff_secs(struct timespec new_time, struct timespec old_time)
{
    uint64_t old_ms  = 0;
    uint64_t new_ms  = 0;
    uint64_t diff = 0;

    old_ms = (old_time.tv_sec * 1000) + (old_time.tv_nsec / 1000000);
    new_ms = (new_time.tv_sec * 1000) + (new_time.tv_nsec / 1000000);

    diff = ((new_ms - old_ms + 500)/1000);   /* 500 added To round off
                                                Eg: 4999 milliseconds will be 4.999 seconds
                                                So adding 500 will behave as a round() func.
                                                We are not using math.round() here because
                                                it mandates to include -lm library */

    return diff;
}

uint64_t get_clock_diff_milli_secs(struct timespec new_time, struct timespec old_time)
{
    uint64_t old_ms  = 0;
    uint64_t new_ms  = 0;
    uint64_t diff_ms = 0;

    old_ms = (old_time.tv_sec * 1000) + (old_time.tv_nsec / 1000000);
    new_ms = (new_time.tv_sec * 1000) + (new_time.tv_nsec / 1000000);

    diff_ms = new_ms - old_ms;
    return diff_ms;
}

struct timespec get_current_time()
{
    struct timespec boottime= {0};
    clockid_t clocktype = CLOCK_MONOTONIC;
#ifdef CLOCK_BOOTTIME
    clocktype = CLOCK_BOOTTIME;
#endif
    clock_gettime(clocktype, &boottime);

    return boottime;
}

int platform_config_load(unsigned int cmd,plfrm_config * config)
{

	if (config ==NULL)
		return -1;

	if(config->init_completed)
		return 0;


	if(config->log_output==log_stdout)
	{
		char *termfile;
		termfile = strdup(ttyname(1));
		config->logfile_fd= open(termfile,O_WRONLY | O_NOCTTY);
		if (config->logfile_fd == -1) {
			platform_log(MAP_LIBRARY,LOG_ERR,"\n Error in openning terminal console");
			free(termfile);
			exit(EXIT_FAILURE);
		}
		log_std_out=1;
		free(termfile);
	}
	else if(config->log_output==log_socket)
	{
		//Todo
	}
	else
	{
		config->log_output=log_syslog;
	}

	if(config->config_file == NULL)
	{
		def_config_path(cmd,&(config->config_file));
	}

	platform_log(MAP_LIBRARY,LOG_DEBUG,"Config path is %s\n",config->config_file);

	if(cmd == MAP_PLATFORM_GET_AGENT_CONFIG)
        {
                if(load_agent_config((void*)config))
                        return -1;
        }
        else if(cmd == MAP_PLATFORM_GET_CONTROLLER_CONFIG)
        {
                if(load_controller_config((void*)config))
                        return -1;
        }

        library_log_level = atoi(map_library_log_level);
        ieee1905_log_level = atoi(map_1905_log_level);
        controller_log_level = atoi(map_controller_log_level);
        agent_log_level = atoi(map_agent_log_level);
        vendor_ipc_log_level = atoi(map_vendor_ipc_log_level);

	config->init_completed=1;

	/* store version */
	platform_log(MAP_LIBRARY,LOG_DEBUG,"store version %s \n ",config->map_config.version);
	if ( NULL != config->map_config.version )
		strncpy (gversion, config->map_config.version,MAX_VERSION_LEN );

	return 0;
}

int platform_get_mac_from_string(char * value, uint8_t *mac)
{
        if(value != NULL)
        {
        if(MAC_ADDR_LEN== sscanf(value, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]))
            return 1;
        }
        return 0;
}

int compare_macaddr(void *mac1, void *mac2)
{
    if (mac1 && mac2) {
        if (0 == memcmp(mac1, mac2, MAC_ADDR_LEN))
            return 1;
    }
    return 0;
}

void platform_get_wds_underlying_if(const char *wdsif, char *underlyingif, int length)
{
	char underlying_if[MAX_IFACE_NAME_LEN] = "wl";
	char *tmp = NULL;

	/*Note wds interfaces names and underlying interface names 
	wds1_1.1 	-> 		wl1_1
	wds1_0.1 	-> 		wl1
	wds0_0.1	->		wl0
	wds0_1.1	->		wl0_1
	*/
	tmp = strchr(wdsif,'_');
	if(NULL != tmp) {
		snprintf(underlying_if+2, sizeof(underlying_if)-2,"%c",*(tmp-1));
		if(*(tmp+1) != '0') {
			snprintf(underlying_if+3, sizeof(underlying_if)-3,"_%c",*(tmp+1));
		}
		underlying_if[MAX_IFACE_NAME_LEN-1] = '\0';
		platform_log(MAP_LIBRARY,LOG_DEBUG, "%s underlying if %s\n", __FUNCTION__, underlying_if);
		strncpy(underlyingif, underlying_if, length-1);
	} else {
		platform_log(MAP_LIBRARY,LOG_ERR, "%s wds name not in defined format %s\n", __FUNCTION__, wdsif);
		memset(underlyingif,'\0', length);
	}
	
	return;
}

int platform_str_to_int(char *string, uint8_t * data)
{
        int i, n = 0, decimals_of_ten = 0;

        *data=0;
        for (i = 0; i < strlen(string); i++) {
            decimals_of_ten = 1;
            for (n = i; n < strlen(string)-1; n++)
                decimals_of_ten *= 10;
            if (string[i] >= '0' && string[i] <= '9' ) {
                *data += ((string[i] - '0') * decimals_of_ten);
            } else {
                printf("string has unknown characters\n");
                *data=0;
                return -1;
            }
        }
        return 0;
}

void platform_hexstr_to_charstr(char *hexstring, char *charstr)
{
    int i;
    char one_byte[3];

    for(i = 0; i < strlen(hexstring)/2; i++)
    {
        if (i > UUID_SIZE)
            break;
        one_byte[0] = hexstring[i * 2];
        one_byte[1] = hexstring[(i * 2) + 1];
        one_byte[2] = 0x00;

        charstr[i] = strtoul(one_byte, NULL, 16);
    }
}

static int get_module_loglevel(int module) {
        switch(module) {
            case MAP_LIBRARY:
            {
                return library_log_level;
            }
            case MAP_IEEE1905:
            {
                return ieee1905_log_level;
            }
            case MAP_AGENT:
            {
                return agent_log_level;
            }
            case MAP_CONTROLLER:
            {
                return controller_log_level;
            }
            case MAP_VENDOR_IPC:
            {
                return vendor_ipc_log_level;
            }
        }
        return LOG_INFO;
}

void platform_log(int module,int level,const char *format,...)
{
        int log_level = 0;
	char *buf = NULL;
	char *p;
	char *q;
	int len;
	va_list args;

        log_level = get_module_loglevel(module);

	if ( level > log_level ) {
            return;
        }

	buf = malloc(PRINT_BUF_SIZE);
	if (!buf) {
		return;
	}

	va_start(args, format);

	do {
		len = vsnprintf( buf,  PRINT_BUF_SIZE, (char *)format, args );

		if (len<=0) break;

		if (len >= PRINT_BUF_SIZE) {
			len = PRINT_BUF_SIZE;
			buf[PRINT_BUF_SIZE-1] = 0;
		}

		/* Remove "\r" */
		p = buf;
		q = buf;
		while (*p) {
			if (*p == '\r') {
				p++;
				continue;
			}
			if (p != q) {
				*q = *p;
			}
			p++;
			q++;
		}
		*q = 0;

		if (log_std_out) {
			write(STDOUT_FILENO, buf, len);
		}
		else
		{
			syslog(level, "%s", buf);
		}
	} while (0);

	if (buf) {
		free(buf);
	}

	va_end(args);
	return;
}


int daemonize(plfrm_config * config)
{

	close(STDIN_FILENO);
	if(config->log_output != log_stdout)
	{
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
	}
	else
	{
		dup2(config->logfile_fd,STDOUT_FILENO);
		dup2(config->logfile_fd,STDERR_FILENO);
	}
	if (daemon(1, 1) == -1) {/* don't redirect stdout and stderr to /dev/null */
		fprintf(stderr, "Failed to daemonize process\n");
		exit(EXIT_FAILURE);
	}
	return 0;
}

int event_notify_main_thread(void *mon_q_hdle, void *monitor_q_data)
{
	int ret = 0;
        monitor_q_handle_t *monitor_q_handle = (monitor_q_handle_t *)mon_q_hdle;

	if ((NULL != monitor_q_handle) && (NULL != monitor_q_data))
	{
            if(insert_last_object(monitor_q_handle->list_handle, monitor_q_data)<0) {
               platform_log(MAP_LIBRARY,LOG_ERR, "%s failed to insert obj in monitor queue\n",__func__);
            }
	}
	else
	{
		ret = -1;
		platform_log(MAP_LIBRARY,LOG_ERR," %s Invalid event notification mechanism\n",__FUNCTION__);
	}

	return ret;
}

void map_lib_platform_measure_time_entry(const char *function_name, timing_measurement_t * time_values, uint8_t delta)
{
	gettimeofday(&time_values->entry_time,NULL);

	if(!delta)
	{
		platform_log(MAP_LIBRARY,LOG_DEBUG,"%s: time micro sec: %ld, \t sec: %ld\n",function_name,time_values->entry_time.tv_usec, time_values->entry_time.tv_sec );
	}
	return;
}

void map_lib_platform_measure_time_exit(const char *function_name, timing_measurement_t * time_values, uint8_t delta)
{
	int32_t consumed_time_microsec = 0;
		
	if((NULL == time_values) || (*function_name == '\0'))
	{
		return;
	}

	if(!strncmp(function_name, time_values->function_name, MAX_FUNCTION_NAME_LEN))
	{
		gettimeofday(&time_values->exit_time,NULL);			
		if(!delta)
		{
			platform_log(MAP_LIBRARY,LOG_DEBUG,"%s: time micro sec: %ld, \t sec: %ld\n",function_name,time_values->exit_time.tv_usec, time_values->exit_time.tv_sec );
		}
		else
		{
			consumed_time_microsec = (time_values->exit_time.tv_sec - time_values->entry_time.tv_sec) * 1000000 + (time_values->exit_time.tv_usec-time_values->entry_time.tv_usec);
			platform_log(MAP_LIBRARY,LOG_ERR,"%s: time consumed millisec : %d \n",function_name,consumed_time_microsec/1000);
		}
	}
}


int hexstr_to_uint8(char *str, uint8_t len, uint8_t *byte) {

    uint8_t i, n = 0, decimals_of_sixteen = 0;
    uint8_t ret = 0;

    *byte=0;
    for (i = 0; i < len; i++) {
        decimals_of_sixteen = 1;
        for (n = i; n < len-1; n++)
            decimals_of_sixteen *= 16;
        if (str[i] >= '0' && str[i] <= '9' ) {
            *byte += ((str[i] - '0') * decimals_of_sixteen);
        } else if (str[i] >= 'a' && str[i] <= 'f' ){
            *byte += (((str[i] - 'a') + 10) * decimals_of_sixteen);
        } else if (str[i] >= 'A' && str[i] <= 'F' ){
            *byte += (((str[i] - 'A') + 10) * decimals_of_sixteen);
        } else {
            *byte = 0;
            ret = -1;
            break;
        }
    }
    return ret;
}

int hexstream_to_bytestream(char * str, uint8_t **byte_ptr, uint16_t *length) {
    uint8_t *bytes = NULL;
    uint16_t no_of_bytes = 0;
    char    *str_cpy = NULL;
    uint16_t  i       = 0;

    str_cpy = strdup(str);
    no_of_bytes = strlen(str)/2;
    *length = no_of_bytes;

    bytes = (uint8_t *)calloc(1, no_of_bytes);
    if(bytes == NULL) {
        free(str_cpy);
        return -1;
    }

    *byte_ptr = bytes;

    while(no_of_bytes) {
        if (hexstr_to_uint8(&str_cpy[i], 2, bytes) < 0) {
            free(str_cpy);
            free(bytes);
            return -1;
        }

       platform_log(MAP_LIBRARY,LOG_DEBUG," JSON_DUMP: %c%c - %x\n", str_cpy[i],str_cpy[i+1], *bytes);
        bytes++;
        i +=2;
        no_of_bytes--;
    }

    free(str_cpy);
    return 0;
}

void platform_get_version ( char*  version )
{
	platform_log(MAP_LIBRARY,LOG_DEBUG,"%s version : %s ",__FUNCTION__,gversion );
	strncpy( version,gversion,MAX_VERSION_LEN );
}

#ifndef OPENWRT
int init_signal_handling()
{

	struct sigaction s;
	sigset_t mask;

	/* Register "normal" signals */

	s.sa_flags = SA_SIGINFO;
	s.sa_sigaction = (void *)signal_handler;
	sigemptyset(&s.sa_mask);
	sigaction(SIGSEGV, &s, (struct sigaction *)NULL);
	sigaction(SIGTERM, &s, (struct sigaction *)NULL);

	/* Ignore SIGPIPE which occurs when writing to closed TCP sockets and causes termination */
	signal(SIGPIPE, SIG_IGN);

	return 0;

}
static void signal_handler(unsigned int sn, siginfo_t si, struct ucontext *sc)
{
	static unsigned int recursive_sighandler = 0;

	platform_log(MAP_LIBRARY,LOG_EMERG,"MULTIAPAGENT: RECEIVED SIGNAL %d\r\n", sn);

	if( !recursive_sighandler ) {
		recursive_sighandler = 1;    
		if (sn == SIGSEGV) {
			print_stack(sn, si, sc);
		}
		if (sn== SIGTERM){
			handle_sigterm(sn, si, sc);
		}
	}
	exit(EXIT_FAILURE);
}

static void print_stack(unsigned int sn, siginfo_t si, struct ucontext *sc)
{
	int buffer[8];
	int count;

	platform_log(MAP_LIBRARY,LOG_EMERG, "STACK DUMP at %p: \r\n", buffer);    
		
	for( count = 0 ; count < 512 ; count+=8 ) {
		platform_log(MAP_LIBRARY,LOG_EMERG, "  %08X %08X %08X %08X %08X %08X %08X %08X\r\n", 
		buffer[count], buffer[count+1], buffer[count+2], buffer[count+3],
		buffer[count+4], buffer[count+5], buffer[count+6], buffer[count+7]);		

	}
	return;
}

static void handle_sigterm(unsigned int sn, siginfo_t si, struct ucontext *sc)
{
	//Cleanup anything if required here
	return;
}
#endif


