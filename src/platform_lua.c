/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

#include <string.h>
#include "platform_map.h"
#include "platform_lua.h"


#define LUA_SCRIPTS_PATH "/usr/bin/"

static platform_handle_lua platform_table_lua[]=
{
	{MAP_PLATFORM_GET_MULTIAP_CONFIG,load_once,"get_multiap_config","multiap_getconfig.lua",get_config,NULL},
	{MAP_PLATFORM_GET_IEEE1905_CONFIG,load_once,"get_ieee1905_config","ieee1905_get_info.lua",get_config,NULL},
	{MAP_PLATFORM_GET_INTERFACE_INFO,load_once,"get_interface_info_all","ieee1905_get_info.lua",get_interface_info,NULL},
	{MAP_PLATFORM_GET_AP_AUTOCONFIG,load_once,"get_AP_Autoconfig","multiap_agent_tlvs.lua",get_ap_autoconfig,NULL},
	{MAP_PLATFORM_SET_IEEE_1905_WIFI_PARAMS,load_once,"set_wifi_params","ieee1905_set.lua",NULL,set_wifi_params},
	{MAP_PLATFORM_GET_MAP_MAC_ADDRESS,load_once,"get_map_mac","multiap_getconfig.lua",get_map_mac_address,NULL},
	{MAP_PLATFORM_GET_IEEE_INTERFACE_FROM_MAC,load_once,"get_if_from_mac","ieee1905_get_info.lua",get_config,NULL},
	{MAP_PLATFORM_GET_INTERFACE_STATE,load_once,"get_interface_state","ieee1905_get_info.lua",get_config,NULL},
	{MAP_PLATFORM_GET_SSID,load_once,"get_ssid","multiap_getconfig.lua",get_config,NULL},
	{MAP_PLATFORM_GET_WPA_PSK,load_once,"get_psk","multiap_getconfig.lua",get_config,NULL},
	{MAP_PLATFORM_GET_FREQUENCY_BAND,load_once,"get_freqband_from_if","multiap_getconfig.lua",get_frequency_band,NULL},
	{MAP_PLATFORM_GET_VALID_FHBH_INTERFACE,load_once,"get_valid_interface","multiap_getconfig.lua",get_config,NULL},
	{MAP_PLATFORM_GET_RADIO_INFO,load_once,"get_radioinfo","multiap_agent_tlvs.lua",get_radio_info,NULL},
	{MAP_PLATFORM_GET_AGENT_BSSID,load_once,"get_bssid_from_ap","multiap_agent_tlvs.lua",get_config,NULL},
	{MAP_PLATFORM_GET_BRIDGE_INFO, load_once, "get_bridge_conf", "ieee1905_get_info.lua", get_bridge_conf, NULL},
	{MAP_PLATFORM_GET_2G_CHANNEL_PREF,load_once,"get_channel_pref","multiap_agent_tlvs.lua",get_current_channel_preference,NULL},
	{MAP_PLATFORM_GET_CONTROLLER_POLICY_CONFIG,load_once,"get_controller_policy_config","multiap_getconfig.lua",controller_load_policy_config,NULL},
	{MAP_PLATFORM_SET_CONTROLLER_INTERFACE_LINK,load_once,"set_controller_link_name","ieee1905_set.lua",NULL,set_config},
	{MAP_PLATFORM_GET_CUMULATIVE_BSS_STATS,load_once,"get_cumulative_bss_stats","multiap_agent_metrics.lua",get_cumulative_bss_stats,NULL},
	{MAP_PLATFORM_GET_CUMULATIVE_STA_STATS,load_once,"get_cumulative_sta_stats","multiap_agent_metrics.lua", get_cumulative_sta_stats, NULL},
	{MAP_PLATFORM_APPLY_ACL,load_once,"map_apply_acl","ieee1905_set.lua",NULL,map_apply_acl},
	{MAP_PLATFORM_QUERY_BEACON_METRICS,load_once,"map_query_beacon_metrics","multiap_agent_metrics.lua", NULL, map_query_beacon_metrics},
	{MAP_PLATFORM_GET_BEACON_METRICS_RESPONSE,load_once,"map_beacon_metrics_response","multiap_agent_metrics.lua",map_beacon_metrics_response, NULL},
	{MAP_PLATFORM_GET_RADIO_BSS_STATE_INFO,load_once,"get_radio_and_bss_state","multiap_agent_tlvs.lua",get_radio_bss_state,NULL},
	{MAP_PLATFORM_LEGACY_STA_STEER,load_once,"map_legacy_sta_steer","multiap_agent_sta_steer.lua", NULL, map_legacy_sta_steer},
	{MAP_PLATFORM_BTM_STA_STEER,load_once,"map_btm_sta_steer","multiap_agent_sta_steer.lua", NULL, map_btm_sta_steer},
	{MAP_PLATFORM_GET_AP_FROM_BSSID,load_once,"get_ap_from_bssid","ieee1905_set.lua",get_config,NULL},
	{MAP_PLATFORM_GET_ASSOC_FRAME,load_once,"get_assoc_frame","multiap_agent_tlvs.lua", get_assoc_frame,NULL},
        {MAP_PLATFORM_SET_IEEE_1905_OFF_BSS,load_once,"switch_off_bss","ieee1905_set.lua",NULL,teardown_wifi_bss},
        {MAP_PLATFORM_SET_IEEE_1905_OFF_RADIO,load_once,"switch_off_radio","ieee1905_set.lua",NULL,teardown_wifi_bss},
};

unsigned int gnum_commands_lua=sizeof(platform_table_lua)/sizeof(platform_handle_lua);

static int lua_prepare(unsigned int cmd_index, lua_State **L,const char* subcmd, void *ctxt);

#define LUA_SCRIPTS_PATH "/usr/bin/"

int platform_get_lua(unsigned int command,const char* subcmd,void* data)
{
	lua_State *L;

	if((command & CMD_MASK)> COMMAND_END)
	{
		platform_log(MAP_LIBRARY,LOG_EMERG,"invalid arguments for %s",__FUNCTION__);
		return -1;
	}
	//platform_log(MAP_LIBRARY,LOG_DEBUG,"Number of commands is :%d",gnum_commands_lua);
	for(int i=0; i<gnum_commands_lua; i++)
	{
		if(platform_table_lua[i].command == command)
		{
	//		platform_log(MAP_LIBRARY,LOG_DEBUG,"command to execute %d",command);
			if(lua_prepare(i,&L,subcmd,NULL))
				goto Failure;

			if(platform_table_lua[i].get_data(L,data))
				goto Failure;

			lua_close(L);
			break;
		}
	}

	return 0;

Failure:
	lua_close(L);
	return -1;
}

int platform_get_context_lua(unsigned int command,const char* subcmd,void* data, void *ctxt)
{
	lua_State *L;

	if((command & CMD_MASK)> COMMAND_END || ctxt == NULL)
	{
		platform_log(MAP_LIBRARY,LOG_EMERG,"invalid arguments for %s",__FUNCTION__);
		return -1;
	}
	//platform_log(MAP_LIBRARY,LOG_DEBUG,"Number of commands is :%d",gnum_commands_lua);
	for(int i=0; i<gnum_commands_lua; i++)
	{
		if(platform_table_lua[i].command == command)
		{
	//		platform_log(MAP_LIBRARY,LOG_DEBUG,"command to execute %d",command);
			if(lua_prepare(i,&L,subcmd,ctxt))
				goto Failure;

			if(platform_table_lua[i].get_data(L,data))
				goto Failure;

			lua_close(L);
			break;
		}
	}

	return 0;

Failure:
	lua_close(L);
	return -1;

}


int platform_set_lua(unsigned int command,void* data)
{
	char json_string[200];
	lua_State *L;

	if((command & CMD_MASK)> COMMAND_END)
	{
		platform_log(MAP_LIBRARY,LOG_EMERG,"invalid arguments for %s",__FUNCTION__);
		return -1;
	}
	// platform_log(MAP_LIBRARY,LOG_DEBUG,"Number of commands is :%d",gnum_commands_lua);
	for(int i=0; i<gnum_commands_lua; i++)
	{

		if(platform_table_lua[i].command == command)
		{
			//platform_log(MAP_LIBRARY,LOG_DEBUG,"command to execute %d\n",command);

			if(platform_table_lua[i].set_data(data, json_string))
			return -1;

			if(json_string == NULL)
			return -1;

			if(lua_prepare(i,&L,json_string,NULL))
        	{
        		lua_close(L);
			return -1;
        	}

			/*Leak Detection Fix */
			lua_close(L);
		}

	}

	return 0;
}

int platform_set_context_lua(unsigned int command,void* data, void *ctxt)
{
	char json_string[512];
	lua_State *L;

	if((command & CMD_MASK)> COMMAND_END || ctxt == NULL)
	{
			platform_log(MAP_LIBRARY,LOG_EMERG,"invalid arguments for %s",__FUNCTION__);
			return -1;
	}
	//platform_log(MAP_LIBRARY,LOG_DEBUG,"Number of commands is :%d",gnum_commands_lua);
	for(int i=0; i<gnum_commands_lua; i++)
	{

		if(platform_table_lua[i].command == command)
		{
			//platform_log(MAP_LIBRARY,LOG_DEBUG,"command to execute %d\n",command);

			if(platform_table_lua[i].set_data(data, json_string))
				return -1;

			if(json_string == NULL)
				return -1;

			if(lua_prepare(i,&L,json_string,ctxt))
			{
				lua_close(L);
				return -1;
			}

			/*Leak Detection Fix */
			lua_close(L);
		}

	}

	return 0;
}

static int lua_prepare(unsigned int cmd_index,lua_State **L,const char* subcmd, void *ctxt)
{
	char scripts[200];

	*L = luaL_newstate();                        /* Create Lua state variable */
	luaL_openlibs(*L);

	//platform_log(MAP_LIBRARY,LOG_DEBUG,"lua_prepare\n");	

	if(ctxt != NULL)
	{
		lua_pushlightuserdata(*L, ctxt);
		lua_setglobal(*L, "connect");
		platform_log(MAP_LIBRARY,LOG_DEBUG,"Context Pushed lua_prepare\n");	
	}


	strncpy(scripts,LUA_SCRIPTS_PATH,sizeof(scripts));
	strcat(scripts,platform_table_lua[cmd_index].script_name);

	if (luaL_loadfile(*L,scripts)) /* Load but don't run the Lua script */
	{
		platform_log(MAP_LIBRARY,LOG_EMERG,"luaL_loadfile() failed for script %s",platform_table_lua[cmd_index].script_name);		/* Error out if file can't be read */
		return -1;
	}
	if (lua_pcall(*L, 0, 0, 0))/* PRIMING RUN. FORGET THIS AND YOU'RE TOAST */
	{
		platform_log(MAP_LIBRARY,LOG_EMERG,"Priming lua_pcall() failed for  %s",platform_table_lua[cmd_index].script_name);			/* Error out if Lua file has an error */
		return -1;
	}
	//platform_log(MAP_LIBRARY,LOG_DEBUG,"Subcmd lua_prepare %s\n",subcmd);	
	if((CHECK_SUBCMD(platform_table_lua[cmd_index].command)) && (subcmd !=NULL) && (strlen(subcmd)<MAX_SUBCMD_LEN))
	{
		int Err = 0;
		lua_getglobal(*L,platform_table_lua[cmd_index].function_name);
		lua_pushstring(*L,subcmd);
		if ((Err = lua_pcall(*L, 1, 1, 0)))	/* Run function, !!! NARG =1 ,NRETURN=1 !!! */
		{
			platform_log(MAP_LIBRARY,LOG_EMERG,"Run lua_pcall() error - %d, failed (attempling to call %s)for function %s\n", Err, lua_tostring(*L, -1), platform_table_lua[cmd_index].function_name);
			return -1;
		}
	}
	else if(!(CHECK_SUBCMD(platform_table_lua[cmd_index].command) )&& (subcmd ==NULL))
	{
		int Err = 0;
		lua_getglobal(*L,platform_table_lua[cmd_index].function_name);
		if (lua_pcall(*L, 0, 1, 0))	/* Run function, !!! NRETURN=1 !!! */
		{
			platform_log(MAP_LIBRARY,LOG_EMERG,"Run lua_pcall() error - %d, failed (attempling to call %s) failed for function %s\n",Err, lua_tostring(*L, -1), platform_table_lua[cmd_index].function_name);
			return -1;
		}
	}
	else
	{
		platform_log(MAP_LIBRARY,LOG_EMERG,"Invalid command");
		return -1;
	}
	return 0;
}



