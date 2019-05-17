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

#ifndef PLATFORM_LUA_H
#define PLATFORM_LUA_H

#include <stdarg.h>
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

typedef int(*T_ref_func_ptr)(lua_State *L,void* data);
typedef int(*T_ref_setfunc_ptr)(void *data, char* json_str);

typedef struct _platform_handle_lua
{
	unsigned int command;
	unsigned int periodicity;
	const char* function_name;
	const char* script_name;
	T_ref_func_ptr get_data;
	T_ref_setfunc_ptr set_data;
}platform_handle_lua;

typedef enum _load{
	load_once=1,
	load_periodically
}load;

int platform_get_lua(unsigned int command, const char *subcmd, void *data);
int platform_get_context_lua(unsigned int command, const char *subcmd, void *data, void *ctxt);
int platform_set_lua(unsigned int command, void *data);
int platform_set_context_lua(unsigned int command, void *data, void *ctxt);

#endif

#ifdef __cplusplus
}
#endif

