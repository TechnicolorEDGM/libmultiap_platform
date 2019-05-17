/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

#include "platform_lib_capi_util.h"

struct ubus_context* get_ubus_context(void)
{
	static struct ubus_context *ctx = NULL;

	if (!ctx)
	{
		ctx = platform_get_mon_context(); //getting ubus context from monitor task
		if (NULL == ctx) 
		{
			platform_log(MAP_LIBRARY,LOG_ERR, "Failed to connect to ubus\n");
			return NULL;
		}
	}

	return ctx;
}


struct uci_context* get_uci_context(void)
{
	static struct uci_context *ctx = NULL;

	if (!ctx)
	{
		ctx = uci_alloc_context();
		if (NULL == ctx) 
		{
			platform_log(MAP_LIBRARY,LOG_ERR, "Failed to create uci context\n");
			return NULL;
		}
	}

	return ctx;
}



bool is_string_in_line(char* line, char* substring)
{
	char *token, *saveptr = NULL;
	bool status = false;
	char* check_str = strdup(line);

	token = strtok_r(check_str, ", ", &saveptr);
	while (token) {
		if (!strncmp(token, substring, strlen(substring)))
		{
			status = true;
			break;
		}
		token = strtok_r(NULL, ", ", &saveptr);	
	}
	free(check_str);
	
	return status;
}

char* get_interface_for_radio(const char* radio_name)
{
        if(0 == strcmp(radio_name,"radio_2G")) {
                return "wl0";
        }
        else if(0 == strcmp(radio_name,"radio_5G")) {
                return "wl1";
        }
        else if(0 == strcmp(radio_name,"radio2")) {
                return "wl2";
        }
        return NULL;
}

bool get_uci_config(char *package, char *section, char* option, char* result, int resultlen)
{
	bool status = false;
	struct  uci_ptr ptr;
	struct  uci_context *uci_ctx = uci_alloc_context();
	if (uci_ctx)
	{
		memset(&ptr, 0, sizeof(ptr));
		ptr.package = package;
		ptr.section = section;
		ptr.option = option;

		if ((uci_lookup_ptr(uci_ctx, &ptr, NULL, true) == UCI_OK)
							&& (ptr.o != NULL && ptr.o->v.string != NULL)) 
		{
			if(ptr.flags & UCI_LOOKUP_COMPLETE)
			{
				strncpy(result, ptr.o->v.string, resultlen);
				result[resultlen - 1] = '\0';
				status = true;
			}
			else
				platform_log(MAP_LIBRARY,LOG_ERR, "uci lookup error for %s.%s.%s\n", package, section, option);
		}
		else {
			platform_log(MAP_LIBRARY,LOG_ERR, "uci lookup failed for %s.%s.%s\n", package, section, option);
                }
                uci_free_context(uci_ctx);
	}

	return status;
}

bool set_uci_config(char *package, char *section, char* option, char* result)
{
        bool status = false;
        struct  uci_ptr ptr;
        struct  uci_context *uci_ctx = get_uci_context();
        if (uci_ctx)
        {
                memset(&ptr, 0, sizeof(ptr));
                ptr.package = package;
                ptr.section = section;
                ptr.option = option;

                if ((uci_lookup_ptr(uci_ctx, &ptr, NULL, true) == UCI_OK)) {
                        ptr.value = result;
                        if ((uci_set(uci_ctx, &ptr) == UCI_OK)) {
                                if (uci_commit(uci_ctx, &ptr.p, false) == UCI_OK) {
                                        status = true;
                                }
                                else
                                        platform_log(MAP_LIBRARY,LOG_ERR, "uci commit failed for %s.%s.%s\n", package, section, option);
                        }
                        else
                                platform_log(MAP_LIBRARY,LOG_ERR, "uci set failed for %s.%s.%s\n", package, section, option);
                }
                else {
                        platform_log(MAP_LIBRARY,LOG_ERR, "uci lookup failed for %s.%s.%s\n", package, section, option);
                }
        }

        return status;
}

char* get_mac_string(uint8_t mac[], char *macstring)
{	
	sprintf(macstring, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return macstring;
}





int read_value_from_transformer(const char* path, char* value, int length)
{
	bool status = false;

	tf_ctx_t* ctx = tf_new_ctx(NULL, 0);
	tf_req_t req = {.type = TF_REQ_GPV, .u.gpv.path = path};
	tf_fill_request(ctx, &req);
	const tf_resp_t* resp = tf_next_response(ctx, false);
	if (resp && (TF_RESP_GPV == resp->type)) {
		strncpy(value, resp->u.gpv.value, length);
		value[length-1] = '\0';
		status = true;
	}
	tf_free_ctx(ctx);

	return status;
}

//This function will load values to be written into the transformer , it will only execute a commit if the commit flag is set
int write_value_to_transformer(const char* path, const char* value, bool commitflag)
{
  bool status = false;
  if (path && value) {
    tf_ctx_t* ctx = tf_new_ctx(NULL, 0);
    tf_req_t req = {.type = TF_REQ_SPV, .u.spv = {.full_path = path, .value = value }};
    // load request
    tf_fill_request(ctx, &req);
    const tf_resp_t* resp = tf_next_response(ctx, false);
    if (resp && (TF_RESP_EMPTY == resp->type)) {
      //commit if commit flag is true
      if(commitflag)
      {
        req.type = TF_REQ_APPLY;
        tf_fill_request(ctx, &req);
        tf_next_response(ctx, true);
      }
      status = true;
    }
    tf_free_ctx(ctx);
  }
  return status;
}

//This function just calls the commit/apply on the transformer
void write_loaded_values_to_transformer()
{
  tf_ctx_t* ctx = tf_new_ctx(NULL, 0);
  tf_req_t req ={0};
  req.type = TF_REQ_APPLY;
  tf_fill_request(ctx, &req);
  //commit the requests
  tf_next_response(ctx, true);
  tf_free_ctx(ctx);
}

// This basically does nothing other than checking the sanity of the output and copy the result back to the caller
static void generic_callback_handler(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct blob_attr **msgptr = req->priv;

	if (msgptr && msg) {
		*msgptr = malloc(blob_raw_len(msg));
		if (*msgptr)
			memcpy(*msgptr, msg, blob_raw_len(msg));
				else
			platform_log(MAP_LIBRARY,LOG_ERR, "generic callback handler; failed to allocate!\n");
		}
		else
		platform_log(MAP_LIBRARY,LOG_ERR, "generic callback handlerfailed!\n");
}


/*
	This is a ubus_invoke() API wrapper.
	This function calls a generic_callback_handler function which copies the result back to the caller in msgptr. So caller can 
	parse the ubus result instead of a callback.
	when called with input (inputbuf), this function frees the inputbuf once done. Caller doesn't have to worry about freeing this
*/
bool invoke_ubus_command(void *ctx, char* ubuspath, char* ubuscmd, struct blob_buf *inputbuf, struct blob_attr **msgptr)
	{
	bool status = false;
	uint32_t id;
	struct ubus_context *ubusctx = NULL;
	struct blob_attr *param = NULL;
	struct blob_buf input = {0};
	bool use_temp_ubus_context = false;

	//if ubus context is passed(get_context/set_context), use it.Otherwise use the ubus context from monitor task
	if (ctx)
		ubusctx = (struct ubus_context*)ctx;
	else 
		ubusctx = get_ubus_context();

	if (!ubusctx) { // if no ubus sessions available; create one and free it once done
		ubusctx = ubus_connect(NULL);
		use_temp_ubus_context = true;
	}

	if (inputbuf)
		param = inputbuf->head;
	else {
		blob_buf_init(&input, 0);
		param = input.head;
	}

	if (ubusctx) {
		*msgptr = NULL;
		if(ubus_lookup_id(ubusctx, ubuspath, &id) == UBUS_STATUS_OK) {
			ubus_invoke(ubusctx, id, ubuscmd, param, generic_callback_handler, msgptr, 5000);

			if (NULL != *msgptr)
				status = true;
			else
				platform_log(MAP_LIBRARY,LOG_ERR, "Failed to get ubus - path:%s, cmd: %s\n", ubuspath, ubuscmd);
	}
		else
			platform_log(MAP_LIBRARY,LOG_ERR, "Failed to get object id for ubus path %s\n", ubuspath);
}
	else 
		platform_log(MAP_LIBRARY,LOG_ERR, "No ubus context!!!\n");

	if (use_temp_ubus_context && ubusctx) //free up the context we have created
		ubus_free(ubusctx);

	if (inputbuf)
		blob_buf_free(inputbuf);
	else
		blob_buf_free(&input);

	return status;
}


/*
	This is also a ubus_invoke() API wrapper.
	This function takes the callback function specified by the caller.
	Caller can either provide inputname or complete input (inputbuf)
	when called with input (inputbuf), this function frees the inputbuf once done. Caller doesn't have to worry about freeing this
	information passed to cbdata will be available to the callback function when invoked
*/
bool invoke_ubus_command_ex(void *ctx, char* ubuspath, char* ubuscmd, struct blob_buf *inputbuf, char* inputname,
								ubus_data_handler_t callbackfn, void* cbdata)
	{
	bool status = false;
	uint32_t id;
	struct ubus_context *ubusctx = NULL;
	struct blob_attr *param = NULL;
	struct blob_buf input = {0};

	//if ubus context is passed(get_context/set_context), use it.Otherwise use the ubus context from monitor task
	if (ctx)
		ubusctx = (struct ubus_context*)ctx;
	else 
		ubusctx = get_ubus_context();

	if (inputbuf)
		param = inputbuf->head;
	else {
		blob_buf_init(&input, 0);
		if (inputname)
			blobmsg_add_string(&input, "name", inputname);
		param = input.head;
	}


	if (ubusctx) {
		if(ubus_lookup_id(ubusctx, ubuspath, &id) == UBUS_STATUS_OK) {
			if (ubus_invoke(ubusctx, id, ubuscmd, param, callbackfn, cbdata, 5000) == UBUS_STATUS_OK)
				status = true;
			else
				platform_log(MAP_LIBRARY,LOG_ERR, "Failed to get ubus - path:%s, cmd: %s\n", ubuspath, ubuscmd);
	}
		else
			platform_log(MAP_LIBRARY,LOG_ERR, "Failed to get object id for ubus path %s\n", ubuspath);
}

	if (inputbuf)
		blob_buf_free(inputbuf);
	else
		blob_buf_free(&input);

	return status;
}

