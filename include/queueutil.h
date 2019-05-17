/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

#ifndef _QUEUE_UTIL_H_
#define _QUEUE_UTIL_H_

#ifdef __cplusplus
extern "C"
{
#endif

// ====== dependencies ======
#include <stdlib.h>
#include <stdint.h>
#include <search.h>
#include <assert.h>
#include <syslog.h>
#include "platform_utils.h"
// ====== Macros ======
// Logging macros
#define kQUtil_MaxName  64
#define kQUitil_Forever 0xFFFFFFFF
#define qLogHndl sfmLogHndl
#define qutil_Log(hndl,lvl,fmt,etc...) platform_log(MAP_LIBRARY,LOG_DEBUG, "%s(): " fmt,__FUNCTION__,##etc)
#if 0
#define qutil_Enter() ulog_Message(qLogHndl,eUlogLevel_Noise,"%s(): Entering\n",__FUNCTION__)
#define qutil_Exit() ulog_Message(qLogHndl,eUlogLevel_Noise,"%s(): Exiting\n",__FUNCTION__)
#else
#define qutil_Enter() platform_log(MAP_LIBRARY,LOG_DEBUG, "%s(): Entering.\n", __FUNCTION__ )
#define qutil_Exit() platform_log(MAP_LIBRARY,LOG_DEBUG, "%s(): Exiting.\n", __FUNCTION__ )
#endif
#define qutil_DebugLog(hndl,lvl,fmt,etc...) platform_log(MAP_LIBRARY,LOG_DEBUG, "%s(): " fmt,__FUNCTION__,##etc)

#define kCpe_NoErr 0
#define kCpe_Err -1
#define kCpe_TimeoutErr -2
//#define diagAssert(trap, errMsg, y)
#define diagAssert(trap, errMsg, y) do{\
         perror(errMsg);\
         assert(0);\
}while(0)
// ====== typedefs ======
typedef struct QueueEvent
{
   struct QueueEvent  *nextEvent ;
   struct QueueEvent  *prevEvent ;
   uint32_t    evCode ;
   size_t      length ;
   void *data ;
}tQueueEvent;

typedef struct
{
   char              name[kQUtil_MaxName];
   pthread_mutex_t   mutex ;
   pthread_cond_t    cond ;
   tQueueEvent       *queueHead ;
   tQueueEvent       *queueTail ;
}tQueue ;

// ====== extern ======

// ====== prototypes ======
extern int queue_EventCreate ( tQueueEvent **ppEvent , size_t size ) ;
extern int queue_EventDestroy ( tQueueEvent *ppEvent ) ;
extern int queue_Create ( tQueue **ppQueue , const char *pName ) ;
extern int queue_Destroy ( tQueue *pQueue ) ;
extern int queue_AddEvent ( tQueue *pQueue , tQueueEvent *pEvent ) ;
extern int queue_GetLength ( tQueue *pQueue , uint32_t *pLength ) ;
//extern int queue_RemoveEventImmediate ( tQueue *pQueue , tQueueEvent **ppEvent ) ;
extern int queue_RemoveEvent ( tQueue *pQueue , struct timespec interval , tQueueEvent **ppEvent ) ;


#ifdef __cplusplus
}
#endif   // _cplusplus
#endif   // _QUEUE_UTIL_H_
