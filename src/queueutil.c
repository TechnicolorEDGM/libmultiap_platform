/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

// ====== dependencies ======
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include "queueutil.h"


static int CreateNamedCondition ( pthread_cond_t *pCond, const char *pName)
{
   // Assert: NULL != pCond && NULL != pName
   int retVal = kCpe_NoErr ;
   pthread_condattr_t condAttr ;
   char errMsg [256];
   qutil_Enter() ;
   retVal = pthread_condattr_init(&condAttr);
   if (retVal != kCpe_NoErr)
   {
      snprintf (errMsg, sizeof(errMsg) - 1, "%s pthread_condattr_init failed %d", __FUNCTION__, retVal);
      diagAssert (DIAGASSERT_TRAP_PRDASSERT, errMsg, 0);
      retVal = kCpe_Err;
   }

   retVal = pthread_condattr_setclock(&condAttr, CLOCK_MONOTONIC);
   if (retVal != kCpe_NoErr)
   {
      snprintf (errMsg, sizeof(errMsg) - 1, "%s pthread_condattr_setclock failed %d", __FUNCTION__, retVal);
      diagAssert (DIAGASSERT_TRAP_PRDASSERT, errMsg, 0);
      retVal = kCpe_Err;
   }

   retVal = pthread_cond_init (pCond, &condAttr);
   if (retVal != kCpe_NoErr)
   {
      snprintf (errMsg, sizeof(errMsg) - 1, "pthread_cond_init failed with %d", retVal);
      diagAssert (DIAGASSERT_TRAP_PRDASSERT, errMsg, 0);
      retVal = kCpe_Err;
   }

   (void)pName ;
   /*retVal = pthread_cond_setname_np (pCond, pName);
   if (retVal != kCpe_NoErr)
   {
      snprintf (errMsg, sizeof(errMsg) - 1, "pthread_cond_setname_np failed with %d", retVal);
      diagAssert (DIAGASSERT_TRAP_PRDASSERT, errMsg, 0);
      retVal = kCpe_Err;
   }*/

   // ignore return value???
   pthread_condattr_destroy (&condAttr);
   qutil_Exit() ;
   return retVal ;
}

static int CreateNamedMutex(pthread_mutex_t *pMutex, const char* pName)
{
   // Assert: NULL != pMutex && NULL != pName
   int retVal = kCpe_NoErr;
   pthread_mutexattr_t attr;
   char errMsg [256];
   qutil_Enter() ;

   // Initialize the attribute and create the mutex.
   // The mutex is alway a NON-RECURSIVE mutex.
   if ( 0 > ( retVal = pthread_mutexattr_init( &attr ) ) )
   {
      qutil_Log(qLogHndl, eUlogLevel_Severe,
                     "pthread_mutexattr_init failed for %s with %d\n",
                     pName, retVal);
      snprintf (errMsg, sizeof(errMsg) - 1, "pthread_mutexattr_init failed for %s with %d",
                     pName, retVal);
      diagAssert (DIAGASSERT_TRAP_PRDASSERT, errMsg, 0);
   }

   /*if ( 0 > ( retVal = pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_DEFAULT ) )
   {
      qutil_Log(qLogHndl, eUlogLevel_Severe,
                     "pthread_mutexattr_settype failed for %s with %d\n",
                     pName, retVal);
      snprintf (errMsg, sizeof(errMsg) - 1, "pthread_mutexattr_settype failed for %s with %d",
                     pName, retVal);
      diagAssert (DIAGASSERT_TRAP_PRDASSERT, errMsg, 0);
   }*/

   if ( 0 > (retVal = pthread_mutex_init(pMutex, &attr)))
   {
      qutil_Log(qLogHndl, eUlogLevel_Severe,
                     "pthread_mutex_init failed for %s with %d\n",
                     pName, retVal);
      snprintf (errMsg, sizeof(errMsg) - 1, "pthread_mutex_init failed for %s with %d",
                     pName, retVal);
      diagAssert (DIAGASSERT_TRAP_PRDASSERT, errMsg, 0);
   }

   (void) pName ;
   /*if (0 > ( retVal = pthread_mutex_setname_np ( pMutex, pName ) ) )
   {
      qutil_Log(qLogHndl, eUlogLevel_Severe,
                     "pthread_mutex_setname_np failed for %s with %d\n",
                     pName, retVal);
      snprintf (errMsg, sizeof(errMsg) - 1, "pthread_mutex_setname_np failed for %s with %d",
                     pName, retVal);
      diagAssert (DIAGASSERT_TRAP_PRDASSERT, errMsg, 0);
   }*/

   // Clean up attr if already created.
   pthread_mutexattr_destroy(&attr);
   qutil_Exit() ;

   return retVal;
}

static int LockQueueMutex ( tQueue *pQueue )
{
   // Assert: NULL != pQueue
   int retVal ;
   char errMsg [256];
   qutil_Enter() ;
   if ( 0 > ( retVal = pthread_mutex_lock( &pQueue->mutex ) ) )
   {
      qutil_Log(qLogHndl, eUlogLevel_Severe,
                     "pthread_mutex_lock failed for %s with %d\n",
                     pQueue->name, retVal);
      snprintf (errMsg, sizeof(errMsg) - 1, "pthread_mutex_lock failed for %s with %d",
                     pQueue->name, retVal);
      diagAssert (DIAGASSERT_TRAP_PRDASSERT, errMsg, 0);
   }
   qutil_Exit() ;
   return kCpe_NoErr ;
}

static int UnlockQueueMutex ( tQueue *pQueue )
{
   // Assert: NULL != pQueue
   int retVal ;
   char errMsg [256];
   qutil_Enter() ;
   if ( 0 > ( retVal = pthread_mutex_unlock( &pQueue->mutex ) ) )
   {
      qutil_Log(qLogHndl, eUlogLevel_Severe,
                     "pthread_mutex_unlock failed for %s with %d\n",
                     pQueue->name, retVal);
      snprintf (errMsg, sizeof(errMsg) - 1, "pthread_mutex_unlock failed for %s with %d",
                     pQueue->name, retVal);
      diagAssert (DIAGASSERT_TRAP_PRDASSERT, errMsg, 0);
   }
   qutil_Exit() ;
   return kCpe_NoErr ;
}

static int SignalQueueCond ( tQueue *pQueue )
{
   // Assert: NULL != pQueue
   int retVal ;
   char errMsg [256];
   qutil_Enter() ;
   if ( 0 > ( retVal = pthread_cond_signal ( &pQueue->cond ) ) )
   {
      qutil_Log(qLogHndl, eUlogLevel_Severe,
                     "pthread_cond_signal failed for %s with %d\n",
                     pQueue->name, retVal);
      snprintf (errMsg, sizeof(errMsg) - 1, "pthread_cond_signal failed for %s with %d",
                     pQueue->name, retVal);
      diagAssert (DIAGASSERT_TRAP_PRDASSERT, errMsg, 0);
   }
   qutil_Exit() ;
   return kCpe_NoErr ;
}

static int TimedWaitQueueCond ( tQueue *pQueue , struct timespec *pTimeSpec )
{
   // Assert: NULL != pQueue
   int retVal ;
   char errMsg [256];
   qutil_Enter() ;
   retVal = pthread_cond_timedwait ( &pQueue->cond , &pQueue->mutex , pTimeSpec ) ;
   if ( 0 > retVal && ETIMEDOUT != retVal )
   {
      qutil_Log(qLogHndl, eUlogLevel_Severe,
                     "pthread_cond_timedwait failed for %s with %d\n",
                     pQueue->name, retVal);
      snprintf (errMsg, sizeof(errMsg) - 1, "pthread_cond_timedwait failed for %s with %d",
                     pQueue->name, retVal);
      diagAssert (DIAGASSERT_TRAP_PRDASSERT, errMsg, 0);
   }
   retVal = ( ETIMEDOUT == retVal )?kCpe_TimeoutErr:kCpe_NoErr ;
   qutil_Exit() ;
   return retVal ;
}

static int  WaitQueueCond ( tQueue *pQueue )
{
   // Assert: NULL != pQueue && NULL != pTimeSpec
   int retVal ;
   char errMsg [256];
   qutil_Enter() ;
   if ( 0 > ( retVal = pthread_cond_wait ( &pQueue->cond , &pQueue->mutex ) ) )
   {
      qutil_Log(qLogHndl, eUlogLevel_Severe,
                     "pthread_cond_wait failed for %s with %d\n",
                     pQueue->name, retVal);
      snprintf (errMsg, sizeof(errMsg) - 1, "pthread_cond_wait failed for %s with %d",
                     pQueue->name, retVal);
      diagAssert (DIAGASSERT_TRAP_PRDASSERT, errMsg, 0);
   }
   qutil_Exit() ;
   return kCpe_NoErr ;
}


static int Enqueue ( tQueue *pQueue , tQueueEvent *pEvent )
{
   //Assert: pQueue != NULL && pEvent !=NULL && pEvent->prevEvent ==NULL && pEvent->nextEvent ==NULL
   int retVal = kCpe_NoErr ;
   pEvent->prevEvent = pQueue->queueTail ;
   if ( NULL != pQueue->queueTail )
   {
      pQueue->queueTail->nextEvent = pEvent ;
      pQueue->queueTail = pEvent ;
   }
   else
   {
      pQueue->queueTail = pEvent ;
      pQueue->queueHead = pEvent ;
   }
   return retVal ;
}

static int Dequeue ( tQueue *pQueue , tQueueEvent **ppEvent )
{
   int retVal = kCpe_NoErr ;
   *ppEvent =  pQueue->queueHead ;
   if ( NULL != pQueue->queueHead )
   {
      if ( NULL != pQueue->queueHead->nextEvent )
      {
         pQueue->queueHead->nextEvent->prevEvent = NULL ;
      }
      else
      {
         pQueue->queueTail = NULL ;
      }
      pQueue->queueHead = pQueue->queueHead->nextEvent ;
   }
   if ( NULL != *ppEvent )
   {
      (*ppEvent)->nextEvent = NULL ;
   }
   return retVal ;
}

// ====== functions ======
int queue_Create ( tQueue **ppQueue , const char *pName )
{
   int retVal = kCpe_NoErr ;
   tQueue *myQueue = NULL ;
   qutil_Enter() ;
   if ( ppQueue && pName )
   {
      myQueue = ( tQueue* ) malloc ( sizeof( tQueue ) ) ;
      if ( myQueue )
      {
         snprintf ( myQueue->name, kQUtil_MaxName*sizeof(char) - 1, "%s",
                        pName );

         retVal = CreateNamedCondition ( &myQueue->cond , myQueue->name ) ;
         if ( kCpe_NoErr == retVal )
         {
            retVal = CreateNamedMutex ( &myQueue->mutex , myQueue->name ) ;
            if ( kCpe_NoErr == retVal )
            {
               myQueue->queueHead = NULL ;
               myQueue->queueTail = NULL ;
               *ppQueue = myQueue ;
            }
         }

         if ( kCpe_NoErr != retVal )
         {
            free ( myQueue ) ;
         }
      }
      else
      {
         qutil_Log(qLogHndl, eUlogLevel_Severe,
                        "No Memory Available\n");
         retVal = kCpe_Err ;
      }
   }
   else
   {
      qutil_Log(qLogHndl, eUlogLevel_Severe,
                     "Bad Parameters\n");
      retVal = kCpe_Err ;
   }
   qutil_Exit() ;
   return retVal ;
}

int queue_Destroy ( tQueue *pQueue )
{
   int retVal = kCpe_NoErr ;
   qutil_Enter() ;
   if ( pQueue )
   {
      LockQueueMutex ( pQueue ) ;
      pthread_cond_destroy ( &pQueue->cond ) ;
      if ( NULL != pQueue->queueHead || NULL != pQueue->queueTail )
      {
         qutil_Log(qLogHndl, eUlogLevel_Severe,
                        "Destroying non-empty queue: %s\n",
                        pQueue->name);
      }
      UnlockQueueMutex ( pQueue ) ;
      pthread_mutex_destroy ( &pQueue->mutex ) ;
      free ( pQueue ) ;
      retVal = kCpe_NoErr ;
   }
   else
   {
      qutil_Log(qLogHndl, eUlogLevel_Severe,
                     "Bad Parameters\n");
      retVal = kCpe_Err ;
   }
   qutil_Exit() ;
   return retVal ;
}

int queue_AddEvent ( tQueue *pQueue , tQueueEvent *pEvent )
{
   int retVal = kCpe_NoErr ;
   qutil_Enter() ;
   if ( pQueue && pEvent )
   {
      LockQueueMutex ( pQueue ) ;
      retVal = Enqueue ( pQueue , pEvent ) ;
      SignalQueueCond ( pQueue ) ;
      UnlockQueueMutex ( pQueue ) ;
   }
   else
   {
      qutil_Log(qLogHndl, eUlogLevel_Severe,
                     "Bad Parameters\n");
      retVal = kCpe_Err ;
   }
   qutil_Exit() ;
   return retVal ;
}
/*int queue_GetLength ( tQueue *pQueue , uint32_t *pLength )
{
   int retVal = kCpe_NoErr ;
   qutil_Enter() ;
   if ( pQueue && pLength )
   {
      LockQueueMutex ( pQueue ) ;
      *pLength = g_queue_get_length ( pQueue->gQueue ) ;
      UnlockQueueMutex( pQueue ) ;
   }
   else
   {
      retVal = kCpe_ParameterErr ;
   }
   qutil_Exit() ;
   return retVal ;
}*/

/*int queue_RemoveEventImmediate ( tQueue *pQueue , tQueueEvent **ppEvent )
{
   // Note: queue_RemoveEvent and queue_RemoveEventImmediate are not themselves threadsafe with each other
   // but are thread safe with queue_AddEvent
   int retVal = kCpe_NoErr ;
   qutil_Enter() ;
   if ( pQueue && ppEvent )
   {
      *ppEvent = NULL ;
      LockQueueMutex ( pQueue ) ;
      if ( NULL != g_queue_peek_tail ( pQueue->gQueue ) )
      {
         *ppEvent = g_queue_pop_tail ( pQueue->gQueue ) ;
      }
      UnlockQueueMutex ( pQueue ) ;
   }
   else
   {
      retVal = kCpe_ParameterErr ;
   }
   qutil_Exit() ;
   return retVal ;
}*/

int queue_EventCreate ( tQueueEvent **ppEvent , size_t dataSize )
{
      int retVal = kCpe_NoErr ;
      qutil_Enter() ;
      tQueueEvent* myQueueEvent = NULL ;
      myQueueEvent = ( tQueueEvent* ) malloc ( sizeof( tQueueEvent ) ) ;
      
      if ( NULL != myQueueEvent )
      {
         myQueueEvent->data = ( void* ) malloc ( dataSize ) ;
         myQueueEvent->nextEvent = NULL ;
         myQueueEvent->prevEvent = NULL ;
         myQueueEvent->evCode = 0 ;
         myQueueEvent->length = dataSize ;
         *ppEvent = myQueueEvent ;
      }
      else
      {
         qutil_Log(qLogHndl, eUlogLevel_Severe,
                        "No Memory Available\n");
         *ppEvent = NULL ;
         retVal = kCpe_Err ;
      }
      qutil_Exit() ;
      return retVal ;
}

int queue_EventDestroy ( tQueueEvent *pEvent )
{
      // ASSERT: NULL != pEvent
      int retVal = kCpe_NoErr ;
      free ( pEvent->data );
      free ( pEvent ) ;
      return retVal ;
}

int queue_RemoveEvent ( tQueue *pQueue , struct timespec interval , tQueueEvent **ppEvent )
{
   int retVal = kCpe_NoErr ;
   qutil_Enter() ;
   if ( pQueue && ppEvent )
   {
      *ppEvent = NULL ;
      LockQueueMutex ( pQueue ) ;
      if ( NULL == pQueue->queueHead )
      {
         if ( kQUitil_Forever == interval.tv_sec || kQUitil_Forever == interval.tv_nsec )
         {
               WaitQueueCond( pQueue ) ;
         }
         else
         {
            retVal = TimedWaitQueueCond ( pQueue , &interval ) ;
            if ( kCpe_TimeoutErr == retVal )
            {
               qutil_Log(qLogHndl, eUlogLevel_Noise,
                              "Queue %s read timed out\n",
                              pQueue->name);
            }
         }
      }

      if ( kCpe_NoErr == retVal )
      {
         retVal = Dequeue ( pQueue , ppEvent ) ;
      }
      UnlockQueueMutex ( pQueue ) ;
   }
   else
   {
      qutil_Log(qLogHndl, eUlogLevel_Severe,
                     "Bad Parameters\n");
      retVal = kCpe_Err ;
   }
   qutil_Exit() ;
   return retVal ;
}
