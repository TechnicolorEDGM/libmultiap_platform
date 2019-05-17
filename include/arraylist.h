/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

#ifndef arraylist_h
#define arraylist_h

#include <stdio.h>
#include <stdint.h>
#include <pthread.h>

typedef struct array_list_s array_list_t;

typedef enum _e_array_list_type {
    eListTypeDefault,
    eListTypeAtomic
}e_array_list_type;

typedef struct array_list_node_s array_list_node_t;

struct array_list_node_s {
    array_list_node_t * next;
    array_list_node_t * prev;
    void * obj;
};

typedef struct array_list_s {
    e_array_list_type type;
    pthread_mutex_t lock;
    uint32_t count;
    array_list_node_t *head;
    array_list_node_t * tail;
}array_list_t;

typedef struct list_iterator_s {
    array_list_t* list;
    array_list_node_t* iter;
}list_iterator_t;


static inline void list_lock_aquire(array_list_t * list) {
    if(list->type == eListTypeAtomic) pthread_mutex_lock(&(list->lock));
}

static inline void list_lock_release(array_list_t * list) {
    if(list->type == eListTypeAtomic) pthread_mutex_unlock(&(list->lock));
}

extern array_list_t* new_array_list(e_array_list_type type);
extern void delete_array_list(array_list_t* list);
extern int push_object(array_list_t* list, void * obj);
extern array_list_node_t* push_object_ex(array_list_t* list, void * obj);
extern void * pop_object(array_list_t* list);
extern int insert_at_index(array_list_t * list, void * obj, int position);
extern int insert_last_object(array_list_t * list, void *obj);
int compare_and_insert(array_list_t * list, void* obj,
                    int (*is_condition_met)(void* obj, void* object_to_find));
extern void* find_object(array_list_t * list, void* object_to_find,
                    int (*is_equal)(void* obj, void* object_to_find));
extern void* remove_last_object(array_list_t* list);
extern void* remove_object_at_index(array_list_t* list, int position);
extern void* remove_object(array_list_t* list, void* object_to_find,
                    int (*is_equal)(void* obj, void* object_to_find)); // O(N)
extern void * last_object(array_list_t* list);
extern void * first_object(array_list_t* list);
extern void * object_at_index(array_list_t* list, int position);
extern int list_get_size(array_list_t* list);

extern list_iterator_t* new_list_iterator(array_list_t* list);            //O(1)
extern void bind_list_iterator(list_iterator_t* i, array_list_t* list);
extern void* get_next_list_object(list_iterator_t* i);               //O(1)
extern void* get_prev_list_object(list_iterator_t* i);
extern void reset_list_iterator(list_iterator_t *i);               //O(1)
extern void free_list_iterator(list_iterator_t *i);                //O(1)

extern void remove_node(array_list_t* list, array_list_node_t* node);
#endif /* arraylist_h */
