/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

#include "arraylist.h"
#include <stdlib.h>

array_list_t * new_array_list(e_array_list_type type) {
    array_list_t *list = calloc(1, sizeof(array_list_t));
    int cleanup = 1;
    do {
        if(list == NULL){
            break;
        }
        list->type = type;
        if(list->type == eListTypeAtomic) {
            pthread_mutex_init(&(list->lock), NULL);
        }
        cleanup = 0;
    }while(0);
    if(cleanup) {
        if(list && list->type==eListTypeAtomic) {
            pthread_mutex_destroy(&(list->lock));
            free(list);
            list = NULL;
        }
    }
    return list;
}

 inline void delete_array_list(array_list_t* list) {
    if(list && (list->type == eListTypeAtomic)) pthread_mutex_destroy(&(list->lock));
    free(list);
}

//peek the last object (dont remove) O(1)
inline void * first_object(array_list_t* list) {
    void * obj = NULL;
    if (list) {
        list_lock_aquire(list);
        if(list && list->head) {
            obj = list->head->obj;
        }
        list_lock_release(list);
    }
    return obj;
}

//peek the last object (dont remove) O(1)
inline void * last_object(array_list_t* list) {
    void * obj = NULL;
    list_lock_aquire(list);
    if(list && list->tail) {
        obj = list->tail->obj;
    }
    list_lock_release(list);
    return obj;
}

static array_list_node_t* allocate_object(void* obj) {
    array_list_node_t* node = NULL;
    if(obj) {
        node = calloc(1, sizeof(array_list_node_t));
        if(node) {
            node->obj = obj;
        }
    }
    return node;
}

//stack PUSH operation O(1)
int push_object(array_list_t* list, void * obj) {
    int ret = -1;
    if(list && obj) {
        array_list_node_t * node =allocate_object(obj);
        if(node) {
            list_lock_aquire(list);
            if(list->head == NULL) {
                list->head = node;
                list->tail = list->head;
            }
            else {
                array_list_node_t* old = list->head;   //head = old->next ...
                list->head = node;                  //head=node<->old->next ...
                node->next = old;
                old->prev = node;
            }
            list->count++;
            list_lock_release(list);
            ret = 0;
        }
    }
    return ret;
}

//stack PUSH operation O(1)
array_list_node_t* push_object_ex(array_list_t* list, void * obj) {
    array_list_node_t* node = NULL;
    if(list && obj) {
        node =allocate_object(obj);
        if(node) {
            list_lock_aquire(list);
            if(list->head == NULL) {
                list->head = node;
                list->tail = list->head;
            }
            else {
                array_list_node_t* old = list->head;   //head = old->next ...
                list->head = node;                  //head=node<->old->next ...
                node->next = old;
                old->prev = node;
            }
            list->count++;
            list_lock_release(list);
        }
    }
    return node;
}

void * pop_object(array_list_t* list) {
    void * obj = NULL;
    array_list_node_t* node = NULL;
    if(list) {
        list_lock_aquire(list);
        if(list->head) {
            node = list->head;
            if(node == list->tail) {
                list->tail = NULL;
            }
            if(node->next) {
                node->next->prev = NULL;
            }
            list->head = node->next;
            list->count--;
            obj = node->obj;
            free(node);
        }
        list_lock_release(list);
    }
    return obj;
}


static inline array_list_node_t * node_at_index(array_list_t* list, int position) {
    array_list_node_t * i = NULL;
    if((list) && (position < list->count)) {
        i = list->head;
        while (((position-1) >= 0) && i != NULL) {
            i = i->next; position--;
        }
    }
    return i;
}

// use this for random access which is linear time O(n)
// for seq access use iterator
void * object_at_index(array_list_t* list, int position) {
    array_list_node_t* node =  NULL;
    list_lock_aquire(list);
    node = node_at_index(list, position);
    void * obj = NULL;
    if(node) {
        obj = node->obj;
    }
    list_lock_release(list);
    return obj;
}

int insert_last_object(array_list_t * list, void *obj) {
    int ret = -1;
    
    if(obj && list) {
        array_list_node_t * node = NULL;
        node = allocate_object(obj);
        list_lock_aquire(list);
        if(list->head == NULL) {
            //if(list->head == NULL)
            {
                list->head = node;
                list->tail = list->head;
            }
//            else {
//                array_list_node_t* old = list->head;   //head = old->next ...
//                list->head = node;                  //head=node<->old->next ...
//                node->next = old;
//                old->prev = node;
//            }
        }
        else {
            node->prev = list->tail;
            list->tail->next = node;
            list->tail = node;
        }
        list->count++;
        list_lock_release(list);
        ret = 0;
    }
    return ret;
}

int insert_at_index(array_list_t * list, void * obj, int position)
{
    int ret = -1;
    if(list && obj) {
        
        if(position == 0) {
            ret = push_object(list, obj);
        }
        else if(position >= list->count) {
            ret = insert_last_object(list, obj);
        }
        else {
            list_lock_aquire(list);
            array_list_node_t * old = node_at_index(list, position);
            if(old) {
                array_list_node_t * new  = allocate_object(obj);
                new->next = old;
                new->prev = old->prev;
                old->prev->next = new;
                old->prev = new;
                list->count++;
                ret = 0;
            }
            list_lock_release(list);
        }
        
    }
    return ret;
}

int compare_and_insert(array_list_t * list, void* obj,
                       int (*is_condition_met)(void* obj, void* object_to_find)) {
    int ret = -1;
    if (list && obj && is_condition_met) {
        list_lock_aquire(list);
        array_list_node_t *new = allocate_object(obj);
        if(list->head == NULL) {
            list->head = new;
            list->tail = list->head;
            list->count++;
            ret = 0;
        }
        else {
            array_list_node_t *node = list->head;
            while(node) {
                if(is_condition_met(node->obj, obj)) {
                    if (node == list->head) {
                        new->prev = NULL;
                        list->head = new;
                    }
                    else {
                        new->prev       = node->prev;
                        new->prev->next = new;
                    }
                    new->next  = node;
                    node->prev = new;
                    list->count++;
                    ret = 0;
                    break;
                }
                else if(node == list->tail) {
                    node->next = new;
                    new->prev  = node;
                    new->next  = NULL;
                    list->tail = new;
                    list->count++;
                    ret = 0;
                    break;
                }
                node = node->next;
            }
        }
        list_lock_release(list);
    }
    return ret;
}

void* find_object(array_list_t * list, void* object_to_find, 
                    int (*is_equal)(void* obj, void* object_to_find)) {
    void *obj = NULL;
    if(list && is_equal && object_to_find) {
        list_lock_aquire(list);
        if(list->head != NULL) {
            array_list_node_t *node = list->head;
            while(node) {
                if(is_equal(node->obj , object_to_find)) {
                    obj = node->obj;
                    break;
                }
                node = node->next;
            }
        }
        list_lock_release(list);
    }
    return obj;
}

void* remove_last_object(array_list_t* list) {
    void * obj = NULL;
    if(list) {
        list_lock_aquire(list);
        if(list->head != NULL) {
            if(list->head == list->tail) {
                obj = list->head->obj;
                free(list->head);
                list->head = list->tail = NULL;
                list->count = 0;
            }
            //else if(list->tail != NULL)
            else {
                array_list_node_t * node2del = list->tail;
                obj = list->tail->obj;
                list->tail = node2del->prev;
                list->tail->next = NULL;
                list->count--;
                free(node2del);
            }
        }
        list_lock_release(list);
    }
    return obj;
}

// Lock should be aquired from the caller of the function
static inline void remove_node_helper (array_list_t* list, array_list_node_t* node) {
            if(node == list->head) {
                if(node == list->tail)
                list->tail = NULL;
                if(node->next) {
                    node->next->prev = NULL;
                }
                list->head = node->next;
            }else if(node == list->tail) {
                list->tail = node->prev;
                list->tail->next = NULL;
            }else {
                node->prev->next = node->next;
                node->next->prev = node->prev;
            }
            list->count--;
            free(node);
}

void remove_node(array_list_t* list, array_list_node_t* node) {
    if(list == NULL || node == NULL) return;
    list_lock_aquire(list);
    remove_node_helper(list, node);
    list_lock_release(list);
}

void* remove_object_at_index(array_list_t* list, int position) {
    void * obj = NULL;
    if(list) {
        list_lock_aquire(list);
        array_list_node_t * node = node_at_index(list, position);
        if(node) {
            obj = node->obj;
            remove_node_helper(list, node);
        }
        list_lock_release(list);
    }
    return obj;
}

void* remove_object(array_list_t* list, void* object_to_find, 
                    int (*is_equal)(void* obj, void* object_to_find)) {
    void *obj = NULL;
    if(list && is_equal) {
        list_lock_aquire(list);
        if(list->head != NULL) {
            array_list_node_t *node = list->head;
            while(node) {
                if(is_equal(node->obj , object_to_find)) {
                    obj = node->obj;
                    break;
                }
                node = node->next;
            }
            if(node) {
                remove_node_helper(list, node);
            }
        }
        list_lock_release(list);
    }
    return obj;
}

extern int list_get_size(array_list_t* list) {
    int size = 0;
    if(list) {
        list_lock_aquire(list);
        size = list->count;
        list_lock_release(list);
    }
    return size;
}

void bind_list_iterator(list_iterator_t* i, array_list_t* list) {
    if(i && list) {
        i->list = list;
        list_lock_aquire(list);
        i->iter = list->head;
        list_lock_release(list);
    }
}

list_iterator_t* new_list_iterator(array_list_t* list) {
    list_iterator_t* i = NULL;
    if(list) {
        i = (list_iterator_t*) calloc(1,sizeof(list_iterator_t));
        if(i) {
            bind_list_iterator(i, list);
        }
    }
    return i;
}

void free_list_iterator(list_iterator_t *i) {
    free(i);
}

void* get_next_list_object(list_iterator_t* i) {
    void * obj = NULL;
    if(i && i->iter) {
        list_lock_aquire(i->list);
        obj = i->iter->obj;
        i->iter = i->iter->next;
        list_lock_release(i->list);
    }
    return obj;
}

void* get_prev_list_object(list_iterator_t* i) {
    void * obj = NULL;
    if(i && i->iter && i->iter->prev)  {
        list_lock_aquire(i->list);
        obj = i->iter->prev->obj;
        i->iter = i->iter->prev;
        list_lock_release(i->list);
    }
    return obj;
}

void reset_list_iterator(list_iterator_t *i) {
    if(i && i->list) {
        list_lock_aquire(i->list);
        i->iter = i->list->head;
        list_lock_release(i->list);
    }
}







