/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

#ifndef hashmap_h
#define hashmap_h

#include <stdio.h>
#include <pthread.h>
#include <stdint.h>

typedef struct hash_map_s hash_map_t;
typedef struct hash_node_list_s hash_node_list_t;
typedef struct hash_key_node_s hash_key_node_t;

typedef enum e_hash_map_type {
    eHashMapDefault,
    eHashMapAtomic
}e_hash_map_type_t;

struct hash_node_list_s {
    hash_node_list_t* next;
    hash_key_node_t* key_node;
    uint8_t *key;      // key for searching the list
    void *value;
};

struct hash_key_node_s {
    hash_key_node_t *next;
    hash_key_node_t *prev;
    hash_node_list_t* node;
};

struct hash_map_s {
    uint32_t elementCount;
    hash_key_node_t * key_head;
    e_hash_map_type_t type;
    pthread_mutex_t lock;
    hash_node_list_t * hashBucket[256];
};

typedef struct hash_iterator_s {
    hash_map_t* map;
    hash_key_node_t* iter;
}hash_iterator_t;


static inline void hash_lock_aquire(hash_map_t * map) {
    if(map->type == eHashMapAtomic) pthread_mutex_lock(&(map->lock));
}

static inline void hash_lock_release(hash_map_t * map) {
    if(map->type == eHashMapAtomic) pthread_mutex_unlock(&(map->lock));
}



extern hash_iterator_t* new_hash_iterator(hash_map_t* map);            //O(1)
extern const char* get_next_hash_key(hash_iterator_t* i);               //O(1)
extern void reset_hash_iterator(hash_iterator_t *i);               //O(1)
extern void free_hash_iterator(hash_iterator_t *i);                //O(1)
extern void print_hash_iterator(hash_iterator_t * i);

extern size_t get_hash_map_size(hash_map_t * map);
extern void print_all_keys(hash_map_t * map);
extern hash_map_t* new_hash_map(e_hash_map_type_t type);
extern void delete_hash_map(hash_map_t* map);
extern void* get_value_for_key(hash_map_t* map, const char* key);
extern int set_value_for_key(hash_map_t* map, const char* key, void* value);    //O(1)
extern void remove_key(hash_map_t* map, const char* key);                             //O(1)
#endif /* hashmap_h */
