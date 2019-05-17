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
#include <string.h>
#include "hashmap.h"
#include "pearsonhash.h"

#define MAX_KEY_LEN 256

static hash_node_list_t* allocate_node(const char* key, void* e) {
    hash_node_list_t* node = NULL;
    size_t keyLen = strnlen(key, MAX_KEY_LEN) + 1 ;
    int cleanup = 1;
    do {
        if(key == NULL || e == NULL) break;
        node = (hash_node_list_t*) calloc(1,sizeof(hash_node_list_t));
        if(node == NULL) break;
        
        if(keyLen < MAX_KEY_LEN) {
            node->key = (uint8_t*) malloc(keyLen);
            if(node->key != NULL) {
                strncpy((char*) node->key, key, keyLen);
                node->value = e;
                cleanup = 0;
            }
        }
    } while(0);
    
    if(cleanup == 1) {
        //cleanup
        free(node->key);
        node->key = NULL;
        free(node);
        node = NULL;
    }
    return node;
}
static hash_key_node_t* remove_key_node(hash_key_node_t* head, hash_key_node_t* node);

static int append_node(hash_map_t * map, hash_node_list_t* head, hash_node_list_t* node) {
    hash_node_list_t * iter = head;
    hash_node_list_t * prev =  NULL;
    int ret = 0;
    while((iter != NULL) &&
          (strncmp( (const char*)node->key, (const char*) iter->key, MAX_KEY_LEN) != 0)) {
        prev = iter;
        iter = iter->next;
    }
    prev->next = node;
    
    if(iter != NULL) {
        node->next = iter->next;
        iter->key_node->node = node;
        node->key_node = iter->key_node;
        ret = 1;
        free(iter->key);
        free(iter);
    }
    return ret;
}

static hash_node_list_t* get_node_for_key(hash_node_list_t * head, const char * key) {
    hash_node_list_t * iter = head;
    while((iter != NULL) && (iter->key != NULL)) {
        if(iter->key != NULL && (strncmp((const char*) iter->key, key, MAX_KEY_LEN) == 0)) {
            break;
        }
        iter = iter->next;
    }
    return iter;
}

hash_map_t* new_hash_map(e_hash_map_type_t type) {
    hash_map_t* map = (hash_map_t*) calloc(1,sizeof(hash_map_t));
    int cleanup = 1;
    do {
        if(map == NULL){
            break;
        }
        map->type = type;
        pthread_mutex_init(&(map->lock), NULL);
        cleanup = 0;
    }while(0);
    if(cleanup) {
        if(map) {
            pthread_mutex_destroy(&(map->lock));
        }
        free(map);
        map = NULL;
    }
    return map;
}

void delete_hash_map(hash_map_t* map) {
    if(map == NULL) return;
    hash_iterator_t * iter = new_hash_iterator(map);
    const char * key = NULL;
    if(iter != NULL) {
        key = get_next_hash_key(iter);
        while(key != NULL) {
            remove_key(map, key);
            key = get_next_hash_key(iter);
        }
    }
    free_hash_iterator(iter);
    if(map && (map->type == eHashMapAtomic)) pthread_mutex_destroy(&(map->lock));
    free(map);
}


void print_all_keys(hash_map_t * map) {
    if(map == NULL) return;
    
    hash_key_node_t* iter = map->key_head;
    while(iter != NULL) {
        printf("key: %s\n", iter->node->key);
        iter = iter->next;
    }
    
}

size_t get_hash_map_size(hash_map_t * map) {
    if(map == NULL) return 0;
    
    size_t size = 0;
    hash_key_node_t* iter = map->key_head;
    while(iter != NULL) {
        size++;
        iter = iter->next;
    }
    return size;
}

static hash_key_node_t* push_key_node(hash_key_node_t* head, hash_node_list_t* node) {
    hash_key_node_t* keyNode = NULL;
    if(node != NULL) {
        keyNode = (hash_key_node_t*) calloc(1,sizeof(hash_key_node_t));
        node->key_node = keyNode;
        keyNode->node = node;
        keyNode->next = head;
        if(head) {
            head->prev = keyNode;
        }
    }
    return keyNode;
}

static hash_key_node_t* remove_key_node(hash_key_node_t* head, hash_key_node_t* node) {
    hash_key_node_t * newHead = NULL;
    if(node != NULL) {
        if(node == head && node->next == NULL) {
            //single node delete
            newHead = NULL;
        } else if(node == head && node->next != NULL) {
            newHead = head->next;
        } else {
            node->prev->next = node->next;
            if(node->next) {
                node->next->prev = node->prev;
            }
            newHead = head;
        }
        free(node);
    }
    else {
        newHead = head;
    }
    return newHead;

}

int set_value_for_key(hash_map_t *map, const char* key, void* value) {
    int hashIndex = -1;
    int key_exist = 0;
    hashIndex = phash8(key);
   
    hash_node_list_t * node =allocate_node(key, value);
    hash_lock_aquire(map);
    if(node != NULL) {
        if(map->hashBucket[hashIndex] == NULL) {
            map->hashBucket[hashIndex] = node;
        }
        else if(strncmp((const char *) map->hashBucket[hashIndex]->key,key,strnlen(key,MAX_KEY_LEN)) ==0) {
            hash_node_list_t * oldNode = map->hashBucket[hashIndex];
            node->next = oldNode->next;
            node->key_node = oldNode->key_node;
            node->key_node->node = node;
            free(oldNode->key);
            free(oldNode);
            map->hashBucket[hashIndex] = node;
            key_exist = 1;
        }
        else {
            key_exist = append_node(map, map->hashBucket[hashIndex], node);
        }
        if(key_exist == 0) map->key_head = push_key_node(map->key_head, node);
    }
    hash_lock_release(map);
    return hashIndex;
}


void* get_value_for_key(hash_map_t * map, const char* key) {
    uint8_t hashIndex = phash8(key);
    void * value = NULL;
    hash_node_list_t* node = NULL;
    hash_lock_aquire(map);
    
    if(map->hashBucket[hashIndex] != NULL) {
        node = get_node_for_key(map->hashBucket[hashIndex], key);
    }
    if(node) {
        value = node->value;
    }
    hash_lock_release(map);
    return value;
}

static hash_node_list_t* remove_node_with_key(hash_map_t* map, hash_node_list_t* head, const char * key) {
    hash_node_list_t * ret = head;
    hash_node_list_t * iter = head;
    hash_node_list_t* prev = NULL;
    while(iter != NULL && (strncmp((const char *) iter->key, key, strnlen(key,MAX_KEY_LEN)) != 0)) {
        prev = iter;
        iter = iter->next;
    }
    
    if(iter != NULL) {
        if(head == iter) {
            ret = head->next;
        }else {
            prev->next = iter->next;
        }
        map->key_head = remove_key_node(map->key_head,iter->key_node);
        free(iter->key);
        free(iter);
    }
    return ret;
}

void remove_key(hash_map_t* map, const char* key) {
    //if(map == NULL || key == NULL) return;
    uint8_t hashIndex = phash8(key);
    hash_node_list_t* array_head = NULL;
    hash_lock_aquire(map);
    array_head = map->hashBucket[hashIndex];
    if(array_head != NULL) {
        if(array_head->next == NULL) {
            map->key_head = remove_key_node(map->key_head, array_head->key_node);
            free(array_head->key);
            free(array_head);
            map->hashBucket[hashIndex] = NULL;
        }
        else {
            map->hashBucket[hashIndex] = remove_node_with_key(map, array_head,key);
        }
    }
    hash_lock_release(map);
}

hash_iterator_t* new_hash_iterator(hash_map_t* map) {
    hash_iterator_t* i = (hash_iterator_t*) calloc(1,sizeof(hash_iterator_t));
    i->map = map;
    i->iter = map->key_head;
    return i;
}

void free_hash_iterator(hash_iterator_t *i) {
    free(i);
}

void reset_hash_iterator(hash_iterator_t *i) {
    hash_lock_aquire(i->map);
    i->iter = i->map->key_head;
    hash_lock_release(i->map);
}

const char* get_next_hash_key(hash_iterator_t* i)
{
    hash_node_list_t * node = NULL;
    const char * key = NULL;
    hash_lock_aquire(i->map);
    if(i->iter != NULL) {
        node = i->iter->node;
        i->iter = i->iter->next;
        if(node != NULL) {
            key = (const char *) node->key;
        }
    }
    hash_lock_release(i->map);
    return key;
}

void print_hash_iterator(hash_iterator_t * i) {
    const char* key = NULL;
    do {
        key = get_next_hash_key(i);
        printf("The Key is %s\n",key);
    }while(key != NULL);
    
}

