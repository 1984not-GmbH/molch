/* Molch, an implementation of the axolotl ratchet based on libsodium
 *  Copyright (C) 2015  Max Bruckner (FSMaxB)
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <stddef.h>

#ifndef LIB_LIST_H
#define LIB_LIST_H
//This is a generic list data type that can store arbitrary data
//It is intended to be used to implement other list types, not directly.
//Kind of like an abstract class.

//node of the linked list
typedef struct list_node list_node;
struct list_node {
	list_node *previous;
	list_node *next;
	void *data;
};

//header of the linked list
typedef struct list_t {
	size_t length;
	list_node *head;
	list_node *tail;
} list_t;

/*
 * Init a list.
 */
void list_init(list_t *list);

/*
 * Add a new element to the end of the list.
 *
 * The node parameter can be used to pass a node to use, if NULL, malloc will be used.
 */
int list_add(list_t * const list, void * const data, list_node *node) __attribute__((warn_unused_result));

/*
 * Remove an element from the list.
 *
 * Get's two function pointers. One that will be used to free the node and one to free the data.
 * If one of those functions is NULL, the corresponding data will not be freed.
 */
void list_remove(list_t * const list, list_node * const node, void (*free_node)(void*), void (*free_data)(void*));

/*
 * Remove all elements from a list
 */
void list_clear(list_t * const list, void (*free_node)(void*), void (*free_data)(void*));

/*
 * Loop through the list. In each iteration, the variables 'index', 'node' and 'value' are available.
 */
#define list_foreach(list, code) {\
	if (list != NULL) {\
		list_node *node = list->head;\
		for (size_t index = 0; (index < list->length) && (node != NULL); index++, node = node->next) {\
			void *value __attribute__((unused));\
			value = node->data;\
			code\
		}\
	}\
}
#endif
