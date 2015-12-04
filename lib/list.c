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

#include <stdlib.h>

#include "list.h"

/*
 * Create a new list.
 */
void list_init(list_t *list) {
	//initialize list
	list->length = 0;
	list->head = NULL;
	list->tail = NULL;
}

/*
 * add a new node to a list.
 */
void add_list_node(list_t * const list, list_node * const node) {
	if (list->length == 0) { //first node in the list
		node->previous = NULL;
		node->next = NULL;
		list->head = node;
		list->tail = node;

		//update length
		list->length++;

		return;
	}

	//add the new node to the tail of the list
	list->tail->next = node;
	node->previous = list->tail;
	node->next = NULL;
	list->tail = node;

	//update length
	list->length++;
}

/*
 * Add a new element to the end of the list.
 *
 * The node parameter can be used to pass a node to use, if NULL, malloc will be used.
 */
int list_add(list_t * const list, void * const data, list_node *node) {
	if ((list == NULL) || (data == NULL)) {
		return -1;
	}

	// if no node has been passed, create one
	if (node == NULL) {
		node = malloc(sizeof(list_node));
		if (node == NULL) {
			return -1;
		}
	}

	node->data = data;
	add_list_node(list, node);

	return 0;
}

/*
 * Remove an element from the list.
 *
 * Get's two function pointers. One that will be used to free the node and one to free the data.
 * If one of those functions is NULL, the corresponding data will not be freed.
 */
void list_remove(list_t * const list, list_node * const node, void (*free_node)(void*), void (*free_data)(void*)) {
	if ((list == NULL) || (node == NULL)) {
		return;
	}

	if (node->next != NULL) { //node is not the tail
		node->next->previous = node->previous;
	} else {
		list->tail = node->previous;
	}

	if (node->previous != NULL) { //node is not the head
		node->previous->next = node->next;
	} else {
		list->head = node->next;
	}

	list->length--;

	//free the node
	if (free_data != NULL) {
		free_data(node->data);
	}

	if (free_node != NULL) {
		free_node(node);
	}
}

/*
 * Remove all elements from a list
 */
void list_clear(list_t * const list, void (*free_node)(void*), void (*free_data)(void*)) {
	if (list == NULL) {
		return;
	}

	while (list->length > 0) {
		list_remove(list, list->tail, free_node, free_data);
	}
}
