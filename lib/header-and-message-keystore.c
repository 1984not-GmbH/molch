/*
 * Molch, an implementation of the axolotl ratchet based on libsodium
 *
 * ISC License
 *
 * Copyright (C) 2015-2016 1984not Security GmbH
 * Author: Max Bruckner (FSMaxB)
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <string.h>

#include "constants.h"
#include "header-and-message-keystore.h"

static const time_t EXPIRATION_TIME = 3600 * 24 * 31; //one month

//create new keystore
void header_and_message_keystore_init(header_and_message_keystore * const keystore) {
	keystore->length = 0;
	keystore->head = NULL;
	keystore->tail = NULL;
}

/*
 * create an empty header_and_message_keystore_node and set up all the pointers.
 */
header_and_message_keystore_node *create_node() {
	header_and_message_keystore_node *node = sodium_malloc(sizeof(header_and_message_keystore_node));
	if (node == NULL) {
		return NULL;
	}

	//initialise buffers with storage arrays
	buffer_init_with_pointer(node->message_key, node->message_key_storage, MESSAGE_KEY_SIZE, 0);
	buffer_init_with_pointer(node->header_key, node->header_key_storage, HEADER_KEY_SIZE, 0);

	return node;
}

/*
 * add a new header_and_message_key_node to a keystore
 */
void add_node(header_and_message_keystore * const keystore, header_and_message_keystore_node * const node) {
	if (keystore->length == 0) { //first node in the list
		node->previous = NULL;
		node->next = NULL;
		keystore->head = node;
		keystore->tail = node;

		//update length
		keystore->length++;
		return;
	}

	//add the new node to the tail of the list
	keystore->tail->next = node;
	node->previous = keystore->tail;
	node->next = NULL;
	keystore->tail = node;

	//update length
	keystore->length++;
}

//add a message key to the keystore
//NOTE: The entire keys are copied, not only the pointer
return_status header_and_message_keystore_add(
		header_and_message_keystore *keystore,
		const buffer_t * const message_key,
		const buffer_t * const header_key) {
	return_status status = return_status_init();

	//check buffer sizes
	if ((message_key->content_length != MESSAGE_KEY_SIZE)
			|| (header_key->content_length != HEADER_KEY_SIZE)) {
		throw(INVALID_INPUT, "Invalid input to header_and_message_keystore_add.");
	}

	header_and_message_keystore_node *new_node = create_node();
	if (new_node == NULL) {
		throw(CREATION_ERROR, "Failed to create node.");
	}

	int status_int = 0;
	//set keys and expiration date
	new_node->expiration_date = time(NULL) + EXPIRATION_TIME;
	status_int = buffer_clone(new_node->message_key, message_key);
	if (status_int != 0) {
		sodium_free_and_null_if_valid(new_node);
		throw(BUFFER_ERROR, "Failed to copy message key.");
	}
	status_int = buffer_clone(new_node->header_key, header_key);
	if (status_int != 0) {
		sodium_free_and_null_if_valid(new_node);
		throw(BUFFER_ERROR, "Failed to copy header key.");
	}

	add_node(keystore, new_node);

cleanup:
	return status;
}

//remove a set of header and message keys from the keystore
void header_and_message_keystore_remove(header_and_message_keystore *keystore, header_and_message_keystore_node *node) {
	if (node == NULL) {
		return;
	}

	if (node->next != NULL) { //node is not the tail
		node->next->previous = node->previous;
	} else { //node ist the tail
		keystore->tail = node->previous;
	}
	if (node->previous != NULL) { //node ist not the head
		node->previous->next = node->next;
	} else { //node is the head
		keystore->head = node->next;
	}

	//free node and overwrite with zero
	sodium_free_and_null_if_valid(node);

	//update length
	keystore->length--;
}

//clear the entire keystore
void header_and_message_keystore_clear(header_and_message_keystore *keystore){
	while (keystore->length > 0) {
		header_and_message_keystore_remove(keystore, keystore->head);
	}
}

mcJSON *header_and_message_keystore_node_json_export(header_and_message_keystore_node * const node, mempool_t * const pool) {
	mcJSON *json = mcJSON_CreateObject(pool);
	if (json == NULL) {
		return NULL;
	}

	//add expiration_date
	mcJSON *expiration_date = mcJSON_CreateNumber((double)node->expiration_date, pool);
	if (expiration_date == NULL) {
		return NULL;
	}
	buffer_create_from_string(expiration_date_string, "expiration_date");
	mcJSON_AddItemToObject(json, expiration_date_string, expiration_date, pool);

	//add message key
	mcJSON *message_key_hex = mcJSON_CreateHexString(node->message_key, pool);
	if (message_key_hex == NULL) {
		return NULL;
	}
	buffer_create_from_string(message_key_string, "message_key");
	mcJSON_AddItemToObject(json, message_key_string, message_key_hex, pool);

	//add header key
	mcJSON *header_key_hex = mcJSON_CreateHexString(node->header_key, pool);
	if (header_key_hex == NULL) {
		return NULL;
	}
	buffer_create_from_string(header_key_string, "header_key");
	mcJSON_AddItemToObject(json, header_key_string, header_key_hex, pool);

	return json;
}

/*
 * Serialise a header_and_message_keystore into JSON. It get's a mempool_t buffer and stores a
 * tree of mcJSON objects into the buffer starting at pool->position
 */
mcJSON *header_and_message_keystore_json_export(
		header_and_message_keystore * const keystore,
		mempool_t * const pool) {
	if ((keystore == NULL) || (pool == NULL)) {
		return NULL;
	}

	mcJSON *json = mcJSON_CreateArray(pool);
	if (json == NULL) {
		return NULL;
	}

	//go through all the header_and_message_keystore_nodes
	header_and_message_keystore_node *node = keystore->head;
	for (size_t i = 0; (i < keystore->length) && (node != NULL); i++, node = node->next) {
		mcJSON *json_node = header_and_message_keystore_node_json_export(node, pool);
		if (json_node == NULL) {
			return NULL;
		}
		mcJSON_AddItemToArray(json, json_node, pool);
	}

	return json;
}

/*
 * Deserialise a heade_and_message_keystore (import from JSON).
 */
int header_and_message_keystore_json_import(
		const mcJSON * const json,
		header_and_message_keystore * const keystore) {
	if ((json == NULL) || (keystore == NULL)) {
		return -1;
	}

	if (json->type != mcJSON_Array) {
		return -2;
	}

	//initialize the keystore
	header_and_message_keystore_init(keystore);

	//add all the keys
	mcJSON *key = json->child;
	for (size_t i = 0; (i < json->length) && (key != NULL); i++, key = key->next) {
		//get references to the relevant mcJSON objects
		buffer_create_from_string(message_key_string, "message_key");
		mcJSON *message_key = mcJSON_GetObjectItem(key, message_key_string);
		buffer_create_from_string(header_key_string, "header_key");
		mcJSON *header_key = mcJSON_GetObjectItem(key, header_key_string);
		buffer_create_from_string(expiration_date_string, "expiration_date");
		mcJSON *expiration_date = mcJSON_GetObjectItem(key, expiration_date_string);

		//check if they are valid
		if ((message_key == NULL) || (message_key->type != mcJSON_String) || (message_key->valuestring->content_length != (2 * MESSAGE_KEY_SIZE + 1))
				|| (header_key == NULL) || (header_key->type != mcJSON_String) || (header_key->valuestring->content_length != (2 * HEADER_KEY_SIZE + 1))
				|| (expiration_date == NULL) || (expiration_date->type != mcJSON_Number)) {
			header_and_message_keystore_clear(keystore);
			return -3;
		}

		header_and_message_keystore_node *node = create_node();
		if (node == NULL) {
			header_and_message_keystore_clear(keystore);
			return -4;
		}

		//copy the mesage key
		int status = buffer_clone_from_hex(node->message_key, message_key->valuestring);
		if (status != 0) {
			sodium_free_and_null_if_valid(node);
			header_and_message_keystore_clear(keystore);
			return status;
		}

		//copy the header key
		status = buffer_clone_from_hex(node->header_key, header_key->valuestring);
		if (status != 0) {
			sodium_free_and_null_if_valid(node);
			header_and_message_keystore_clear(keystore);
			return status;
		}

		node->expiration_date = expiration_date->valuedouble; //double should be large enough

		add_node(keystore, node);
	}
	return 0;
}
