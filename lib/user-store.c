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

#include <string.h>
#include <assert.h>

#include "user-store.h"

//create a new user_store
user_store* user_store_create() {
	user_store *store = sodium_malloc(sizeof(user_store));
	if (store == NULL) { //couldn't allocate memory
		return NULL;
	}
	store->length = 0;
	store->head = NULL;
	store->tail = NULL;
	//TODO check the result?
	sodium_mprotect_noaccess(store);
	return store;
}

//destroy a user store
void user_store_destroy(user_store* store) {
	user_store_clear(store);
	sodium_free(store);
}

/*
 * add a new user node to a user store.
 */
void add_user_store_node(user_store * const store, user_store_node * const node) {
	sodium_mprotect_readwrite(store); //unlock memory
	if (store->length == 0) { //first node in the list
		node->previous = NULL;
		node->next = NULL;
		store->head = node;
		store->tail = node;

		//update length
		store->length++;

		sodium_mprotect_noaccess(store);

		return;
	}

	//add the new node to the tail of the list
	sodium_mprotect_readwrite(store->tail);
	store->tail->next = node;
	sodium_mprotect_noaccess(store->tail);
	node->previous = store->tail;
	node->next = NULL;
	store->tail = node;


	//update length
	store->length++;

	//lock memory after usage
	sodium_mprotect_noaccess(node);
	sodium_mprotect_noaccess(store);
}

/*
 * create an empty user_store_node and set up all the pointers.
 */
user_store_node *create_user_store_node() {
	user_store_node *node = sodium_malloc(sizeof(user_store_node));
	if (node == NULL) {
		return NULL;
	}

	//initialise pointers
	node->previous = NULL;
	node->next = NULL;

	//initialise all the buffers
	buffer_init_with_pointer(node->public_identity_key, node->public_identity_key_storage, crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	buffer_init_with_pointer(node->private_identity_key, node->private_identity_key_storage, crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);

	//initialise prekey buffers
	for (size_t i = 0; i < PREKEY_AMOUNT; i++) {
		buffer_init_with_pointer(&(node->public_prekeys[i]), &(node->public_prekey_storage[i * crypto_box_PUBLICKEYBYTES]), crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
		buffer_init_with_pointer(&(node->private_prekeys[i]), &(node->private_prekey_storage[i * crypto_box_SECRETKEYBYTES]), crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	}

	conversation_store_init(node->conversations);

	return node;
}

//add a new user to the user store
//NOTE: The entire buffers are copied, not only the pointer
int user_store_add(
		user_store *store,
		const buffer_t * const public_identity,
		const buffer_t * const private_identity,
		const buffer_t * const public_prekeys,
		const buffer_t * const private_prekeys) {
	//check size of the input buffers
	if ((public_identity->content_length != crypto_box_PUBLICKEYBYTES)
			|| (private_identity->content_length != crypto_box_SECRETKEYBYTES)
			|| (public_prekeys->content_length != PREKEY_AMOUNT * crypto_box_PUBLICKEYBYTES)
			|| (private_prekeys->content_length != PREKEY_AMOUNT * crypto_box_SECRETKEYBYTES)) {
		return -6;
	}

	user_store_node *new_node = create_user_store_node();
	if (new_node == NULL) { //couldn't allocate memory
		return -1;
	}

	int status;
	//fill the content (copy keys)
	status = buffer_clone(new_node->public_identity_key, public_identity);
	if (status != 0) {
		sodium_free(new_node);
		return status;
	}
	status = buffer_clone(new_node->private_identity_key, private_identity);
	if (status != 0) {
		sodium_free(new_node);
		return status;
	}

	//prekeys
	//copy them
	status = buffer_clone_to_raw(new_node->public_prekey_storage, sizeof(new_node->private_prekey_storage), public_prekeys);
	if (status != 0) {
		sodium_free(new_node);
		return status;
	}
	status = buffer_clone_to_raw(new_node->private_prekey_storage, sizeof(new_node->private_prekey_storage), private_prekeys);
	if (status != 0) {
		sodium_free(new_node);
		return status;
	}

	add_user_store_node(store, new_node);

	return 0;
}

/*
 * Find a user for a given public identity key.
 *
 * Returns NULL if no user was found.
 */
user_store_node* user_store_find_node(user_store * const store, const buffer_t * const public_identity) {
	if (public_identity->content_length != crypto_box_PUBLICKEYBYTES) {
		return NULL;
	}

	sodium_mprotect_readonly(store);

	user_store_node *current_node = store->head;

	//search for the matching public identity key
	while (current_node != NULL) {
		sodium_mprotect_readonly(current_node);
		if (buffer_compare(current_node->public_identity_key, public_identity) == 0) {
			//match found
			sodium_mprotect_noaccess(current_node);
			break;
		}
		user_store_node *temp = current_node;
		current_node = current_node->next; //go on through the list
		sodium_mprotect_noaccess(temp);
	}
	sodium_mprotect_noaccess(store);

	return current_node;
}

/*
 * List all of the users.
 *
 * Returns a buffer containing a list of all the public
 * identity keys of the user.
 */
buffer_t* user_store_list(user_store * const store) {
	sodium_mprotect_readonly(store);
	buffer_t *list = buffer_create_on_heap(crypto_box_PUBLICKEYBYTES * store->length, crypto_box_PUBLICKEYBYTES * store->length);

	user_store_node *current_node = store->head;
	for (size_t i = 0; (i < store->length) && (current_node != NULL); i++) {
		sodium_mprotect_readonly(current_node);
		int status = buffer_copy(
				list,
				i * crypto_box_PUBLICKEYBYTES,
				current_node->public_identity_key,
				0,
				current_node->public_identity_key->content_length);
		if (status != 0) { //copying went wrong
			sodium_mprotect_noaccess(current_node);
			sodium_mprotect_noaccess(store);
			buffer_destroy_from_heap(list);

			return buffer_create_on_heap(0, 0);
		}
		user_store_node *next_node = current_node->next;
		sodium_mprotect_noaccess(current_node);
		current_node = next_node;
	}
	sodium_mprotect_noaccess(store);

	return list;
}

/*
 * Remove a user from the user store.
 *
 * The user is identified by it's public identity key.
 */
void user_store_remove_by_key(user_store * const store, const buffer_t * const public_identity) {
	user_store_node *node = user_store_find_node(store, public_identity);

	if (node == NULL) {
		return;
	}

	user_store_remove(store, node);
}

//remove a user form the user store
void user_store_remove(user_store *store, user_store_node *node) {
	if (node == NULL) {
		return;
	}

	sodium_mprotect_readwrite(store);
	sodium_mprotect_readwrite(node);

	//clear the conversation store
	conversation_store_clear(node->conversations);

	if (node->next != NULL) { //node is not the tail
		sodium_mprotect_readwrite(node->next);
		node->next->previous = node->previous;
		sodium_mprotect_noaccess(node->next);
	} else { //node ist the tail
		store->tail = node->previous;
	}
	if (node->previous != NULL) { //node ist not the head
		sodium_mprotect_readwrite(node->previous);
		node->previous->next = node->next;
		sodium_mprotect_noaccess(node->previous);
	} else { //node is the head
		store->head = node->next;
	}

	sodium_free(node);

	//update length
	store->length--;
	sodium_mprotect_noaccess(store);
}

//clear the entire user store
void user_store_clear(user_store *store){
	sodium_mprotect_readonly(store);
	while (store->length > 0) {
		user_store_remove(store, store->head);
		sodium_mprotect_readonly(store); //necessary because user_store_remove resets this
	}

	sodium_mprotect_noaccess(store);
}

mcJSON *user_store_node_json_export(user_store_node * const node, mempool_t * const pool) {
	mcJSON *json = mcJSON_CreateObject(pool);
	if (json == NULL) {
		return NULL;
	}

	//add identity keys
	mcJSON *public_identity = mcJSON_CreateHexString(node->public_identity_key, pool);
	if (public_identity == NULL) {
		return NULL;
	}
	mcJSON_AddItemToObject(json, buffer_create_from_string("public_identity"), public_identity, pool);
	mcJSON *private_identity = mcJSON_CreateHexString(node->private_identity_key, pool);
	if (private_identity == NULL) {
		return NULL;
	}
	mcJSON_AddItemToObject(json, buffer_create_from_string("private_identity"), private_identity, pool);

	/* create arrays for prekeys */
	mcJSON *public_prekey_array = mcJSON_CreateArray(pool);
	if (public_prekey_array == NULL) {
		return NULL;
	}
	mcJSON_AddItemToObject(json, buffer_create_from_string("public_prekeys"), public_prekey_array, pool);
	mcJSON *private_prekey_array = mcJSON_CreateArray(pool);
	if (private_prekey_array == NULL) {
		return NULL;
	}
	mcJSON_AddItemToObject(json, buffer_create_from_string("private_prekeys"), private_prekey_array, pool);

	/* fill prekey arrays */
	for (size_t i = 0; i < PREKEY_AMOUNT; i++) {
		assert(crypto_box_PUBLICKEYBYTES == crypto_box_SECRETKEYBYTES);

		//public prekey
		mcJSON *public_prekey = mcJSON_CreateHexString(&(node->public_prekeys[i]), pool);
		if (public_prekey == NULL) {
			return NULL;
		}
		mcJSON_AddItemToArray(public_prekey_array, public_prekey, pool);

		//private_prekey
		mcJSON *private_prekey = mcJSON_CreateHexString(&(node->private_prekeys[i]), pool);
		if (private_prekey == NULL) {
			return NULL;
		}
		mcJSON_AddItemToArray(private_prekey_array, private_prekey, pool);
	}

	//add conversation store
	mcJSON *conversations = conversation_store_json_export(node->conversations, pool);
	if (conversations == NULL) {
		return NULL;
	}

	mcJSON_AddItemToObject(json, buffer_create_from_string("conversations"), conversations, pool);

	return json;
}

/*
 * Serialise a user store into JSON. It get's a mempool_t buffer and stores a tree of
 * mcJSON objects into the buffer starting at pool->position.
 *
 * Returns NULL in case of Failure.
 */
mcJSON *user_store_json_export(user_store * const store, mempool_t * const pool) {
	if ((store == NULL) || (pool == NULL)) {
		return NULL;
	}

	mcJSON *json = mcJSON_CreateArray(pool);
	if (json == NULL) {
		return NULL;
	}

	//go through all the user_store_nodes
	sodium_mprotect_readonly(store);
	user_store_node *node = store->head;
	for (size_t i = 0; (i < store->length) && (node != NULL); i++) {
		sodium_mprotect_readonly(node);
		mcJSON *json_node = user_store_node_json_export(node, pool);
		if (json_node == NULL) {
			return NULL;
		}
		mcJSON_AddItemToArray(json, json_node, pool);

		// has to be done here because of the access permissions
		user_store_node *next_node = node->next;
		sodium_mprotect_noaccess(node);
		node = next_node;
	}
	sodium_mprotect_noaccess(store);

	return json;
}

/*
 * Import a list of prekeys from JSON.
 */
int prekey_import(user_store_node * const node, const mcJSON * const public_prekey_array, const mcJSON * const private_prekey_array) {
	if ((public_prekey_array == NULL) || (public_prekey_array->type != mcJSON_Array) || (public_prekey_array->length != PREKEY_AMOUNT)
			|| (private_prekey_array == NULL) || (private_prekey_array->type != mcJSON_Array) || (private_prekey_array->length != PREKEY_AMOUNT)) {
		return -1;
	}

	mcJSON *current_private_prekey = private_prekey_array->child;
	mcJSON *current_public_prekey = public_prekey_array->child;
	//copy the prekeys
	size_t i;
	for (i = 0;
			(i < PREKEY_AMOUNT)
				&& (current_private_prekey != NULL)
				&& (current_private_prekey->type == mcJSON_String)
				&& (current_private_prekey->valuestring->content_length == (2 * crypto_box_SECRETKEYBYTES + 1))
				&& (current_public_prekey != NULL)
				&& (current_public_prekey->type == mcJSON_String)
				&& (current_public_prekey->valuestring->content_length == (2 * crypto_box_PUBLICKEYBYTES + 1));
			i++,
				current_private_prekey = current_private_prekey->next,
				current_public_prekey = current_public_prekey->next) {
		//copy private prekey
		int status = buffer_clone_from_hex(&(node->private_prekeys[i]), current_private_prekey->valuestring);
		if (status != 0) {
			return status;
		}
		//copy public prekey
		status = buffer_clone_from_hex(&(node->public_prekeys[i]), current_public_prekey->valuestring);
		if (status != 0) {
			return status;
		}
	}

	if (i != PREKEY_AMOUNT) {
		return -5;
	}

	return 0;
}

/*
 * Deserialise a user store (import from JSON).
 */
user_store *user_store_json_import(const mcJSON * const json) {
	if ((json == NULL) || (json->type != mcJSON_Array)) {
		return NULL;
	}

	user_store *store = user_store_create();
	if (store == NULL) {
		return NULL;
	}

	//add all the users
	mcJSON *user = json->child;
	for (size_t i = 0; (i < json->length) && (user != NULL); i++, user = user->next) {
		//get reference to the relevant mcJSON objects
		mcJSON *private_identity = mcJSON_GetObjectItem(user, buffer_create_from_string("private_identity"));
		mcJSON *public_identity = mcJSON_GetObjectItem(user, buffer_create_from_string("public_identity"));
		mcJSON *private_prekeys = mcJSON_GetObjectItem(user, buffer_create_from_string("private_prekeys"));
		mcJSON *public_prekeys = mcJSON_GetObjectItem(user, buffer_create_from_string("public_prekeys"));
		mcJSON *conversations = mcJSON_GetObjectItem(user, buffer_create_from_string("conversations"));

		//check if they are valid
		if ((private_identity == NULL) || (private_identity->type != mcJSON_String) || (private_identity->valuestring->content_length != (2 * crypto_box_SECRETKEYBYTES + 1))
				|| (public_identity == NULL) || (public_identity->type != mcJSON_String) || (public_identity->valuestring->content_length != (2 * crypto_box_PUBLICKEYBYTES + 1))
				|| (conversations->type != mcJSON_Array)) {
			user_store_destroy(store);
			return NULL;
		}

		//create new user_store_node
		user_store_node *node = create_user_store_node();
		if (node == NULL) {
			user_store_destroy(store);
			return NULL;
		}

		//copy private_identity
		node->private_identity_key->readonly = false;
		if (buffer_clone_from_hex(node->private_identity_key, private_identity->valuestring) != 0) {
			sodium_free(node);
			user_store_destroy(store);
			return NULL;
		}
		node->private_identity_key->readonly = true;

		//copy public_identity
		node->public_identity_key->readonly = false;
		if (buffer_clone_from_hex(node->public_identity_key, public_identity->valuestring) != 0) {
			sodium_free(node);
			user_store_destroy(store);
			return NULL;
		}
		node->public_identity_key->readonly = true;

		//copy the prekeys
		if (prekey_import(node, public_prekeys, private_prekeys) != 0) {
			sodium_free(node);
			user_store_destroy(store);
			return NULL;
		}

		//import the conversation store
		if (conversation_store_json_import(node->conversations, conversations) != 0) {
			sodium_free(node);
			user_store_destroy(store);
			return NULL;
		}

		//now add the imported node to the user store, this also does all the sodium_mprotect work
		add_user_store_node(store, node);
	}

	return store;
}
