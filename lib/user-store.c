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

#include "constants.h"
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
	node->prekeys = NULL;

	//initialise all the buffers
	buffer_init_with_pointer(node->public_identity_key, node->public_identity_key_storage, PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	buffer_init_with_pointer(node->private_identity_key, node->private_identity_key_storage, PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);


	conversation_store_init(node->conversations);

	return node;
}

//add a new user to the user store
//NOTE: The entire buffers are copied, not only the pointer
int user_store_add(
		user_store *store,
		const buffer_t * const public_identity,
		const buffer_t * const private_identity) {
	//check size of the input buffers
	if ((public_identity->content_length != PUBLIC_KEY_SIZE)
			|| (private_identity->content_length != PRIVATE_KEY_SIZE)) {
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
	new_node->prekeys = prekey_store_create();
	if (new_node->prekeys == NULL) {
		status = -1;
		goto cleanup;
	}

	add_user_store_node(store, new_node);

cleanup:
	if (status != 0) {
		sodium_free(new_node);
	}

	return 0;
}

/*
 * Find a user for a given public identity key.
 *
 * Returns NULL if no user was found.
 */
user_store_node* user_store_find_node(user_store * const store, const buffer_t * const public_identity) {
	if (public_identity->content_length != PUBLIC_KEY_SIZE) {
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
	buffer_t *list = buffer_create_on_heap(PUBLIC_KEY_SIZE * store->length, PUBLIC_KEY_SIZE * store->length);

	user_store_node *current_node = store->head;
	for (size_t i = 0; (i < store->length) && (current_node != NULL); i++) {
		sodium_mprotect_readonly(current_node);
		int status = buffer_copy(
				list,
				i * PUBLIC_KEY_SIZE,
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
	buffer_create_from_string(public_identity_string, "public_identity");
	mcJSON_AddItemToObject(json, public_identity_string, public_identity, pool);
	mcJSON *private_identity = mcJSON_CreateHexString(node->private_identity_key, pool);
	if (private_identity == NULL) {
		return NULL;
	}
	buffer_create_from_string(private_identity_string, "private_identity");
	mcJSON_AddItemToObject(json, private_identity_string, private_identity, pool);

	//add prekeys
	mcJSON *prekeys = prekey_store_json_export(node->prekeys, pool);
	if (prekeys == NULL) {
		return NULL;
	}
	buffer_create_from_string(prekeys_string, "prekeys");
	mcJSON_AddItemToObject(json, prekeys_string, prekeys, pool);

	//add conversation store
	mcJSON *conversations = conversation_store_json_export(node->conversations, pool);
	if (conversations == NULL) {
		return NULL;
	}

	buffer_create_from_string(conversations_string, "conversations");
	mcJSON_AddItemToObject(json, conversations_string, conversations, pool);

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

	user_store_node *node = NULL;

	int status = 0;
	//add all the users
	mcJSON *user = json->child;
	for (size_t i = 0; (i < json->length) && (user != NULL); i++, user = user->next) {
		//create new user_store_node
		user_store_node *node = create_user_store_node();
		if (node == NULL) {
			status = -1;
			goto cleanup;
		}

		//private identity key
		buffer_create_from_string(private_identity_string, "private_identity");
		mcJSON *private_identity = mcJSON_GetObjectItem(user, private_identity_string);
		if ((private_identity == NULL) || (private_identity->type != mcJSON_String) || (private_identity->valuestring->content_length != (2 * PRIVATE_KEY_SIZE + 1))) {
			status = -1;
			goto cleanup;
		}
		node->private_identity_key->readonly = false;
		if (buffer_clone_from_hex(node->private_identity_key, private_identity->valuestring) != 0) {
			status = -1;
			goto cleanup;
		}
		node->private_identity_key->readonly = true;

		//public identity key
		buffer_create_from_string(public_identity_string, "public_identity");
		mcJSON *public_identity = mcJSON_GetObjectItem(user, public_identity_string);
		if ((public_identity == NULL) || (public_identity->type != mcJSON_String) || (public_identity->valuestring->content_length != (2 * PUBLIC_KEY_SIZE + 1))) {
			status = -1;
			goto cleanup;
		}
		node->public_identity_key->readonly = false;
		if (buffer_clone_from_hex(node->public_identity_key, public_identity->valuestring) != 0) {
			status = -1;
			goto cleanup;
		}
		node->public_identity_key->readonly = true;

		//prekeys
		buffer_create_from_string(prekeys_string, "prekeys");
		mcJSON *prekeys = mcJSON_GetObjectItem(user, prekeys_string);
		if ((prekeys == NULL) || (prekeys->type != mcJSON_Object)) {
			status = -1;
			goto cleanup;
		}
		node->prekeys = prekey_store_json_import(prekeys);
		if (node->prekeys == NULL) {
			status = -1;
			goto cleanup;
		}

		//conversations
		buffer_create_from_string(conversations_string, "conversations");
		mcJSON *conversations = mcJSON_GetObjectItem(user, conversations_string);
		if ((conversations == NULL) || (conversations->type != mcJSON_Array)) {
			status = -1;
			goto cleanup;
		}
		status = conversation_store_json_import(conversations, node->conversations);
		if (status != 0) {
			goto cleanup;
		}

		//now add the imported node to the user store, this also does all the sodium_mprotect work
		add_user_store_node(store, node);
	}

cleanup:
	if (status != 0) {
		user_store_destroy(store);
		if (node != NULL) {
			if (node->prekeys != NULL) {
				prekey_store_destroy(node->prekeys);
			}
			sodium_free(node);
		}
	}

	return store;
}
