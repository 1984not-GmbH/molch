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
return_status user_store_create(user_store ** const store) {
	return_status status = return_status_init();

	//check input
	if (store == NULL) {
		throw(INVALID_INPUT, "Pointer to put new user store into is NULL.");
	}

	*store = sodium_malloc(sizeof(user_store));
	if (*store == NULL) {
		throw(ALLOCATION_FAILED, "Failed to allocate user store.");
	}

	//initialise
	(*store)->length = 0;
	(*store)->head = NULL;
	(*store)->tail = NULL;

cleanup:
	if (status.status != SUCCESS) {
		if (store != NULL) {
			*store = NULL;
		}
	}

	return status;
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
	if (store->length == 0) { //first node in the list
		node->previous = NULL;
		node->next = NULL;
		store->head = node;
		store->tail = node;

		//update length
		store->length++;

		return;
	}

	//add the new node to the tail of the list
	store->tail->next = node;
	node->previous = store->tail;
	node->next = NULL;
	store->tail = node;

	//update length
	store->length++;
}

/*
 * create an empty user_store_node and set up all the pointers.
 */
return_status create_user_store_node(user_store_node ** const node) {
	return_status status = return_status_init();

	if (node == NULL) {
		throw(INVALID_INPUT, "Pointer to put new user store node into is NULL.");
	}

	*node = sodium_malloc(sizeof(user_store_node));
	if (*node == NULL) {
		throw(ALLOCATION_FAILED, "Failed to allocate user store node.");
	}

	//initialise pointers
	(*node)->previous = NULL;
	(*node)->next = NULL;
	(*node)->prekeys = NULL;
	(*node)->master_keys = NULL;

	//initialise the public_signing key buffer
	buffer_init_with_pointer((*node)->public_signing_key, (*node)->public_signing_key_storage, PUBLIC_MASTER_KEY_SIZE, PUBLIC_MASTER_KEY_SIZE);

	conversation_store_init((*node)->conversations);

cleanup:
	if (status.status != SUCCESS) {
		if (node != NULL) {
			*node = NULL;
		}
	}

	return status;
}

/*
 * Create a new user and add it to the user store.
 *
 * The seed is optional an can be used to add entropy in addition
 * to the entropy provided by the OS. IMPORTANT: Don't put entropy in
 * here, that was generated by the OSs CPRNG!
 */
return_status user_store_create_user(
		user_store *store,
		const buffer_t * const seed, //optional, can be NULL
		buffer_t * const public_signing_key, //output, optional, can be NULL
		buffer_t * const public_identity_key) { //output, optional, can be NULL

	return_status status = return_status_init();

	user_store_node *new_node = NULL;
	status = create_user_store_node(&new_node);
	throw_on_error(CREATION_ERROR, "Failed to create new user store node.");

	//generate the master keys
	status = master_keys_create(
			&(new_node->master_keys),
			seed,
			new_node->public_signing_key,
			public_identity_key);
	throw_on_error(CREATION_ERROR, "Failed to create master keys.");

	//prekeys
	status = prekey_store_create(&(new_node->prekeys));
	throw_on_error(CREATION_ERROR, "Failed to create prekey store.")

	//copy the public signing key, if requested
	if (public_signing_key != NULL) {
		if (public_signing_key->buffer_length < PUBLIC_MASTER_KEY_SIZE) {
			throw(INCORRECT_BUFFER_SIZE, "Invalidly sized buffer for public signing key.");
		}

		if (buffer_clone(public_signing_key, new_node->public_signing_key) != 0) {
			throw(BUFFER_ERROR, "Failed to clone public signing key.");
		}
	}

	add_user_store_node(store, new_node);

cleanup:
	if (status.status != SUCCESS) {
		if (new_node != NULL) {
			if (new_node->prekeys != NULL) {
				prekey_store_destroy(new_node->prekeys);
			}
			if (new_node->master_keys != NULL) {
				sodium_free(new_node->master_keys);
			}

			sodium_free(new_node);
		}
	}

	return status;
}

/*
 * Find a user for a given public signing key.
 *
 * Returns NULL if no user was found.
 */
return_status user_store_find_node(user_store_node ** const node, user_store * const store, const buffer_t * const public_signing_key) {
	return_status status = return_status_init();

	if ((node == NULL) || (public_signing_key == NULL) || (public_signing_key->content_length != PUBLIC_MASTER_KEY_SIZE)) {
		throw(INVALID_INPUT, "Invalid input for user_store_find_node.");
	}

	*node = store->head;

	//search for the matching public identity key
	while (*node != NULL) {
		if (buffer_compare((*node)->public_signing_key, public_signing_key) == 0) {
			//match found
			break;
		}
		*node = (*node)->next; //go on through the list
	}
	if (*node == NULL) {
		throw(NOT_FOUND, "Couldn't find the user store node.");
	}

cleanup:
	if (status.status != SUCCESS) {
		if (node != NULL) {
			*node = NULL;
		}
	}

	return status;
}

/*
 * List all of the users.
 *
 * Returns a buffer containing a list of all the public
 * signing keys of the user.
 *
 * The buffer is heap allocated, so don't forget to free it!
 */
return_status user_store_list(buffer_t ** const list, user_store * const store) {
	return_status status = return_status_init();

	if ((list == NULL) || (store == NULL)) {
		throw(INVALID_INPUT, "Invalid input to user_store_list.");
	}

	*list = buffer_create_on_heap(PUBLIC_MASTER_KEY_SIZE * store->length, PUBLIC_MASTER_KEY_SIZE * store->length);
	if (*list == NULL) {
		throw(ALLOCATION_FAILED, "Failed to allocate user list buffer.");
	}

	user_store_node *current_node = store->head;
	for (size_t i = 0; (i < store->length) && (current_node != NULL); i++) {
		int status_int = buffer_copy(
				*list,
				i * PUBLIC_MASTER_KEY_SIZE,
				current_node->public_signing_key,
				0,
				current_node->public_signing_key->content_length);
		if (status_int != 0) { //copying went wrong
			throw(BUFFER_ERROR, "Failed to copy public master key to user list.");
		}

		user_store_node *next_node = current_node->next;
		current_node = next_node;
	}

cleanup:
	if (status.status != SUCCESS) {
		if (list != NULL) {
			if (*list != NULL) {
				buffer_destroy_from_heap(*list);
			}
		}
	}

	return status;
}

/*
 * Remove a user from the user store.
 *
 * The user is identified by it's public signing key.
 */
return_status user_store_remove_by_key(user_store * const store, const buffer_t * const public_signing_key) {
	return_status status = return_status_init();

	user_store_node *node = NULL;
	status = user_store_find_node(&node, store, public_signing_key);
	throw_on_error(NOT_FOUND, "Failed to find user to remove.");

	user_store_remove(store, node);

cleanup:
	return status;
}

//remove a user form the user store
void user_store_remove(user_store *store, user_store_node *node) {
	if (node == NULL) {
		return;
	}

	//clear the conversation store
	conversation_store_clear(node->conversations);

	if (node->next != NULL) { //node is not the tail
		node->next->previous = node->previous;
	} else { //node ist the tail
		store->tail = node->previous;
	}
	if (node->previous != NULL) { //node ist not the head
		node->previous->next = node->next;
	} else { //node is the head
		store->head = node->next;
	}

	sodium_free(node);

	//update length
	store->length--;
}

//clear the entire user store
void user_store_clear(user_store *store){
	if (store == NULL) {
		return;
	}

	while (store->length > 0) {
		user_store_remove(store, store->head);
	}

}

mcJSON *user_store_node_json_export(user_store_node * const node, mempool_t * const pool) {
	mcJSON *json = mcJSON_CreateObject(pool);
	if (json == NULL) {
		return NULL;
	}

	//add master keys
	mcJSON *master_keys = master_keys_json_export(node->master_keys, pool);
	if (master_keys == NULL) {
		return NULL;
	}
	buffer_create_from_string(master_keys_string, "master_keys");
	mcJSON_AddItemToObject(json, master_keys_string, master_keys, pool);

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
	user_store_node *node = store->head;
	for (size_t i = 0; (i < store->length) && (node != NULL); i++) {
		mcJSON *json_node = user_store_node_json_export(node, pool);
		if (json_node == NULL) {
			return NULL;
		}
		mcJSON_AddItemToArray(json, json_node, pool);

		// has to be done here because of the access permissions
		user_store_node *next_node = node->next;
		node = next_node;
	}

	return json;
}

/*
 * Deserialise a user store (import from JSON).
 */
user_store *user_store_json_import(const mcJSON * const json) {
	return_status status = return_status_init();

	user_store *store = NULL;
	user_store_node *node = NULL;

	if ((json == NULL) || (json->type != mcJSON_Array)) {
		throw(INVALID_INPUT, "Invalid input for user_store_json_import.");
	}

	status = user_store_create(&store);
	throw_on_error(CREATION_ERROR, "Failed to create user store.");

	//add all the users
	mcJSON *user = json->child;
	for (size_t i = 0; (i < json->length) && (user != NULL); i++, user = user->next) {
		//create new user_store_node
		node = NULL;
		status = create_user_store_node(&node);
		throw_on_error(CREATION_ERROR, "Failed to create user store node.");

		//master keys
		buffer_create_from_string(master_keys_string, "master_keys");
		mcJSON *master_keys = mcJSON_GetObjectItem(user, master_keys_string);
		if ((master_keys == NULL) || (master_keys->type != mcJSON_Object)) {
			throw(DATA_FETCH_ERROR, "Failed to get master keys from JSON tree.");
		}
		node->master_keys = master_keys_json_import(master_keys);
		if (node->master_keys == NULL) {
			throw(IMPORT_ERROR, "Failed to import master keys from JSON.");
		}
		//copy the public signing key
		status = master_keys_get_signing_key(node->master_keys, node->public_signing_key);
		throw_on_error(DATA_FETCH_ERROR, "Failed to get signing key from master keys.");

		//prekeys
		buffer_create_from_string(prekeys_string, "prekeys");
		mcJSON *prekeys = mcJSON_GetObjectItem(user, prekeys_string);
		if ((prekeys == NULL) || (prekeys->type != mcJSON_Object)) {
			throw(DATA_FETCH_ERROR, "Failed to get prekeys from JSON tree.");
		}
		node->prekeys = prekey_store_json_import(prekeys);
		if (node->prekeys == NULL) {
			throw(IMPORT_ERROR, "Failed to import prekeys from JSON.");
		}

		//conversations
		buffer_create_from_string(conversations_string, "conversations");
		mcJSON *conversations = mcJSON_GetObjectItem(user, conversations_string);
		if ((conversations == NULL) || (conversations->type != mcJSON_Array)) {
			throw(DATA_FETCH_ERROR, "Failed to get conversations from JSON tree.");
		}
		if (conversation_store_json_import(conversations, node->conversations) != 0) {
			throw(IMPORT_ERROR, "Failed to import conversations from JSON.");
		}

		//now add the imported node to the user store
		add_user_store_node(store, node);
		node = NULL;
	}

cleanup:
	if (status.status != SUCCESS) {
		if (store != NULL) {
			user_store_destroy(store);
		}

		if (node != NULL) {
			if (node->prekeys != NULL) {
				prekey_store_destroy(node->prekeys);
			}
			if (node->master_keys != NULL) {
				sodium_free(node->master_keys);
			}
			sodium_free(node);
		}

		return_status_destroy_errors(&status);
	}

	return store;
}
