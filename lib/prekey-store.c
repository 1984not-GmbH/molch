/* Molch, an implementation of the axolotl ratchet based on libsodium
 *  Copyright (C) 2015-2016 1984not Security GmbH
 *  Author: Max Bruckner (FSMaxB)
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

#include <sodium.h>
#include <limits.h>
#include "prekey-store.h"

static const time_t PREKEY_EXPIRATION_TIME = 3600 * 24 * 31; //one month
static const time_t DEPRECATED_PREKEY_EXPIRATION_TIME = 3600; //one hour

/*
 * Initialise a new keystore. Generates all the keys.
 */
return_status prekey_store_create(prekey_store ** const store) {
	return_status status = return_status_init();

	if (store == NULL) {
		throw(INVALID_INPUT, "Invalid input to prekey_store_create.");
	}

	*store = sodium_malloc(sizeof(prekey_store));
	if (*store == NULL) {
		throw(ALLOCATION_FAILED, "Failed to allocate prekey store.");
	}
	//set expiration date to the past --> rotate will create new keys
	(*store)->oldest_expiration_date = 0;
	(*store)->oldest_deprecated_expiration_date = 0;

	(*store)->deprecated_prekeys = NULL;

	for (size_t i = 0; i < PREKEY_AMOUNT; i++) {
		(*store)->prekeys[i].expiration_date = time(NULL) + PREKEY_EXPIRATION_TIME;
		if (((*store)->oldest_expiration_date == 0) || ((*store)->prekeys[i].expiration_date < (*store)->oldest_expiration_date)) {
			(*store)->oldest_expiration_date = (*store)->prekeys[i].expiration_date;
		}

		(*store)->prekeys[i].next = NULL;

		//initialize the key buffers
		buffer_init_with_pointer(
				(*store)->prekeys[i].public_key,
				(*store)->prekeys[i].public_key_storage,
				PUBLIC_KEY_SIZE,
				PUBLIC_KEY_SIZE);
		buffer_init_with_pointer(
				(*store)->prekeys[i].private_key,
				(*store)->prekeys[i].private_key_storage,
				PRIVATE_KEY_SIZE,
				PRIVATE_KEY_SIZE);

		//generate the keys
		int status_int = 0;
		status_int = crypto_box_keypair(
				(*store)->prekeys[i].public_key->content,
				(*store)->prekeys[i].private_key->content);
		if (status_int != 0) {
			throw(KEYGENERATION_FAILED, "Failed to generate prekey pair.");
		}
	}

cleanup:
	if (status.status != SUCCESS) {
		if (store != NULL) {
			if (*store != NULL) {
				sodium_free(store);
				*store = NULL;
			}
		}
	}

	return status;
}

/*
 * Helper that puts a prekey pair in the deprecated list and generates a new one.
 */
int deprecate(prekey_store * const store, size_t index) {
	int status = 0;
	//create a new node
	prekey_store_node *deprecated_node = sodium_malloc(sizeof(prekey_store_node));
	if (deprecated_node == NULL) {
		status = -1;
		goto cleanup;
	}

	//initialise the deprecated node
	deprecated_node->next =store->deprecated_prekeys;
	deprecated_node->expiration_date = time(NULL) + DEPRECATED_PREKEY_EXPIRATION_TIME;
	buffer_init_with_pointer(
			deprecated_node->public_key,
			deprecated_node->public_key_storage,
			PUBLIC_KEY_SIZE,
			PUBLIC_KEY_SIZE);
	buffer_init_with_pointer(
			deprecated_node->private_key,
			deprecated_node->private_key_storage,
			PRIVATE_KEY_SIZE,
			PRIVATE_KEY_SIZE);

	//copy the node over
	status = buffer_clone(deprecated_node->public_key, store->prekeys[index].public_key);
	if (status != 0) {
		goto cleanup;
	}
	status = buffer_clone(deprecated_node->private_key, store->prekeys[index].private_key);
	if (status != 0) {
		goto cleanup;
	}

	//add it to the list of deprecated keys
	if ((store->oldest_deprecated_expiration_date == 0) || (store->oldest_deprecated_expiration_date > deprecated_node->expiration_date)) {
		store->oldest_deprecated_expiration_date = deprecated_node->expiration_date;
	}
	store->deprecated_prekeys = deprecated_node;

	//generate a new key
	status = crypto_box_keypair(
			store->prekeys[index].public_key->content,
			store->prekeys[index].public_key->content);
	if (status != 0) {
		goto cleanup;
	}
	store->prekeys[index].expiration_date = time(NULL) + PREKEY_EXPIRATION_TIME;

cleanup:
	if ((status != 0) && (deprecated_node != NULL)) {
		sodium_free(deprecated_node);
	}

	return status;
}

/*
 * Get a private prekey from it's public key. This will automatically
 * deprecate the requested prekey put it in the outdated key store and
 * generate a new one.
 */
return_status prekey_store_get_prekey(
		prekey_store * const store,
		const buffer_t * const public_key, //input
		buffer_t * const private_key) { //output

	return_status status = return_status_init();

	//check buffers sizes
	if ((store == NULL) || (public_key->content_length != PUBLIC_KEY_SIZE) || (private_key->buffer_length < PRIVATE_KEY_SIZE)) {
		throw(INVALID_INPUT, "Invalid input for prekey_store_get_prekey.");
	}

	prekey_store_node *found_prekey = NULL;

	//search for the prekey
	size_t i;
	for (i = 0; i < PREKEY_AMOUNT; i++) {
		if (buffer_compare(public_key, store->prekeys[i].public_key) == 0) {
			found_prekey = &(store->prekeys[i]);
			break;
		}
	}

	//if not found, search in the list of deprecated keys.
	bool deprecated = false;
	if (found_prekey == NULL) {
		deprecated = true;
		prekey_store_node *next = store->deprecated_prekeys;
		while (next != NULL) {
			if (buffer_compare(public_key, next->public_key) == 0) {
				found_prekey = next;
				break;
			}
			next = next->next;
		}
	}

	if (found_prekey == NULL) {
		private_key->content_length = 0;
		throw(NOT_FOUND, "No matching prekey found.");
	}

	//copy the private key
	if (buffer_clone(private_key, found_prekey->private_key) != 0) {
		private_key->content_length = 0;
		throw(BUFFER_ERROR, "Failed to copy private key.");
	}

	//if the key wasn't in the deprectated list already, deprecate it
	if (!deprecated) {
		if (deprecate(store, i) != 0) {
			throw(GENERIC_ERROR, "Failed to deprecate prekey.");
		}
	}

cleanup:
	return status;
}

/*
 * Generate a list containing all public prekeys.
 * (this list can then be stored on a public server).
 */
return_status prekey_store_list(
		prekey_store * const store,
		buffer_t * const list) { //output, PREKEY_AMOUNT * PUBLIC_KEY_SIZE
	return_status status = return_status_init();

	//check input
	if ((store == NULL) || (list->buffer_length < (PREKEY_AMOUNT * PUBLIC_KEY_SIZE))) {
		throw(INVALID_INPUT, "Invalid input to prekey_store_list.");
	}

	for (size_t i = 0; i < PREKEY_AMOUNT; i++) {
		int status_int = 0;
		status_int = buffer_copy(
				list,
				PUBLIC_KEY_SIZE * i,
				store->prekeys[i].public_key,
				0,
				PUBLIC_KEY_SIZE);
		if (status_int != 0) {
			list->content_length = 0;
			throw(BUFFER_ERROR, "Failed to copy public prekey.");
		}
	}

cleanup:
	return status;
}

/*
 * Automatically deprecate old keys and generate new ones
 * and throw away deprecated ones that are too old.
 */
return_status prekey_store_rotate(prekey_store * const store) {
	return_status status = return_status_init();

	if (store == NULL) {
		throw(INVALID_INPUT, "Invalid input to prekey_store_rotate: store is NULL.");
	}

	time_t current_time = time(NULL);

	//Is the expiration date too far into the future?
	if ((current_time + PREKEY_EXPIRATION_TIME) < store->oldest_expiration_date) {
		//TODO: Is this correct behavior?
		//Set the expiration date of everything to the current time + PREKEY_EXPIRATION_TIME
		for (size_t i = 0; i < PREKEY_AMOUNT; i++) {
			store->prekeys[i].expiration_date = current_time + PREKEY_EXPIRATION_TIME;
		}

		prekey_store_node *next = store->deprecated_prekeys;
		while (next != NULL) {
			next->expiration_date = current_time + DEPRECATED_PREKEY_EXPIRATION_TIME;
			next = next->next;
		}

		goto cleanup; //TODO Doesn't this skip the deprecated ones?
	}

	//At least one outdated prekey
	time_t new_oldest_expiration_date = current_time + PREKEY_EXPIRATION_TIME;
	if (store->oldest_expiration_date < current_time) {
		for (size_t i = 0; i < PREKEY_AMOUNT; i++) {
			if (store->prekeys[i].expiration_date < current_time) {
				if (deprecate(store, i) != 0) {
					throw(GENERIC_ERROR, "Failed to deprecate key.");
				}
			} else if (store->prekeys[i].expiration_date < new_oldest_expiration_date) {
				new_oldest_expiration_date = store->prekeys[i].expiration_date;
			}
		}
	}
	store->oldest_expiration_date = new_oldest_expiration_date;

	//Is the deprecated oldest expiration date too far into the future?
	if ((current_time + DEPRECATED_PREKEY_EXPIRATION_TIME) < store->oldest_deprecated_expiration_date) {
		//TODO: Is this correct behavior?
		//Set the expiration date of everything to the current time + DEPRECATED_PREKEY_EXPIRATION_TIME
		prekey_store_node *next = store->deprecated_prekeys;
		while (next != NULL) {
			next->expiration_date = current_time + DEPRECATED_PREKEY_EXPIRATION_TIME;
			next = next->next;
		}

		goto cleanup;
	}

	//At least one key to be removed
	time_t new_oldest_deprecated_expiration_date = current_time + DEPRECATED_PREKEY_EXPIRATION_TIME;
	if ((store->deprecated_prekeys != NULL) && (store->oldest_deprecated_expiration_date < current_time)) {
		prekey_store_node **last_pointer = &(store->deprecated_prekeys);
		prekey_store_node *next = store->deprecated_prekeys;
		while(next != NULL) {
			if (next->expiration_date < current_time) {
				*last_pointer = next->next;
				sodium_free(next);
				next = *last_pointer;
				continue;
			} else if (next->expiration_date < new_oldest_deprecated_expiration_date) {
				new_oldest_deprecated_expiration_date = next->expiration_date;
			}

			last_pointer = &(next->next);
			next = next->next;
		}
	}

cleanup:
	return status;
}

void prekey_store_destroy(prekey_store * const store) {
	if (store == NULL) {
		return;
	}

	while (store->deprecated_prekeys != NULL) {
		prekey_store_node *node = store->deprecated_prekeys;
		store->deprecated_prekeys = node->next;
		sodium_free(node);
	}
}

/*
 * Helper that serialises a prekey_store_node as json.
 */
mcJSON *prekey_store_node_json_export(const prekey_store_node * const node, mempool_t * const pool) {
	if (node == NULL) {
		return NULL;
	}

	mcJSON *json = mcJSON_CreateObject(pool);
	if (json == NULL) {
		return NULL;
	}

	//add expiration date
	mcJSON *expiration_date = mcJSON_CreateNumber((double)node->expiration_date, pool);
	if (expiration_date == NULL) {
		return NULL;
	}
	buffer_create_from_string(expiration_date_string, "expiration_date");
	mcJSON_AddItemToObject(json, expiration_date_string, expiration_date, pool);

	//add public key
	mcJSON *public_key_hex = mcJSON_CreateHexString(node->public_key, pool);
	if (public_key_hex == NULL) {
		return NULL;
	}
	buffer_create_from_string(public_key_string, "public_key");
	mcJSON_AddItemToObject(json, public_key_string, public_key_hex, pool);

	//add private key
	mcJSON *private_key_hex = mcJSON_CreateHexString(node->private_key, pool);
	if (private_key_hex == NULL) {
		return NULL;
	}
	buffer_create_from_string(private_key_string, "private_key");
	mcJSON_AddItemToObject(json, private_key_string, private_key_hex, pool);

	return json;
}

/*
 * Serialise a prekey store into JSON. It get's a mempool_t buffer and stores a tree of
 * mcJSON objects into the buffer starting at pool->position.
 *
 * Returns NULL in case of Failure.
 */
mcJSON *prekey_store_json_export(const prekey_store * const store, mempool_t * const pool) {
	mcJSON *json = mcJSON_CreateObject(pool);
	if (json == NULL) {
		return NULL;
	}

	//add oldest expiration_date
	mcJSON *oldest_expiration_date = mcJSON_CreateNumber((double)store->oldest_expiration_date, pool);
	if (oldest_expiration_date == NULL) {
		return NULL;
	}
	buffer_create_from_string(oldest_expiration_date_string, "oldest_expiration_date");
	mcJSON_AddItemToObject(json, oldest_expiration_date_string, oldest_expiration_date, pool);

	//add oldest deprecated expiration date
	mcJSON *oldest_deprecated_expiration_date = mcJSON_CreateNumber((double)store->oldest_deprecated_expiration_date, pool);
	if (oldest_deprecated_expiration_date == NULL) {
		return NULL;
	}
	buffer_create_from_string(oldest_deprecated_expiration_date_string, "oldest_deprecated_expiration_date");
	mcJSON_AddItemToObject(json, oldest_deprecated_expiration_date_string, oldest_deprecated_expiration_date, pool);

	//create the list of prekeys
	mcJSON *prekeys = mcJSON_CreateArray(pool);
	if (prekeys == NULL) {
		return NULL;
	}
	buffer_create_from_string(prekeys_string, "prekeys");
	mcJSON_AddItemToObject(json, prekeys_string, prekeys, pool);

	for (size_t i = 0; i < PREKEY_AMOUNT; i++) {
		mcJSON *node = prekey_store_node_json_export(&(store->prekeys[i]), pool);
		if (node == NULL) {
			return NULL;
		}
		mcJSON_AddItemToArray(prekeys, node, pool);
	}

	//create the list of deprecated prekeys
	mcJSON *deprecated_prekeys = mcJSON_CreateArray(pool);
	if (deprecated_prekeys == NULL) {
		return NULL;
	}
	buffer_create_from_string(deprecated_prekeys_string, "deprecated_prekeys");
	mcJSON_AddItemToObject(json, deprecated_prekeys_string, deprecated_prekeys, pool);

	prekey_store_node *next = store->deprecated_prekeys;
	while (next != NULL) {
		mcJSON *node = prekey_store_node_json_export(next, pool);
		if (node == NULL) {
			return NULL;
		}
		mcJSON_AddItemToArray(deprecated_prekeys, node, pool);

		next = next->next;
	}

	return json;
}

/*
 * Helper to import a prekey store node from json.
 */
int prekey_store_node_json_import(prekey_store_node * const node, const mcJSON * const json) {
	if ((json == NULL) || (node == NULL)) {
		return -1;
	}

	buffer_create_from_string(expiration_date_string, "expiration_date");
	mcJSON *expiration_date = mcJSON_GetObjectItem(json, expiration_date_string);
	if ((expiration_date == NULL) || (expiration_date->type != mcJSON_Number)) {
		return -1;
	}
	node->expiration_date = (time_t) expiration_date->valuedouble;

	buffer_create_from_string(public_key_string, "public_key");
	mcJSON *public_key = mcJSON_GetObjectItem(json, public_key_string);
	if ((public_key == NULL) || (public_key->type != mcJSON_String) || (public_key->valuestring->content_length != ((2 * PUBLIC_KEY_SIZE) + 1))) {
		return -1;
	}
	buffer_init_with_pointer(node->public_key, node->public_key_storage, PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	if (buffer_clone_from_hex(node->public_key, public_key->valuestring) != 0) {
		return -1;
	}

	buffer_create_from_string(private_key_string, "private_key");
	mcJSON *private_key = mcJSON_GetObjectItem(json, private_key_string);
	if ((private_key == NULL) || (private_key->type != mcJSON_String) || (private_key->valuestring->content_length != ((2 * PUBLIC_KEY_SIZE) + 1))) {
		return -1;
	}
	buffer_init_with_pointer(node->private_key, node->private_key_storage, PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
	if (buffer_clone_from_hex(node->private_key, private_key->valuestring) != 0) {
		return -1;
	}

	return 0;
}

/*
 * Deserialise a prekey store (import from JSON).
 */
prekey_store *prekey_store_json_import(const mcJSON * const json __attribute__((unused))) {
	prekey_store *store = sodium_malloc(sizeof(prekey_store));
	if (store == NULL) {
		return NULL;
	}

	store->deprecated_prekeys = NULL;

	int status = 0;

	//expiration dates
	buffer_create_from_string(oldest_expiration_date_string, "oldest_expiration_date");
	mcJSON *oldest_expiration_date = mcJSON_GetObjectItem(json, oldest_expiration_date_string);
	if ((oldest_expiration_date == NULL) || (oldest_expiration_date->type != mcJSON_Number)) {
		status = -1;
		goto cleanup;
	}
	store->oldest_expiration_date = (time_t)oldest_expiration_date->valuedouble;

	buffer_create_from_string(oldest_deprecated_expiration_date_string, "oldest_deprecated_expiration_date");
	mcJSON *oldest_deprecated_expiration_date = mcJSON_GetObjectItem(json, oldest_deprecated_expiration_date_string);
	if ((oldest_deprecated_expiration_date == NULL) || (oldest_deprecated_expiration_date->type != mcJSON_Number)) {
		status = -1;
		goto cleanup;
	}
	store->oldest_deprecated_expiration_date = (time_t)oldest_deprecated_expiration_date->valuedouble;

	//load all the regular prekeys
	buffer_create_from_string(prekeys_string, "prekeys");
	mcJSON *prekeys = mcJSON_GetObjectItem(json, prekeys_string);
	if ((prekeys == NULL) || (prekeys->type != mcJSON_Array) || (prekeys->length != PREKEY_AMOUNT)) {
		status = -1;
		goto cleanup;
	}
	mcJSON *node = prekeys->child;
	for (size_t i = 0; (i < PREKEY_AMOUNT) && (node != NULL); i++, node = node->next) {
		status = prekey_store_node_json_import(&(store->prekeys[i]), node);
		if (status != 0) {
			goto cleanup;
		}
	}

	//load all the deprecated prekeys
	buffer_create_from_string(deprecated_prekeys_string, "deprecated_prekeys");
	mcJSON *deprecated_prekeys = mcJSON_GetObjectItem(json, deprecated_prekeys_string);
	if ((deprecated_prekeys == NULL) || (deprecated_prekeys->type != mcJSON_Array)) {
		status = -1;
		goto cleanup;
	}
	if (deprecated_prekeys->length == 0) {
		node = NULL;
	} else {
		node = mcJSON_GetArrayItem(deprecated_prekeys, deprecated_prekeys->length - 1); //last element
	}
	for (size_t i = 0; (i < deprecated_prekeys->length) && (node != NULL); i++, node = node->prev) {
		prekey_store_node *prekey_node = sodium_malloc(sizeof(prekey_store_node));
		if (prekey_node == NULL) {
			status = -1;
			goto cleanup;
		}
		prekey_node->next = store->deprecated_prekeys;

		status = prekey_store_node_json_import(prekey_node, node);
		if (status != 0) {
			goto cleanup;
		}

		store->deprecated_prekeys = prekey_node;
	}

cleanup:
	if (status != 0) {
		prekey_store_destroy(store);
		return NULL;
	}

	return store;
}
