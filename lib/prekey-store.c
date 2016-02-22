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

#include <sodium.h>
#include <limits.h>
#include "prekey-store.h"

/*
 * Initialise a new keystore. Generates all the keys.
 */
prekey_store *prekey_store_create() {
	prekey_store *store = sodium_malloc(sizeof(prekey_store));
	if (store == NULL) {
		return NULL;
	}
	//set timestamp to the past --> rotate will create new keys
	store->oldest_timestamp = 0;
	store->oldest_deprecated_timestamp = 0;

	store->deprecated_prekeys = NULL;

	int status = 0;
	size_t i;
	for (i = 0; i < PREKEY_AMOUNT; i++) {
		store->prekeys[i].timestamp = time(NULL);
		if ((store->oldest_timestamp == 0) || (store->prekeys[i].timestamp < store->oldest_timestamp)) {
			store->oldest_timestamp = store->prekeys[i].timestamp;
		}

		store->prekeys[i].next = NULL;

		//initialize the key buffers
		buffer_init_with_pointer(
				store->prekeys[i].public_key,
				store->prekeys[i].public_key_storage,
				PUBLIC_KEY_SIZE,
				PUBLIC_KEY_SIZE);
		buffer_init_with_pointer(
				store->prekeys[i].private_key,
				store->prekeys[i].private_key_storage,
				PRIVATE_KEY_SIZE,
				PRIVATE_KEY_SIZE);

		//generate the keys
		status = crypto_box_keypair(
				store->prekeys[i].public_key->content,
				store->prekeys[i].private_key->content);
		if (status != 0) {
			goto cleanup;
		}
	}

cleanup:
	if (status != 0) {
		sodium_free(store);
		return NULL;
	}

	return store;
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
	deprecated_node->timestamp = time(NULL);
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
	if ((store->oldest_deprecated_timestamp == 0) || (store->oldest_deprecated_timestamp > deprecated_node->timestamp)) {
		store->oldest_deprecated_timestamp = deprecated_node->timestamp;
	}
	store->deprecated_prekeys = deprecated_node;

	//generate a new key
	status = crypto_box_keypair(
			store->prekeys[index].public_key->content,
			store->prekeys[index].public_key->content);
	if (status != 0) {
		goto cleanup;
	}
	store->prekeys[index].timestamp = time(NULL);

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
int prekey_store_get_prekey(
		prekey_store * const store,
		const buffer_t * const public_key, //input
		buffer_t * const private_key) { //output
	//check buffers sizes
	if ((store == NULL) || (public_key->content_length != PUBLIC_KEY_SIZE) || (private_key->buffer_length < PRIVATE_KEY_SIZE)) {
		return -1;
	}

	prekey_store_node *found_prekey = NULL;

	int status = 0;
	//search for the prekey
	size_t i;
	for (i = 0; i < PREKEY_AMOUNT; i++) {
		if (buffer_compare(public_key, store->prekeys[i].public_key) == 0) {
			found_prekey = &(store->prekeys[i]);
			break;
		}
	}

	//if not found, search in the list of deprecated keys.
	if (found_prekey == NULL) {
		i = SIZE_MAX;
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
		status = -1;
		goto cleanup;
	}

	//copy the private key
	status = buffer_clone(private_key, found_prekey->private_key);
	if (status != 0) {
		private_key->content_length = 0;
		goto cleanup;
	}

	//if the key wasn't in the deprectated list already, deprecate it
	if (i != SIZE_MAX) {
		status = deprecate(store, i);
		if (status != 0) {
			goto cleanup;
		}
	}

cleanup:
	return status;
}

/*
 * Generate a list containing all public prekeys.
 * (this list can then be stored on a public server).
 */
int prekey_store_list(
		prekey_store * const store,
		buffer_t * const list) { //output, PREKEY_AMOUNT * PUBLIC_KEY_SIZE
	//check input
	if ((store == NULL) || (list->buffer_length < (PREKEY_AMOUNT * PUBLIC_KEY_SIZE))) {
		return -1;
	}

	int status = 0;
	for (size_t i = 0; i < PREKEY_AMOUNT; i++) {
		status = buffer_copy(
				list,
				PUBLIC_KEY_SIZE * i,
				store->prekeys[i].public_key,
				0,
				PUBLIC_KEY_SIZE);
		if (status != 0) {
			list->content_length = 0;
			goto cleanup;
		}
	}

cleanup:
	return status;
}

/*
 * Automatically deprecate old keys and generate new ones
 * and throw away deprecated ones that are too old.
 */
int prekey_store_rotate(prekey_store * const store) {
	if (store == NULL) {
		return -1;
	}

	//time after which a prekey get's deprecated
	static const time_t deprecated_time = 3600 * 24 * 31; //one month
	//time after which a deprecated prekey gets removed
	static const time_t remove_time = 3600; //one hour

	time_t current_time = time(NULL);

	int status = 0;

	//Is the timestamp in the future?
	if (current_time < store->oldest_timestamp) {
		//TODO: Is this correct behavior?
		//Set the timestamp of everything to the current time
		for (size_t i = 0; i < PREKEY_AMOUNT; i++) {
			store->prekeys[i].timestamp = current_time;
		}

		prekey_store_node *next = store->deprecated_prekeys;
		while (next != NULL) {
			next->timestamp = current_time;
			next = next->next;
		}

		goto cleanup;
	}

	//At least one outdated prekey
	time_t new_oldest_timestamp = current_time;
	if ((store->oldest_timestamp + deprecated_time) < current_time) {
		for (size_t i = 0; i < PREKEY_AMOUNT; i++) {
			if ((store->prekeys[i].timestamp + deprecated_time) < current_time) {
				status = deprecate(store, i);
				if (status != 0) {
					goto cleanup;
				}
			} else if (store->prekeys[i].timestamp < new_oldest_timestamp) {
				new_oldest_timestamp = store->prekeys[i].timestamp;
			}
		}
	}
	store->oldest_timestamp = new_oldest_timestamp;

	//Is the deprecated oldest timestamp in the future?
	if (current_time < store->oldest_deprecated_timestamp) {
		//TODO: Is this correct behavior?
		//Set the timestamp of everything to the current time
		prekey_store_node *next = store->deprecated_prekeys;
		while (next != NULL) {
			next->timestamp = current_time;
			next = next->next;
		}

		goto cleanup;
	}

	//At least one key to be removed
	time_t new_oldest_deprecated_timestamp = current_time;
	if ((store->deprecated_prekeys != NULL) && (store->oldest_deprecated_timestamp + remove_time) < current_time) {
		prekey_store_node **last_pointer = &(store->deprecated_prekeys);
		prekey_store_node *next = store->deprecated_prekeys;
		while(next != NULL) {
			if ((next->timestamp + remove_time) < current_time) {
				*last_pointer = next->next;
				sodium_free(next);
				next = *last_pointer;
				continue;
			} else if (next->timestamp < new_oldest_deprecated_timestamp) {
				new_oldest_deprecated_timestamp = next->timestamp;
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
