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

#include <cstring>

#include "common.h"
#include "constants.h"
#include "header-and-message-keystore.h"
#include "zeroed_malloc.h"

extern "C" {
	#include <key.pb-c.h>
	#include <key_bundle.pb-c.h>
}

static const time_t EXPIRATION_TIME = 3600 * 24 * 31; //one month

//create new keystore
void header_and_message_keystore_init(header_and_message_keystore * const keystore) {
	keystore->length = 0;
	keystore->head = nullptr;
	keystore->tail = nullptr;
}

/*
 * create an empty header_and_message_keystore_node and set up all the pointers.
 */
static header_and_message_keystore_node *create_node(void) {
	header_and_message_keystore_node *node = (header_and_message_keystore_node*)sodium_malloc(sizeof(header_and_message_keystore_node));
	if (node == nullptr) {
		return nullptr;
	}

	//initialise buffers with storage arrays
	node->message_key->init_with_pointer(node->message_key_storage, MESSAGE_KEY_SIZE, 0);
	node->header_key->init_with_pointer(node->header_key_storage, HEADER_KEY_SIZE, 0);

	return node;
}

/*
 * add a new header_and_message_key_node to a keystore
 */
static void add_node(header_and_message_keystore * const keystore, header_and_message_keystore_node * const node) {
	if (node == nullptr) {
		return;
	}

	if (keystore->length == 0) { //first node in the list
		node->previous = nullptr;
		node->next = nullptr;
		keystore->head = node;
		keystore->tail = node;

		//update length
		keystore->length++;
		return;
	}

	//add the new node to the tail of the list
	keystore->tail->next = node;
	node->previous = keystore->tail;
	node->next = nullptr;
	keystore->tail = node;

	//update length
	keystore->length++;
}

return_status create_and_populate_node(
		header_and_message_keystore_node ** const new_node,
		const time_t expiration_date,
		Buffer * const header_key,
		Buffer * const message_key) __attribute__((warn_unused_result));
return_status create_and_populate_node(
		header_and_message_keystore_node ** const new_node,
		const time_t expiration_date,
		Buffer * const header_key,
		Buffer * const message_key) {
	return_status status = return_status_init();

	//check buffer sizes
	if ((message_key->content_length != MESSAGE_KEY_SIZE)
			|| (header_key->content_length != HEADER_KEY_SIZE)) {
		THROW(INVALID_INPUT, "Invalid input to populate_node.");
	}

	*new_node = create_node();
	THROW_on_failed_alloc(*new_node);

	//set keys and expiration date
	(*new_node)->expiration_date = expiration_date;
	{
		int status_int = buffer_clone((*new_node)->message_key, message_key);
		if (status_int != 0) {
			THROW(BUFFER_ERROR, "Failed to copy message key.");
		}
	}
	{
		int status_int = buffer_clone((*new_node)->header_key, header_key);
		if (status_int != 0) {
			THROW(BUFFER_ERROR, "Failed to copy header key.");
		}
	}

cleanup:
	on_error {
		if (new_node != nullptr) {
			sodium_free_and_null_if_valid(*new_node);
		}
	}

	return status;
}

//add a message key to the keystore
//NOTE: The entire keys are copied, not only the pointer
return_status header_and_message_keystore_add(
		header_and_message_keystore *keystore,
		Buffer * const message_key,
		Buffer * const header_key) {
	return_status status = return_status_init();

	header_and_message_keystore_node *new_node = nullptr;

	time_t expiration_date = time(nullptr) + EXPIRATION_TIME;

	status = create_and_populate_node(&new_node, expiration_date, header_key, message_key);
	THROW_on_error(INIT_ERROR, "Failed to populate node.")

	add_node(keystore, new_node);

cleanup:
	on_error {
		sodium_free_and_null_if_valid(new_node);
	}
	return status;
}

//remove a set of header and message keys from the keystore
void header_and_message_keystore_remove(header_and_message_keystore *keystore, header_and_message_keystore_node *node) {
	if (node == nullptr) {
		return;
	}

	if (node->next != nullptr) { //node is not the tail
		node->next->previous = node->previous;
	} else { //node ist the tail
		keystore->tail = node->previous;
	}
	if (node->previous != nullptr) { //node ist not the head
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

static return_status header_and_message_keystore_node_export(header_and_message_keystore_node * const node, KeyBundle ** const bundle) {
	return_status status = return_status_init();

	Key *header_key = nullptr;
	Key *message_key = nullptr;

	//check input
	if ((node == nullptr) || (bundle == nullptr)) {
		THROW(INVALID_INPUT, "Invalid input to header_and_message_keystore_node_export.");
	}

	//allocate the buffers
	//key bundle
	*bundle = (KeyBundle*)zeroed_malloc(sizeof(KeyBundle));
	THROW_on_failed_alloc(*bundle);
	key_bundle__init(*bundle);

	//header key
	header_key = (Key*)zeroed_malloc(sizeof(Key));
	THROW_on_failed_alloc(header_key);
	key__init(header_key);
	header_key->key.data = (unsigned char*)zeroed_malloc(HEADER_KEY_SIZE);
	THROW_on_failed_alloc(header_key->key.data);

	//message key
	message_key = (Key*)zeroed_malloc(sizeof(Key));
	THROW_on_failed_alloc(message_key);
	key__init(message_key);
	message_key->key.data = (unsigned char*)zeroed_malloc(MESSAGE_KEY_SIZE);
	THROW_on_failed_alloc(message_key->key.data);

	//backup header key
	int status_int;
	status_int = buffer_clone_to_raw(
		header_key->key.data,
		HEADER_KEY_SIZE,
		node->header_key);
	if (status_int != 0) {
		THROW(BUFFER_ERROR, "Failed to copy header_key to backup.");
	}
	header_key->key.len = node->header_key->content_length;

	//backup message key
	status_int = buffer_clone_to_raw(
		message_key->key.data,
		HEADER_KEY_SIZE,
		node->message_key);
	if (status_int != 0) {
		THROW(BUFFER_ERROR, "Failed to copy message_key to backup.");
	}
	message_key->key.len = node->message_key->content_length;

	//set expiration time
	(*bundle)->expiration_time = (uint64_t) node->expiration_date;
	(*bundle)->has_expiration_time = true;

	//fill key bundle
	(*bundle)->header_key = header_key;
	(*bundle)->message_key = message_key;

cleanup:
	on_error {
		if ((bundle != nullptr) && (*bundle != nullptr)) {
			key_bundle__free_unpacked(*bundle, &protobuf_c_allocators);
			*bundle = nullptr;
		} else {
			if (header_key != nullptr) {
				key__free_unpacked(header_key, &protobuf_c_allocators);
				header_key = nullptr;
			}

			if (message_key != nullptr) {
				key__free_unpacked(message_key, &protobuf_c_allocators);
				message_key = nullptr;
			}
		}
	}

	return status;
}

return_status header_and_message_keystore_export(
		const header_and_message_keystore * const store,
		KeyBundle *** const key_bundles,
		size_t * const bundle_size) {
	return_status status = return_status_init();

	//check input
	if ((store == nullptr) || (key_bundles == nullptr) || (bundle_size == nullptr)) {
		THROW(INVALID_INPUT, "Invalid input to header_and_message_keystore_export.");
	}

	if (store->length != 0) {
		*key_bundles = (KeyBundle**)zeroed_malloc(store->length * sizeof(KeyBundle));
		THROW_on_failed_alloc(*key_bundles);
		//initialize with nullptr pointers
		memset(*key_bundles, '\0', store->length * sizeof(KeyBundle));
	} else {
		*key_bundles = nullptr;
	}

	{
		size_t position;
		header_and_message_keystore_node *node = nullptr;
		for (position = 0, node = store->head;
				(position < store->length) && (node != nullptr);
				position++, node = node->next) {
			status = header_and_message_keystore_node_export(node, &(*key_bundles)[position]);
			THROW_on_error(EXPORT_ERROR, "Failed to export header and message keystore node.");
		}
	}

	*bundle_size = store->length;

cleanup:
	on_error {
		if ((key_bundles != nullptr) && (*key_bundles != nullptr) && (store != nullptr)) {
			for (size_t i = 0; i < store->length; i++) {
				if ((*key_bundles)[i] != nullptr) {
					key_bundle__free_unpacked((*key_bundles)[i], &protobuf_c_allocators);
					(*key_bundles)[i] = nullptr;
				}
			}

			zeroed_free_and_null_if_valid(*key_bundles);
		}

		if (bundle_size != nullptr) {
			*bundle_size = 0;
		}
	}

	return status;
}

return_status header_and_message_keystore_import(
		header_and_message_keystore * const store,
		KeyBundle ** const key_bundles,
		const size_t bundles_size) {
	return_status status =  return_status_init();

	header_and_message_keystore_node *current_node = nullptr;

	if ((store != nullptr) && (bundles_size == 0) && (key_bundles == nullptr)) {
		//valid empty keystore
		goto cleanup;
	}

	//check input
	if ((store == nullptr)
			|| ((bundles_size == 0) && (key_bundles != nullptr))
			|| ((bundles_size > 0) && (key_bundles == nullptr))) {
		THROW(INVALID_INPUT, "Invalid input to header_and_message_keystore_import.");
	}

	header_and_message_keystore_init(store);

	//add all the keys
	for (size_t i = 0; i < bundles_size; i++) {
		KeyBundle *current_key_bundle = key_bundles[i];

		if (!current_key_bundle->has_expiration_time) {
			THROW(PROTOBUF_MISSING_ERROR, "Key bundle has no expiration time.");
		}

		//create buffers that point to the data in the protobuf struct
		buffer_create_with_existing_array(header_key, current_key_bundle->header_key->key.data, current_key_bundle->message_key->key.len);
		buffer_create_with_existing_array(message_key, current_key_bundle->message_key->key.data, current_key_bundle->message_key->key.len);

		//create new node
		status = create_and_populate_node(&current_node, (time_t)current_key_bundle->expiration_time, header_key, message_key);
		THROW_on_error(CREATION_ERROR, "Failed to create header_and_message_keystore_node.");

		add_node(store, current_node);
		current_node = nullptr; //set to nullptr because we don't have the ownership anymore
	}

cleanup:
	on_error {
		if (store != nullptr) {
			header_and_message_keystore_clear(store);
		}

		if (current_node != nullptr) {
			sodium_free_and_null_if_valid(current_node);
		}
	}

	return status;
}

