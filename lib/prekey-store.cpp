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

#include <sodium.h>
#include <algorithm>
#include <climits>

#include "prekey-store.h"
#include "common.h"

static const time_t PREKEY_EXPIRATION_TIME = 3600 * 24 * 31; //one month
static const time_t DEPRECATED_PREKEY_EXPIRATION_TIME = 3600; //one hour

static void node_init(prekey_store_node * const node) {
	if (node == nullptr) {
		return;
	}

	node->private_key->init_with_pointer(node->private_key_storage, PRIVATE_KEY_SIZE, 0);
	node->public_key->init_with_pointer(node->public_key_storage, PUBLIC_KEY_SIZE, 0);
	node->next = nullptr;
	node->expiration_date = 0;
}


/*
 * Initialise a new keystore. Generates all the keys.
 */
return_status prekey_store_create(prekey_store ** const store) {
	return_status status = return_status_init();

	if (store == nullptr) {
		THROW(INVALID_INPUT, "Invalid input to prekey_store_create.");
	}

	*store = (prekey_store*)sodium_malloc(sizeof(prekey_store));
	THROW_on_failed_alloc(*store);

	//set expiration date to the past --> rotate will create new keys
	(*store)->oldest_expiration_date = 0;
	(*store)->oldest_deprecated_expiration_date = 0;

	(*store)->deprecated_prekeys = nullptr;

	for (size_t i = 0; i < PREKEY_AMOUNT; i++) {
		node_init(&((*store)->prekeys[i]));

		(*store)->prekeys[i].expiration_date = time(nullptr) + PREKEY_EXPIRATION_TIME;
		if (((*store)->oldest_expiration_date == 0) || ((*store)->prekeys[i].expiration_date < (*store)->oldest_expiration_date)) {
			(*store)->oldest_expiration_date = (*store)->prekeys[i].expiration_date;
		}

		//generate the keys
		int status_int = 0;
		status_int = crypto_box_keypair(
				(*store)->prekeys[i].public_key->content,
				(*store)->prekeys[i].private_key->content);
		if (status_int != 0) {
			THROW(KEYGENERATION_FAILED, "Failed to generate prekey pair.");
		}

		//set the key sizes
		(*store)->prekeys[i].public_key->content_length = PUBLIC_KEY_SIZE;
		(*store)->prekeys[i].private_key->content_length = PRIVATE_KEY_SIZE;
	}

cleanup:
	on_error {
		if (store != nullptr) {
				sodium_free_and_null_if_valid(*store);
		}
	}

	return status;
}

static void node_add(prekey_store * const store, prekey_store_node * const node) {
	if ((node == nullptr) || (store == nullptr)) {
		return;
	}

	node->next = store->deprecated_prekeys;
	store->deprecated_prekeys = node;
}

/*
 * Helper that puts a prekey pair in the deprecated list and generates a new one.
 */
static int deprecate(prekey_store * const store, size_t index) {
	int status = 0;
	//create a new node
	prekey_store_node *deprecated_node = (prekey_store_node*)sodium_malloc(sizeof(prekey_store_node));
	if (deprecated_node == nullptr) {
		status = -1;
		goto cleanup;
	}

	//initialise the deprecated node
	node_init(deprecated_node);
	deprecated_node->expiration_date = time(nullptr) + DEPRECATED_PREKEY_EXPIRATION_TIME;

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
	node_add(store, deprecated_node);

	//generate a new key
	status = crypto_box_keypair(
			store->prekeys[index].public_key->content,
			store->prekeys[index].public_key->content);
	if (status != 0) {
		goto cleanup;
	}
	store->prekeys[index].expiration_date = time(nullptr) + PREKEY_EXPIRATION_TIME;

cleanup:
	if (status != 0) {
		sodium_free_and_null_if_valid(deprecated_node);
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
		Buffer * const public_key, //input
		Buffer * const private_key) { //output

	return_status status = return_status_init();

	prekey_store_node *found_prekey = nullptr;
	bool deprecated = false;

	//check buffers sizes
	if ((store == nullptr) || (public_key->content_length != PUBLIC_KEY_SIZE) || (private_key->getBufferLength() < PRIVATE_KEY_SIZE)) {
		THROW(INVALID_INPUT, "Invalid input for prekey_store_get_prekey.");
	}

	//search for the prekey
	size_t i;
	for (i = 0; i < PREKEY_AMOUNT; i++) {
		if (buffer_compare(public_key, store->prekeys[i].public_key) == 0) {
			found_prekey = &(store->prekeys[i]);
			break;
		}
	}

	//if not found, search in the list of deprecated keys.
	if (found_prekey == nullptr) {
		deprecated = true;
		prekey_store_node *next = store->deprecated_prekeys;
		while (next != nullptr) {
			if (buffer_compare(public_key, next->public_key) == 0) {
				found_prekey = next;
				break;
			}
			next = next->next;
		}
	}

	if (found_prekey == nullptr) {
		private_key->content_length = 0;
		THROW(NOT_FOUND, "No matching prekey found.");
	}

	//copy the private key
	if (buffer_clone(private_key, found_prekey->private_key) != 0) {
		private_key->content_length = 0;
		THROW(BUFFER_ERROR, "Failed to copy private key.");
	}

	//if the key wasn't in the deprectated list already, deprecate it
	if (!deprecated) {
		if (deprecate(store, i) != 0) {
			THROW(GENERIC_ERROR, "Failed to deprecate prekey.");
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
		Buffer * const list) { //output, PREKEY_AMOUNT * PUBLIC_KEY_SIZE
	return_status status = return_status_init();

	//check input
	if ((store == nullptr) || (list->getBufferLength() < (PREKEY_AMOUNT * PUBLIC_KEY_SIZE))) {
		THROW(INVALID_INPUT, "Invalid input to prekey_store_list.");
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
			THROW(BUFFER_ERROR, "Failed to copy public prekey.");
		}
	}

cleanup:
	return status;
}

/*
 * Automatically deprecate old keys and generate new ones
 * and THROW away deprecated ones that are too old.
 */
return_status prekey_store_rotate(prekey_store * const store) {
	return_status status = return_status_init();

	time_t current_time = time(nullptr);

	if (store == nullptr) {
		THROW(INVALID_INPUT, "Invalid input to prekey_store_rotate: store is nullptr.");
	}

	//Is the expiration date too far into the future?
	if ((current_time + PREKEY_EXPIRATION_TIME) < store->oldest_expiration_date) {
		//TODO: Is this correct behavior?
		//Set the expiration date of everything to the current time + PREKEY_EXPIRATION_TIME
		for (size_t i = 0; i < PREKEY_AMOUNT; i++) {
			store->prekeys[i].expiration_date = current_time + PREKEY_EXPIRATION_TIME;
		}

		prekey_store_node *next = store->deprecated_prekeys;
		while (next != nullptr) {
			next->expiration_date = current_time + DEPRECATED_PREKEY_EXPIRATION_TIME;
			next = next->next;
		}

		goto cleanup; //TODO Doesn't this skip the deprecated ones?
	}

	//At least one outdated prekey
	{
		time_t new_oldest_expiration_date = current_time + PREKEY_EXPIRATION_TIME;
		if (store->oldest_expiration_date < current_time) {
			for (size_t i = 0; i < PREKEY_AMOUNT; i++) {
				if (store->prekeys[i].expiration_date < current_time) {
					if (deprecate(store, i) != 0) {
						THROW(GENERIC_ERROR, "Failed to deprecate key.");
					}
				} else if (store->prekeys[i].expiration_date < new_oldest_expiration_date) {
					new_oldest_expiration_date = store->prekeys[i].expiration_date;
				}
			}
		}
		store->oldest_expiration_date = new_oldest_expiration_date;
	}

	//Is the deprecated oldest expiration date too far into the future?
	if ((current_time + DEPRECATED_PREKEY_EXPIRATION_TIME) < store->oldest_deprecated_expiration_date) {
		//TODO: Is this correct behavior?
		//Set the expiration date of everything to the current time + DEPRECATED_PREKEY_EXPIRATION_TIME
		prekey_store_node *next = store->deprecated_prekeys;
		while (next != nullptr) {
			next->expiration_date = current_time + DEPRECATED_PREKEY_EXPIRATION_TIME;
			next = next->next;
		}

		goto cleanup;
	}

	//At least one key to be removed
	{
		time_t new_oldest_deprecated_expiration_date = current_time + DEPRECATED_PREKEY_EXPIRATION_TIME;
		if ((store->deprecated_prekeys != nullptr) && (store->oldest_deprecated_expiration_date < current_time)) {
			prekey_store_node **last_pointer = &(store->deprecated_prekeys);
			prekey_store_node *next = store->deprecated_prekeys;
			while(next != nullptr) {
				if (next->expiration_date < current_time) {
					*last_pointer = next->next;
					sodium_free_and_null_if_valid(next);
					next = *last_pointer;
					continue;
				} else if (next->expiration_date < new_oldest_deprecated_expiration_date) {
					new_oldest_deprecated_expiration_date = next->expiration_date;
				}

				last_pointer = &(next->next);
				next = next->next;
			}
		}
	}

cleanup:
	return status;
}

void prekey_store_destroy(prekey_store * const store) {
	if (store == nullptr) {
		return;
	}

	while (store->deprecated_prekeys != nullptr) {
		prekey_store_node *node = store->deprecated_prekeys;
		store->deprecated_prekeys = node->next;
		sodium_free_and_null_if_valid(node);
	}
}

/*!
 * Calculate the number of deprecated prekeys
 * \param store Prekey store in which to count.
 * \return Number of deprecated prekeys.
 */
static size_t count_deprecated_prekeys(prekey_store * const store) {
	size_t length = 0;
	for (prekey_store_node *node = store->deprecated_prekeys; node != nullptr; node = node->next, length++) {}

	return length;
}

return_status prekey_store_export_key(prekey_store_node* node, Prekey ** const keypair) __attribute__((warn_unused_result));
return_status prekey_store_export_key(prekey_store_node* node, Prekey ** const keypair) {
	return_status status = return_status_init();

	Key *private_prekey = nullptr;
	Key *public_prekey = nullptr;

	//check input
	if ((node == nullptr) || (keypair == nullptr)) {
		THROW(INVALID_INPUT, "Invalid input to prekey_store_export_key.");
	}

	//allocate and init the prekey protobuf struct
	*keypair = (Prekey*)zeroed_malloc(sizeof(Prekey));
	THROW_on_failed_alloc(*keypair);

	prekey__init(*keypair);

	//allocate and init the key structs
	private_prekey = (Key*)zeroed_malloc(sizeof(Key));
	THROW_on_failed_alloc(private_prekey);
	key__init(private_prekey);
	public_prekey = (Key*)zeroed_malloc(sizeof(Key));
	THROW_on_failed_alloc(public_prekey);
	key__init(public_prekey);

	//create the key buffers
	private_prekey->key.data = (unsigned char*)zeroed_malloc(PRIVATE_KEY_SIZE);
	THROW_on_failed_alloc(private_prekey->key.data);
	private_prekey->key.len = PRIVATE_KEY_SIZE;

	public_prekey->key.data = (unsigned char*)zeroed_malloc(PUBLIC_KEY_SIZE);
	THROW_on_failed_alloc(private_prekey->key.data);
	public_prekey->key.len = PUBLIC_KEY_SIZE;

	//fill the buffers
	if (buffer_clone_to_raw(private_prekey->key.data, private_prekey->key.len, (Buffer*)node->private_key) != 0) {
		THROW(BUFFER_ERROR, "Failed to clone private prekey.");
	}
	if (buffer_clone_to_raw(public_prekey->key.data, public_prekey->key.len, (Buffer*)node->public_key) != 0) {
		THROW(BUFFER_ERROR, "Failed to clone public prekey.");
	}

	//set the expiration date
	(*keypair)->has_expiration_time = true;
	(*keypair)->expiration_time = (uint64_t)node->expiration_date;

	//set the keys
	(*keypair)->public_key = public_prekey;
	public_prekey = nullptr;
	(*keypair)->private_key = private_prekey;
	private_prekey = nullptr;

cleanup:
	on_error {
		if (keypair != nullptr) {
			prekey__free_unpacked(*keypair, &protobuf_c_allocators);
			zeroed_free_and_null_if_valid(*keypair);
		}

		zeroed_free_and_null_if_valid(private_prekey);
		zeroed_free_and_null_if_valid(public_prekey);
	}

	return status;
}

return_status prekey_store_export(
		prekey_store * const store,
		Prekey *** const keypairs,
		size_t * const keypairs_length,
		Prekey *** const deprecated_keypairs,
		size_t * const deprecated_keypairs_length) {
	return_status status = return_status_init();

	size_t deprecated_prekey_count = 0;

	//check input
	if ((store == nullptr) || (keypairs == nullptr) || (deprecated_keypairs == nullptr)) {
		THROW(INVALID_INPUT, "Invalid input to prekey_store_export.");
	}

	//allocate the prekey array
	*keypairs = (Prekey**)zeroed_malloc(PREKEY_AMOUNT * sizeof(Prekey*));
	THROW_on_failed_alloc(*keypairs);

	//initialize pointers with zero
	std::fill(*keypairs, *keypairs + PREKEY_AMOUNT, nullptr);

	deprecated_prekey_count = count_deprecated_prekeys(store);
	if (deprecated_prekey_count > 0) {
		//allocate and init the deprecated prekey array
		*deprecated_keypairs = (Prekey**)zeroed_malloc(deprecated_prekey_count * sizeof(Prekey*));
		THROW_on_failed_alloc(*deprecated_keypairs);
	} else {
		*deprecated_keypairs = nullptr;
	}

	//normal keys
	for (size_t i = 0; i < PREKEY_AMOUNT; i++) {
		status = prekey_store_export_key(&(store->prekeys[i]), &(*keypairs)[i]);
		THROW_on_error(EXPORT_ERROR, "Failed to export prekey pair.");
	}

	//deprecated keys
	{
		prekey_store_node *node = store->deprecated_prekeys;
		for (size_t i = 0; (i < deprecated_prekey_count) && (node != nullptr); i++, node = node->next) {
			status = prekey_store_export_key(node, &(*deprecated_keypairs)[i]);
			THROW_on_error(EXPORT_ERROR, "Failed to export deprecated prekey pair.");
		}
	}

	*keypairs_length = PREKEY_AMOUNT;
	*deprecated_keypairs_length = deprecated_prekey_count;

cleanup:
	on_error {
		if ((keypairs != nullptr) && (*keypairs != nullptr)) {
			for (size_t i = 0; i < PREKEY_AMOUNT; i++) {
				if ((*keypairs)[i] != nullptr) {
					prekey__free_unpacked((*keypairs)[i], &protobuf_c_allocators);
					(*keypairs)[i] = nullptr;
				}
			}

			zeroed_free_and_null_if_valid(*keypairs);
		}

		if ((deprecated_keypairs != nullptr) && (*deprecated_keypairs != nullptr)) {
			for (size_t i = 0; i < deprecated_prekey_count; i++) {
				if ((*deprecated_keypairs)[i] != nullptr) {
					prekey__free_unpacked((*deprecated_keypairs)[i], &protobuf_c_allocators);
					(*deprecated_keypairs)[i] = nullptr;
				}
			}

			zeroed_free_and_null_if_valid(*deprecated_keypairs);
		}

		if (keypairs_length != nullptr) {
			*keypairs_length = 0;
		}

		if (deprecated_keypairs_length != nullptr) {
			*deprecated_keypairs_length = 0;
		}
	}

	return status;
}

static return_status prekey_store_node_import(prekey_store_node * const node, const Prekey * const keypair) {
	return_status status = return_status_init();

	//check input
	if ((node == nullptr) || (keypair == nullptr)) {
		THROW(INVALID_INPUT, "Invalid input to prekey_store_node_import.");
	}

	node_init(node);

	//check if all necessary values are contained in the keypair
	if ((keypair->private_key  == nullptr)
			|| (keypair->private_key->key.len != PRIVATE_KEY_SIZE)
			|| !keypair->has_expiration_time) {
		THROW(PROTOBUF_MISSING_ERROR, "Protobuf is missing some data.");
	}

	//check if a public key has been stored, if yes, check the size
	if ((keypair->public_key != nullptr)
			&& (keypair->public_key->key.len != PUBLIC_KEY_SIZE)) {
		THROW(INCORRECT_BUFFER_SIZE, "Public key has an incorrect length.");
	}

	//copy the private key
	if (buffer_clone_from_raw(node->private_key, keypair->private_key->key.data, keypair->private_key->key.len) != 0) {
		THROW(BUFFER_ERROR, "Failed to import private key.");
	}

	//does the public key exist, if yes: copy, if not: create it from private key
	if (keypair->public_key != nullptr) {
		if (buffer_clone_from_raw(node->public_key, keypair->public_key->key.data, keypair->public_key->key.len) != 0) {
			THROW(BUFFER_ERROR, "Failed to import public key.");
		}
	} else {
		if (crypto_scalarmult_base(node->public_key->content, node->private_key->content) != 0) {
			THROW(KEYDERIVATION_FAILED, "Failed to derive public prekey from private one.");
		}
		node->public_key->content_length = PUBLIC_KEY_SIZE;
		node->private_key->content_length = PRIVATE_KEY_SIZE;
	}

	node->expiration_date = (time_t)keypair->expiration_time;

cleanup:
	on_error {
		if (node != nullptr) {
			node->public_key->content_length = 0;
			node->private_key->content_length = 0;
			node->expiration_date = 0;
		}
	}

	return status;
}

return_status prekey_store_import(
		prekey_store ** const store,
		Prekey ** const keypairs,
		const size_t keypairs_length,
		Prekey ** const deprecated_keypairs,
		const size_t deprecated_keypairs_length) {
	return_status status = return_status_init();

	prekey_store_node *deprecated_keypair = nullptr;

	//check input
	if ((store == nullptr) || (keypairs == nullptr)
			|| (keypairs_length != PREKEY_AMOUNT)
			|| ((deprecated_keypairs_length == 0) && (deprecated_keypairs != nullptr))
			|| ((deprecated_keypairs_length > 0) && (deprecated_keypairs == nullptr))) {
		THROW(INVALID_INPUT, "Invalid input to prekey_store_import");
	}

	*store = (prekey_store*)sodium_malloc(sizeof(prekey_store));
	THROW_on_failed_alloc(*store);

	//init the store
	(*store)->deprecated_prekeys = nullptr;
	(*store)->oldest_deprecated_expiration_date = 0;
	(*store)->oldest_expiration_date = 0;

	//copy the prekeys
	for (size_t i = 0; i < keypairs_length; i++) {
		status = prekey_store_node_import(&((*store)->prekeys[i]), keypairs[i]);
		THROW_on_error(IMPORT_ERROR, "Failed to import prekey.");

		//update expiration date
		if (((*store)->oldest_expiration_date == 0)
				|| ((*store)->prekeys[i].expiration_date < (*store)->oldest_expiration_date)) {
			(*store)->oldest_expiration_date = (*store)->prekeys[i].expiration_date;
		}
	}

	//add the deprecated prekeys
	for (size_t i = 1; i <= deprecated_keypairs_length; i++) {
		deprecated_keypair = (prekey_store_node*)sodium_malloc(sizeof(prekey_store_node));
		THROW_on_failed_alloc(deprecated_keypair);

		status = prekey_store_node_import(deprecated_keypair, deprecated_keypairs[deprecated_keypairs_length - i]);
		THROW_on_error(IMPORT_ERROR, "Failed to import deprecated prekey.");

		//update expiration date
		if (((*store)->oldest_deprecated_expiration_date == 0)
				|| (deprecated_keypair->expiration_date < (*store)->oldest_deprecated_expiration_date)) {
			(*store)->oldest_deprecated_expiration_date = deprecated_keypair->expiration_date;
		}

		node_add(*store, deprecated_keypair);
		deprecated_keypair = nullptr;
	}

cleanup:
	on_error {
		if ((store != nullptr) && (*store != nullptr)) {
			prekey_store_destroy(*store);
		}

		sodium_free_and_null_if_valid(deprecated_keypair);
	}

	return status;
}

