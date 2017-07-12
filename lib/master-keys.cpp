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
#include "master-keys.h"
#include "spiced-random.h"

/*
 * Create a new set of master keys.
 *
 * Seed is optional, can be NULL. It can be of any length and doesn't
 * require to have high entropy. It will be used as entropy source
 * in addition to the OSs CPRNG.
 *
 * WARNING: Don't use Entropy from the OSs CPRNG as seed!
 */
return_status master_keys_create(
		master_keys_t ** const keys, //output
		const buffer_t * const seed,
		buffer_t * const public_signing_key, //output, optional, can be NULL
		buffer_t * const public_identity_key //output, optional, can be NULL
		) {
	return_status status = return_status_init();


	//seeds
	buffer_t *crypto_seeds = NULL;

	if (keys == NULL) {
		THROW(INVALID_INPUT, "Invalid input for master_keys_create.");
	}

	*keys = (master_keys_t*)sodium_malloc(sizeof(master_keys));
	THROW_on_failed_alloc(*keys);

	//initialize the buffers
	buffer_init_with_pointer((*keys)->public_signing_key, (*keys)->public_signing_key_storage, PUBLIC_MASTER_KEY_SIZE, PUBLIC_MASTER_KEY_SIZE);
	buffer_init_with_pointer((*keys)->private_signing_key, (*keys)->private_signing_key_storage, PRIVATE_MASTER_KEY_SIZE, PRIVATE_MASTER_KEY_SIZE);
	buffer_init_with_pointer((*keys)->public_identity_key, (*keys)->public_identity_key_storage, PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	buffer_init_with_pointer((*keys)->private_identity_key, (*keys)->private_identity_key_storage, PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);

	if (seed != NULL) { //use external seed
		//create the seed buffer
		crypto_seeds = buffer_create_with_custom_allocator(
				crypto_sign_SEEDBYTES + crypto_box_SEEDBYTES,
				crypto_sign_SEEDBYTES + crypto_box_SEEDBYTES,
				sodium_malloc,
				sodium_free);
		THROW_on_failed_alloc(crypto_seeds);

		status = spiced_random(crypto_seeds, seed, crypto_seeds->buffer_length);
		THROW_on_error(GENERIC_ERROR, "Failed to create spiced random data.");

		//generate the signing keypair
		int status_int = 0;
		status_int = crypto_sign_seed_keypair(
				(*keys)->public_signing_key->content,
				(*keys)->private_signing_key_storage,
				crypto_seeds->content);
		if (status_int != 0) {
			THROW(KEYGENERATION_FAILED, "Failed to generate signing keypair.");
		}

		//generate the identity keypair
		status_int = crypto_box_seed_keypair(
				(*keys)->public_identity_key->content,
				(*keys)->private_identity_key->content,
				crypto_seeds->content + crypto_sign_SEEDBYTES);
		if (status_int != 0) {
			THROW(KEYGENERATION_FAILED, "Failed to generate encryption keypair.");
		}
	} else { //don't use external seed
		//generate the signing keypair
		int status_int = 0;
		status_int = crypto_sign_keypair(
				(*keys)->public_signing_key->content,
				(*keys)->private_signing_key->content);
		if (status_int != 0) {
			THROW(KEYGENERATION_FAILED, "Failed to generate signing keypair.");
		}

		//generate the identity keypair
		status_int = crypto_box_keypair(
				(*keys)->public_identity_key->content,
				(*keys)->private_identity_key->content);
		if (status_int != 0) {
			THROW(KEYGENERATION_FAILED, "Failed to generate encryption keypair.");
		}
	}

	//copy the public keys if requested
	if (public_signing_key != NULL) {
		if (public_signing_key->buffer_length < PUBLIC_MASTER_KEY_SIZE) {
			public_signing_key->content_length = 0;
			THROW(INCORRECT_BUFFER_SIZE, "Public master key buffer is too short.");
		}

		if (buffer_clone(public_signing_key, (*keys)->public_signing_key) != 0) {
			THROW(BUFFER_ERROR, "Failed to copy public signing key.");
		}
	}
	if (public_identity_key != NULL) {
		if (public_identity_key->buffer_length < PUBLIC_KEY_SIZE) {
			public_identity_key->content_length = 0;
			THROW(INCORRECT_BUFFER_SIZE, "Public encryption key buffer is too short.");
		}

		if (buffer_clone(public_identity_key, (*keys)->public_identity_key) != 0) {
			THROW(BUFFER_ERROR, "Failed to copy public encryption key.");
		}
	}

cleanup:
	buffer_destroy_with_custom_deallocator_and_null_if_valid(crypto_seeds, sodium_free);

	on_error {
		if (keys != NULL) {
			sodium_free_and_null_if_valid(*keys);
		}

		return status;
	}

	if ((keys != NULL) && (*keys != NULL)) {
		sodium_mprotect_noaccess(*keys);
	}
	return status;
}

/*
 * Get the public signing key.
 */
return_status master_keys_get_signing_key(
		master_keys_t * const keys,
		buffer_t * const public_signing_key) {
	return_status status = return_status_init();

	//check input
	if ((keys == NULL) || (public_signing_key == NULL) || (public_signing_key->buffer_length < PUBLIC_MASTER_KEY_SIZE)) {
		THROW(INVALID_INPUT, "Invalid input to master_keys_get_signing_key.");
	}

	sodium_mprotect_readonly(keys);

	if (buffer_clone(public_signing_key, keys->public_signing_key) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy public signing key.");
	}

cleanup:
	if (keys != NULL) {
		sodium_mprotect_noaccess(keys);
	}

	return status;
}

/*
 * Get the public identity key.
 */
return_status master_keys_get_identity_key(
		master_keys_t * const keys,
		buffer_t * const public_identity_key) {
	return_status status = return_status_init();

	//check input
	if ((keys == NULL) || (public_identity_key == NULL) || (public_identity_key->buffer_length < PUBLIC_KEY_SIZE)) {
		THROW(INVALID_INPUT, "Invalid input to master_keys_get_identity_key.");
	}

	sodium_mprotect_readonly(keys);

	if (buffer_clone(public_identity_key, keys->public_identity_key) != 0) {
		goto cleanup;
	}

cleanup:
	if (keys != NULL) {
		sodium_mprotect_noaccess(keys);
	}

	return status;
}

/*
 * Sign a piece of data. Returns the data and signature in one output buffer.
 */
return_status master_keys_sign(
		master_keys_t * const keys,
		const buffer_t * const data,
		buffer_t * const signed_data) { //output, length of data + SIGNATURE_SIZE
	return_status status = return_status_init();

	if ((keys == NULL)
			|| (data == NULL)
			|| (signed_data == NULL)
			|| (signed_data->buffer_length < (data->content_length + SIGNATURE_SIZE))) {
		THROW(INVALID_INPUT, "Invalid input to master_keys_sign.");
	}

	sodium_mprotect_readonly(keys);

	{
		int status_int = 0;
		unsigned long long signed_message_length;
		status_int = crypto_sign(
				signed_data->content,
				&signed_message_length,
				data->content,
				data->content_length,
				keys->private_signing_key->content);
		if (status_int != 0) {
			THROW(SIGN_ERROR, "Failed to sign message.");
		}

		signed_data->content_length = (size_t) signed_message_length;
	}

cleanup:
	if (keys != NULL) {
		sodium_mprotect_noaccess(keys);
	}

	on_error {
		if (signed_data != NULL) {
			signed_data->content_length = 0;
		}
	}

	return status;
}

return_status master_keys_export(
		master_keys_t * const keys,
		Key ** const public_signing_key,
		Key ** const private_signing_key,
		Key ** const public_identity_key,
		Key ** const private_identity_key) {
	return_status status = return_status_init();

	//check input
	if ((keys == NULL)
			|| (public_signing_key == NULL) || (private_signing_key == NULL)
			|| (public_identity_key == NULL) || (private_identity_key == NULL)) {
		THROW(INVALID_INPUT, "Invalid input to keys_export");
	}

	//allocate the structs
	*public_signing_key = (Key*)zeroed_malloc(sizeof(Key));
	THROW_on_failed_alloc(*public_signing_key);
	key__init(*public_signing_key);
	*private_signing_key = (Key*)zeroed_malloc(sizeof(Key));
	THROW_on_failed_alloc(*private_signing_key);
	key__init(*private_signing_key);
	*public_identity_key = (Key*)zeroed_malloc(sizeof(Key));
	THROW_on_failed_alloc(*public_identity_key);
	key__init(*public_identity_key);
	*private_identity_key = (Key*)zeroed_malloc(sizeof(Key));
	THROW_on_failed_alloc(*private_identity_key);
	key__init(*private_identity_key);

	//allocate the key buffers
	(*public_signing_key)->key.data = (unsigned char*)zeroed_malloc(PUBLIC_MASTER_KEY_SIZE);
	THROW_on_failed_alloc((*public_signing_key)->key.data);
	(*public_signing_key)->key.len = PUBLIC_MASTER_KEY_SIZE;
	(*private_signing_key)->key.data = (unsigned char*)zeroed_malloc(PRIVATE_MASTER_KEY_SIZE);
	THROW_on_failed_alloc((*private_signing_key)->key.data);
	(*private_signing_key)->key.len = PRIVATE_MASTER_KEY_SIZE;
	(*public_identity_key)->key.data = (unsigned char*)zeroed_malloc(PUBLIC_KEY_SIZE);
	THROW_on_failed_alloc((*public_identity_key)->key.data);
	(*public_identity_key)->key.len = PUBLIC_KEY_SIZE;
	(*private_identity_key)->key.data = (unsigned char*)zeroed_malloc(PUBLIC_KEY_SIZE);
	THROW_on_failed_alloc((*private_identity_key)->key.data);
	(*private_identity_key)->key.len = PUBLIC_KEY_SIZE;

	//unlock the master keys
	sodium_mprotect_readonly(keys);

	//copy the keys
	if (buffer_clone_to_raw((*public_signing_key)->key.data, (*public_signing_key)->key.len, keys->public_signing_key) != 0) {
		THROW(BUFFER_ERROR, "Failed to export public signing key.");
	}
	if (buffer_clone_to_raw((*private_signing_key)->key.data, (*private_signing_key)->key.len, keys->private_signing_key) != 0) {
		THROW(BUFFER_ERROR, "Failed to export private signing key.");
	}
	if (buffer_clone_to_raw((*public_identity_key)->key.data, (*public_identity_key)->key.len, keys->public_identity_key) != 0) {
		THROW(BUFFER_ERROR, "Failed to export public identity key.");
	}
	if (buffer_clone_to_raw((*private_identity_key)->key.data, (*private_identity_key)->key.len, keys->private_identity_key) != 0) {
		THROW(BUFFER_ERROR, "Failed to export private identity key.");
	}

cleanup:
	on_error {
		if ((public_signing_key != NULL) && (*public_signing_key != NULL)) {
			key__free_unpacked(*public_signing_key, &protobuf_c_allocators);
			*public_signing_key = NULL;
		}

		if ((private_signing_key != NULL) && (*private_signing_key != NULL)) {
			key__free_unpacked(*private_signing_key, &protobuf_c_allocators);
			*private_signing_key = NULL;
		}

		if ((public_identity_key != NULL) && (*public_identity_key != NULL)) {
			key__free_unpacked(*public_identity_key, &protobuf_c_allocators);
			*public_identity_key = NULL;
		}

		if ((private_identity_key != NULL) && (*private_identity_key != NULL)) {
			key__free_unpacked(*private_identity_key, &protobuf_c_allocators);
			*private_identity_key = NULL;
		}

	}

	if (keys != NULL) {
		sodium_mprotect_noaccess(keys);
	}

	return status;
}

return_status master_keys_import(
		master_keys_t ** const keys,
		const Key * const public_signing_key,
		const Key * const private_signing_key,
		const Key * const public_identity_key,
		const Key * const private_identity_key) {
	return_status status = return_status_init();

	//check inputs
	if ((keys == NULL)
			|| (public_signing_key == NULL) || (private_signing_key == NULL)
			|| (public_identity_key == NULL) || (private_identity_key == NULL)) {
		THROW(INVALID_INPUT, "Invalid input to master_keys_import.");
	}

	*keys = (master_keys_t*)sodium_malloc(sizeof(master_keys_t));
	THROW_on_failed_alloc(*keys);

	//initialize the buffers
	buffer_init_with_pointer((*keys)->public_signing_key, (*keys)->public_signing_key_storage, PUBLIC_MASTER_KEY_SIZE, 0);
	buffer_init_with_pointer((*keys)->private_signing_key, (*keys)->private_signing_key_storage, PRIVATE_MASTER_KEY_SIZE, 0);
	buffer_init_with_pointer((*keys)->public_identity_key, (*keys)->public_identity_key_storage, PUBLIC_KEY_SIZE, 0);
	buffer_init_with_pointer((*keys)->private_identity_key, (*keys)->private_identity_key_storage, PRIVATE_KEY_SIZE, 0);

	//copy the keys
	if (buffer_clone_from_raw((*keys)->public_signing_key, public_signing_key->key.data, public_signing_key->key.len) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy public signing key.");
	}
	if (buffer_clone_from_raw((*keys)->private_signing_key, private_signing_key->key.data, private_signing_key->key.len) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy private signing key.");
	}
	if (buffer_clone_from_raw((*keys)->public_identity_key, public_identity_key->key.data, public_identity_key->key.len) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy public identity key.");
	}
	if (buffer_clone_from_raw((*keys)->private_identity_key, private_identity_key->key.data, private_identity_key->key.len) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy private identity key.");
	}

	sodium_mprotect_noaccess(*keys);

cleanup:
	on_error {
		if (keys != NULL) {
			sodium_free_and_null_if_valid(*keys);
		}
	}

	return status;
}

