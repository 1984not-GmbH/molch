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
		master_keys ** const keys, //output
		const buffer_t * const seed,
		buffer_t * const public_signing_key, //output, optional, can be NULL
		buffer_t * const public_identity_key //output, optional, can be NULL
		) {
	return_status status = return_status_init();


	//seeds
	buffer_t *crypto_seeds = NULL;

	if (keys == NULL) {
		throw(INVALID_INPUT, "Invalid input for master_keys_create.");
	}

	*keys = sodium_malloc(sizeof(master_keys));
	throw_on_failed_alloc(*keys);

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
		throw_on_failed_alloc(crypto_seeds);

		status = spiced_random(crypto_seeds, seed, crypto_seeds->buffer_length);
		throw_on_error(GENERIC_ERROR, "Failed to create spiced random data.");

		//generate the signing keypair
		int status_int = 0;
		status_int = crypto_sign_seed_keypair(
				(*keys)->public_signing_key->content,
				(*keys)->private_signing_key_storage,
				crypto_seeds->content);
		if (status_int != 0) {
			throw(KEYGENERATION_FAILED, "Failed to generate signing keypair.");
		}

		//generate the identity keypair
		status_int = crypto_box_seed_keypair(
				(*keys)->public_identity_key->content,
				(*keys)->private_identity_key->content,
				crypto_seeds->content + crypto_sign_SEEDBYTES);
		if (status_int != 0) {
			throw(KEYGENERATION_FAILED, "Failed to generate encryption keypair.");
		}
	} else { //don't use external seed
		//generate the signing keypair
		int status_int = 0;
		status_int = crypto_sign_keypair(
				(*keys)->public_signing_key->content,
				(*keys)->private_signing_key->content);
		if (status_int != 0) {
			throw(KEYGENERATION_FAILED, "Failed to generate signing keypair.");
		}

		//generate the identity keypair
		status_int = crypto_box_keypair(
				(*keys)->public_identity_key->content,
				(*keys)->private_identity_key->content);
		if (status_int != 0) {
			throw(KEYGENERATION_FAILED, "Failed to generate encryption keypair.");
		}
	}

	//copy the public keys if requested
	if (public_signing_key != NULL) {
		if (public_signing_key->buffer_length < PUBLIC_MASTER_KEY_SIZE) {
			public_signing_key->content_length = 0;
			throw(INCORRECT_BUFFER_SIZE, "Public master key buffer is too short.");
		}

		if (buffer_clone(public_signing_key, (*keys)->public_signing_key) != 0) {
			throw(BUFFER_ERROR, "Failed to copy public signing key.");
		}
	}
	if (public_identity_key != NULL) {
		if (public_identity_key->buffer_length < PUBLIC_KEY_SIZE) {
			public_identity_key->content_length = 0;
			throw(INCORRECT_BUFFER_SIZE, "Public encryption key buffer is too short.");
		}

		if (buffer_clone(public_identity_key, (*keys)->public_identity_key) != 0) {
			throw(BUFFER_ERROR, "Failed to copy public encryption key.");
		}
	}

cleanup:
	buffer_destroy_with_custom_deallocator_and_null_if_valid(crypto_seeds, sodium_free);

	on_error(
		if (keys != NULL) {
			sodium_free_and_null_if_valid(*keys);
		}

		return status;
	)

	if ((keys != NULL) && (*keys != NULL)) {
		sodium_mprotect_noaccess(*keys);
	}
	return status;
}

/*
 * Get the public signing key.
 */
return_status master_keys_get_signing_key(
		master_keys * const keys,
		buffer_t * const public_signing_key) {
	return_status status = return_status_init();

	//check input
	if ((keys == NULL) || (public_signing_key == NULL) || (public_signing_key->buffer_length < PUBLIC_MASTER_KEY_SIZE)) {
		throw(INVALID_INPUT, "Invalid input to master_keys_get_signing_key.");
	}

	sodium_mprotect_readonly(keys);

	if (buffer_clone(public_signing_key, keys->public_signing_key) != 0) {
		throw(BUFFER_ERROR, "Failed to copy public signing key.");
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
		master_keys * const keys,
		buffer_t * const public_identity_key) {
	return_status status = return_status_init();

	//check input
	if ((keys == NULL) || (public_identity_key == NULL) || (public_identity_key->buffer_length < PUBLIC_KEY_SIZE)) {
		throw(INVALID_INPUT, "Invalid input to master_keys_get_identity_key.");
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
		master_keys * const keys,
		const buffer_t * const data,
		buffer_t * const signed_data) { //output, length of data + SIGNATURE_SIZE
	return_status status = return_status_init();

	if ((keys == NULL)
			|| (data == NULL)
			|| (signed_data == NULL)
			|| (signed_data->buffer_length < (data->content_length + SIGNATURE_SIZE))) {
		throw(INVALID_INPUT, "Invalid input to master_keys_sign.");
	}

	sodium_mprotect_readonly(keys);

	int status_int = 0;
	unsigned long long signed_message_length;
	status_int = crypto_sign(
			signed_data->content,
			&signed_message_length,
			data->content,
			data->content_length,
			keys->private_signing_key->content);
	if (status_int != 0) {
		throw(SIGN_ERROR, "Failed to sign message.");
	}

	signed_data->content_length = (size_t) signed_message_length;

cleanup:
	if (keys != NULL) {
		sodium_mprotect_noaccess(keys);
	}

	on_error(
		if (signed_data != NULL) {
			signed_data->content_length = 0;
		}
	)

	return status;
}

return_status master_keys_export(
		master_keys * const keys,
		Key ** const public_signing_key,
		Key ** const private_signing_key,
		Key ** const public_identity_key,
		Key ** const private_identity_key) {
	return_status status = return_status_init();

	//check input
	if ((keys == NULL)
			|| (public_signing_key == NULL) || (private_signing_key == NULL)
			|| (public_identity_key == NULL) || (private_identity_key == NULL)) {
		throw(INVALID_INPUT, "Invalid input to keys_export");
	}

	//allocate the structs
	*public_signing_key = zeroed_malloc(sizeof(Key));
	throw_on_failed_alloc(*public_signing_key);
	key__init(*public_signing_key);
	*private_signing_key = zeroed_malloc(sizeof(Key));
	throw_on_failed_alloc(*private_signing_key);
	key__init(*private_signing_key);
	*public_identity_key = zeroed_malloc(sizeof(Key));
	throw_on_failed_alloc(*public_identity_key);
	key__init(*public_identity_key);
	*private_identity_key = zeroed_malloc(sizeof(Key));
	throw_on_failed_alloc(*private_identity_key);
	key__init(*private_identity_key);

	//allocate the key buffers
	(*public_signing_key)->key.data = zeroed_malloc(PUBLIC_MASTER_KEY_SIZE);
	throw_on_failed_alloc((*public_signing_key)->key.data);
	(*public_signing_key)->key.len = PUBLIC_MASTER_KEY_SIZE;
	(*private_signing_key)->key.data = zeroed_malloc(PRIVATE_MASTER_KEY_SIZE);
	throw_on_failed_alloc((*private_signing_key)->key.data);
	(*private_signing_key)->key.len = PRIVATE_MASTER_KEY_SIZE;
	(*public_identity_key)->key.data = zeroed_malloc(PUBLIC_KEY_SIZE);
	throw_on_failed_alloc((*public_identity_key)->key.data);
	(*public_identity_key)->key.len = PUBLIC_KEY_SIZE;
	(*private_identity_key)->key.data = zeroed_malloc(PUBLIC_KEY_SIZE);
	throw_on_failed_alloc((*private_identity_key)->key.data);
	(*private_identity_key)->key.len = PUBLIC_KEY_SIZE;

	//unlock the master keys
	sodium_mprotect_readonly(keys);

	//copy the keys
	if (buffer_clone_to_raw((*public_signing_key)->key.data, (*public_signing_key)->key.len, keys->public_signing_key) != 0) {
		throw(BUFFER_ERROR, "Failed to export public signing key.");
	}
	if (buffer_clone_to_raw((*private_signing_key)->key.data, (*private_signing_key)->key.len, keys->private_signing_key) != 0) {
		throw(BUFFER_ERROR, "Failed to export private signing key.");
	}
	if (buffer_clone_to_raw((*public_identity_key)->key.data, (*public_identity_key)->key.len, keys->public_identity_key) != 0) {
		throw(BUFFER_ERROR, "Failed to export public identity key.");
	}
	if (buffer_clone_to_raw((*private_identity_key)->key.data, (*private_identity_key)->key.len, keys->private_identity_key) != 0) {
		throw(BUFFER_ERROR, "Failed to export private identity key.");
	}

cleanup:
	on_error(
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

	)

	if (keys != NULL) {
		sodium_mprotect_noaccess(keys);
	}

	return status;
}

/*
 * Serialise the master keys into JSON. It get's a mempool_t buffer and stores mcJSON
 * Objects into it starting at pool->position.
 */
mcJSON *master_keys_json_export(master_keys * const keys, mempool_t * const pool) {
	if ((keys == NULL) || (pool == NULL)) {
		return NULL;
	}

	mcJSON *json = mcJSON_CreateObject(pool);
	if (json == NULL) {
		return NULL;
	}

	sodium_mprotect_readonly(keys);

	//public signing key
	buffer_create_from_string(public_signing_key_string, "public_signing_key");
	mcJSON *public_signing_key = mcJSON_CreateHexString(keys->public_signing_key, pool);
	if (public_signing_key == NULL) {
		goto fail;
	}
	mcJSON_AddItemToObject(json, public_signing_key_string, public_signing_key, pool);

	//private signing key
	buffer_create_from_string(private_signing_key_string, "private_signing_key");
	mcJSON *private_signing_key = mcJSON_CreateHexString(keys->private_signing_key, pool);
	if (private_signing_key == NULL) {
		goto fail;
	}
	mcJSON_AddItemToObject(json, private_signing_key_string, private_signing_key, pool);

	//public identity key
	buffer_create_from_string(public_identity_key_string, "public_identity_key");
	mcJSON *public_identity_key = mcJSON_CreateHexString(keys->public_identity_key, pool);
	if (public_identity_key == NULL) {
		goto fail;
	}
	mcJSON_AddItemToObject(json, public_identity_key_string, public_identity_key, pool);

	//private identity key
	buffer_create_from_string(private_identity_key_string, "private_identity_key");
	mcJSON *private_identity_key = mcJSON_CreateHexString(keys->private_identity_key, pool);
	if (private_identity_key == NULL) {
		goto fail;
	}
	mcJSON_AddItemToObject(json, private_identity_key_string, private_identity_key, pool);

	goto cleanup;

fail:
	sodium_mprotect_noaccess(keys);

	return NULL;

cleanup:
	sodium_mprotect_noaccess(keys);

	return json;
}

/*
 * Deserialize a set of master keys (import from JSON).
 */
master_keys *master_keys_json_import(const mcJSON * const json) {
	if ((json == NULL) || (json->type != mcJSON_Object)) {
		return NULL;
	}

	master_keys *keys = sodium_malloc(sizeof(master_keys));
	if (keys == NULL) {
		return NULL;
	}

	//the public signing key
	buffer_init_with_pointer(keys->public_signing_key, keys->public_signing_key_storage, PUBLIC_MASTER_KEY_SIZE, PUBLIC_MASTER_KEY_SIZE);
	buffer_create_from_string(public_signing_key_string, "public_signing_key");
	mcJSON *public_signing_key = mcJSON_GetObjectItem(json, public_signing_key_string);
	if ((public_signing_key == NULL) || (public_signing_key->type != mcJSON_String) || (public_signing_key->valuestring->content_length != (2 * PUBLIC_MASTER_KEY_SIZE + 1))) {
		goto fail;
	}
	if (buffer_clone_from_hex(keys->public_signing_key, public_signing_key->valuestring) != 0) {
		goto fail;
	}

	//the private signing key
	buffer_init_with_pointer(keys->private_signing_key, keys->private_signing_key_storage, PRIVATE_MASTER_KEY_SIZE, PRIVATE_MASTER_KEY_SIZE);
	buffer_create_from_string(private_signing_key_string, "private_signing_key");
	mcJSON *private_signing_key = mcJSON_GetObjectItem(json, private_signing_key_string);
	if ((private_signing_key == NULL) || (private_signing_key->type != mcJSON_String) || (private_signing_key->valuestring->content_length != (2 * PRIVATE_MASTER_KEY_SIZE + 1))) {
		goto fail;
	}
	if (buffer_clone_from_hex(keys->private_signing_key, private_signing_key->valuestring) != 0) {
		goto fail;
	}

	//the public identity key
	buffer_init_with_pointer(keys->public_identity_key, keys->public_identity_key_storage, PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	buffer_create_from_string(public_identity_key_string, "public_identity_key");
	mcJSON *public_identity_key = mcJSON_GetObjectItem(json, public_identity_key_string);
	if ((public_identity_key == NULL) || (public_identity_key->type != mcJSON_String) || (public_identity_key->valuestring->content_length != (2 * PUBLIC_KEY_SIZE + 1))) {
		goto fail;
	}
	if (buffer_clone_from_hex(keys->public_identity_key, public_identity_key->valuestring) != 0) {
		goto fail;
	}

	//the private identity key
	buffer_init_with_pointer(keys->private_identity_key, keys->private_identity_key_storage, PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
	buffer_create_from_string(private_identity_key_string, "private_identity_key");
	mcJSON *private_identity_key = mcJSON_GetObjectItem(json, private_identity_key_string);
	if ((private_identity_key == NULL) || (private_identity_key->type != mcJSON_String) || (private_identity_key->valuestring->content_length != (2 * PRIVATE_KEY_SIZE + 1))) {
		goto fail;
	}
	if (buffer_clone_from_hex(keys->private_identity_key, private_identity_key->valuestring) != 0) {
		goto fail;
	}

	goto cleanup;

fail:
	sodium_free_and_null_if_valid(keys);

	return NULL;

cleanup:
	sodium_mprotect_noaccess(keys);

	return keys;
}
