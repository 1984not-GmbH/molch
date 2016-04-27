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
	if (*keys == NULL) {
		throw(ALLOCATION_FAILED, "Failed to allocate master keys.");
	}

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
		if (crypto_seeds == NULL) {
			throw(ALLOCATION_FAILED, "Failed to allocate cyrpto_seeds buffer.");
		}

		if (spiced_random(crypto_seeds, seed, crypto_seeds->buffer_length) != 0) {
			throw(GENERIC_ERROR, "Failed to create spiced random data.");
		}

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
	if (crypto_seeds != NULL) {
		buffer_destroy_with_custom_deallocator(crypto_seeds, sodium_free);
	}

	if (status.status != SUCCESS) {
		if (keys != NULL) {
			if (*keys != NULL) {
				sodium_free(keys);
				*keys = NULL;
			}
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
int master_keys_get_signing_key(
		master_keys * const keys,
		buffer_t * const public_signing_key) {
	//check input
	if ((keys == NULL) || (public_signing_key == NULL) || (public_signing_key->buffer_length < PUBLIC_MASTER_KEY_SIZE)) {
		return -6;
	}

	sodium_mprotect_readonly(keys);

	int status = 0;
	status = buffer_clone(public_signing_key, keys->public_signing_key);
	if (status != 0) {
		goto cleanup;
	}

cleanup:
	sodium_mprotect_noaccess(keys);

	return status;
}

/*
 * Get the public identity key.
 */
int master_keys_get_identity_key(
		master_keys * const keys,
		buffer_t * const public_identity_key) {
	//check input
	if ((keys == NULL) || (public_identity_key == NULL) || (public_identity_key->buffer_length < PUBLIC_KEY_SIZE)) {
		return -6;
	}

	sodium_mprotect_readonly(keys);

	int status = 0;
	status = buffer_clone(public_identity_key, keys->public_identity_key);
	if (status != 0) {
		goto cleanup;
	}

cleanup:
	sodium_mprotect_noaccess(keys);

	return status;
}

/*
 * Sign a piece of data. Returns the data and signature in one output buffer.
 */
int master_keys_sign(
		master_keys * const keys,
		const buffer_t * const data,
		buffer_t * const signed_data) { //output, length of data + SIGNATURE_SIZE
	if ((keys == NULL)
			|| (data == NULL)
			|| (signed_data == NULL)
			|| (signed_data->buffer_length < (data->content_length + SIGNATURE_SIZE))) {
		return -6;
	}

	sodium_mprotect_readonly(keys);

	int status = 0;
	unsigned long long signed_message_length;
	status = crypto_sign(
			signed_data->content,
			&signed_message_length,
			data->content,
			data->content_length,
			keys->private_signing_key->content);
	if (status != 0) {
		goto cleanup;
	}

	signed_data->content_length = (size_t) signed_message_length;

cleanup:
	sodium_mprotect_noaccess(keys);

	if (status != 0) {
		signed_data->content_length = 0;
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
	sodium_free(keys);

	return NULL;

cleanup:
	sodium_mprotect_noaccess(keys);

	return keys;
}
