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
master_keys *master_keys_create(
		const buffer_t * const seed,
		buffer_t * const public_signing_key, //output, optional, can be NULL
		buffer_t * const public_identity_key //output, optional, can be NULL
		) {
	master_keys *keys = sodium_malloc(sizeof(master_keys));
	if (keys == NULL) {
		return NULL;
	}

	//initialize the buffers
	buffer_init_with_pointer(keys->public_signing_key, keys->public_signing_key_storage, PUBLIC_MASTER_KEY_SIZE, PUBLIC_MASTER_KEY_SIZE);
	buffer_init_with_pointer(keys->private_signing_key, keys->private_signing_key_storage, PRIVATE_MASTER_KEY_SIZE, PRIVATE_MASTER_KEY_SIZE);
	buffer_init_with_pointer(keys->public_identity_key, keys->public_identity_key_storage, PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	buffer_init_with_pointer(keys->private_identity_key, keys->private_identity_key_storage, PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);

	//seeds
	buffer_t *crypto_seeds = NULL;

	int status = 0;

	if (seed != NULL) { //use external seed
		//create the seed buffer
		crypto_seeds = buffer_create_with_custom_allocator(
				crypto_sign_SEEDBYTES + crypto_box_SEEDBYTES,
				crypto_sign_SEEDBYTES + crypto_box_SEEDBYTES,
				sodium_malloc,
				sodium_free);
		if (crypto_seeds == NULL) {
			status = -1;
			goto cleanup;
		}

		status = spiced_random(crypto_seeds, seed, crypto_seeds->buffer_length);
		if (status != 0) {
			goto cleanup;
		}

		//generate the signing keypair
		status = crypto_sign_seed_keypair(
				keys->public_signing_key->content,
				keys->private_signing_key_storage,
				crypto_seeds->content);
		if (status != 0) {
			goto cleanup;
		}

		//generate the identity keypair
		status = crypto_box_seed_keypair(
				keys->public_identity_key->content,
				keys->private_identity_key->content,
				crypto_seeds->content + crypto_sign_SEEDBYTES);
		if (status != 0) {
			goto cleanup;
		}
	} else { //don't use external seed
		//generate the signing keypair
		status = crypto_sign_keypair(
				keys->public_signing_key->content,
				keys->private_signing_key->content);
		if (status != 0) {
			goto cleanup;
		}

		//generate the identity keypair
		status = crypto_box_keypair(
				keys->public_identity_key->content,
				keys->private_identity_key->content);
		if (status != 0) {
			goto cleanup;
		}
	}

	//copy the public keys if requested
	if (public_signing_key != NULL) {
		if (public_signing_key->buffer_length < PUBLIC_MASTER_KEY_SIZE) {
			public_signing_key->content_length = 0;
			status = -1;
			goto cleanup;
		}

		status = buffer_clone(public_signing_key, keys->public_signing_key);
		if (status != 0) {
			goto cleanup;
		}
	}
	if (public_identity_key != NULL) {
		if (public_identity_key->buffer_length < PUBLIC_KEY_SIZE) {
			public_identity_key->content_length = 0;
			status = -1;
			goto cleanup;
		}

		status = buffer_clone(public_identity_key, keys->public_identity_key);
		if (status != 0) {
			goto cleanup;
		}
	}

cleanup:
	if (crypto_seeds != NULL) {
		buffer_destroy_with_custom_deallocator(crypto_seeds, sodium_free);
	}

	if (status != 0) {
		sodium_free(keys);
		return NULL;
	}

	sodium_mprotect_noaccess(keys);
	return keys;
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
 * Serialise the master keys into JSON. It get's a mempool_t buffer and stores mcJSON
 * Objects into it starting at pool->position.
 */
mcJSON *master_keys_json_export(master_keys * const keys, mempool_t * const pool) __attribute__((warn_unused_result));

/*
 * Deserialize a set of master keys (import from JSON).
 */
master_keys *master_keys_json_import(const mcJSON * const json) __attribute__((warn_unused_result));
