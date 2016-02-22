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

#include <time.h>

#include "constants.h"
#include "../buffer/buffer.h"
#include "../mcJSON/mcJSON.h"

#ifndef LIB_PREKEY_STORE
#define LIB_PREKEY_STORE

typedef struct prekey_store_node prekey_store_node;
struct prekey_store_node {
	prekey_store_node *next;
	buffer_t public_key[1];
	unsigned char public_key_storage[PUBLIC_KEY_SIZE];
	buffer_t private_key[1];
	unsigned char private_key_storage[PRIVATE_KEY_SIZE];
	time_t timestamp;
};

typedef struct prekey_store prekey_store;
struct prekey_store {
	time_t oldest_timestamp;
	prekey_store_node prekeys[PREKEY_AMOUNT];
	prekey_store_node *deprecated_prekeys;
	time_t oldest_deprecated_timestamp;
};

/*
 * Initialise a new keystore. Generates all the keys.
 */
prekey_store *prekey_store_create() __attribute__((warn_unused_result));

/*
 * Get a private prekey from it's public key. This will automatically
 * deprecate the requested prekey put it in the outdated key store and
 * generate a new one.
 */
int prekey_store_get_prekey(
		prekey_store * const store,
		const buffer_t * const public_key, //input
		buffer_t * const private_key) __attribute__((warn_unused_result)); //output

/*
 * Generate a list containing all public prekeys.
 * (this list can then be stored on a public server).
 */
int prekey_store_list(
		prekey_store * const store,
		buffer_t * const list) __attribute__((warn_unused_result)); //output, PREKEY_AMOUNT * PUBLIC_KEY_SIZE

/*
 * Automatically deprecate old keys and generate new ones
 * and throw away deprecated ones that are too old.
 */
int prekey_store_rotate(prekey_store * const store) __attribute__((warn_unused_result));

void prekey_store_destroy(prekey_store * const store);

/*
 * Serialise a prekey store into JSON. It get's a mempool_t buffer and stores a tree of
 * mcJSON objects into the buffer starting at pool->position.
 *
 * Returns NULL in case of Failure.
 */
mcJSON *prekey_store_json_export(const prekey_store * const store, mempool_t * const pool) __attribute__((warn_unused_result));
#endif
