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

#include <time.h>

#include "constants.h"
#include "common.h"
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
	time_t expiration_date;
};

typedef struct prekey_store prekey_store;
struct prekey_store {
	time_t oldest_expiration_date;
	prekey_store_node prekeys[PREKEY_AMOUNT];
	prekey_store_node *deprecated_prekeys;
	time_t oldest_deprecated_expiration_date;
};

/*
 * Initialise a new keystore. Generates all the keys.
 */
return_status prekey_store_create(prekey_store ** const store) __attribute__((warn_unused_result));

/*
 * Get a private prekey from it's public key. This will automatically
 * deprecate the requested prekey put it in the outdated key store and
 * generate a new one.
 */
return_status prekey_store_get_prekey(
		prekey_store * const store,
		const buffer_t * const public_key, //input
		buffer_t * const private_key) __attribute__((warn_unused_result)); //output

/*
 * Generate a list containing all public prekeys.
 * (this list can then be stored on a public server).
 */
return_status prekey_store_list(
		prekey_store * const store,
		buffer_t * const list) __attribute__((warn_unused_result)); //output, PREKEY_AMOUNT * PUBLIC_KEY_SIZE

/*
 * Automatically deprecate old keys and generate new ones
 * and throw away deprecated ones that are too old.
 */
return_status prekey_store_rotate(prekey_store * const store) __attribute__((warn_unused_result));

void prekey_store_destroy(prekey_store * const store);

/*
 * Serialise a prekey store into JSON. It get's a mempool_t buffer and stores a tree of
 * mcJSON objects into the buffer starting at pool->position.
 *
 * Returns NULL in case of Failure.
 */
mcJSON *prekey_store_json_export(const prekey_store * const store, mempool_t * const pool) __attribute__((warn_unused_result));

/*
 * Deserialise a prekey store (import from JSON).
 */
prekey_store *prekey_store_json_import(const mcJSON * const json) __attribute__((warn_unused_result));
#endif
