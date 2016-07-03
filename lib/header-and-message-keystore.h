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
#include <time.h>

#include "constants.h"
#include "return-status.h"
#include "../buffer/buffer.h"
#include "../mcJSON/mcJSON.h"

#ifndef LIB_HEADER_AND_MESSAGE_KEY_STORE_H
#define LIB_HEADER_AND_MESSAGE_KEY_STORE_H
//the message key store is currently a double linked list with all the message keys that haven't been
//used yet. (the keys are stored to still be able to decrypt old messages that weren't received)

//node of the linked list
typedef struct header_and_message_keystore_node header_and_message_keystore_node;
struct header_and_message_keystore_node {
	header_and_message_keystore_node *previous;
	header_and_message_keystore_node *next;
	buffer_t message_key[1];
	unsigned char message_key_storage[MESSAGE_KEY_SIZE];
	buffer_t header_key[1];
	unsigned char header_key_storage[HEADER_KEY_SIZE];
	time_t expiration_date;
};

//header of the key store
typedef struct header_and_message_keystore {
	size_t length;
	header_and_message_keystore_node *head;
	header_and_message_keystore_node *tail;
} header_and_message_keystore;

//initialise a new keystore
void header_and_message_keystore_init(header_and_message_keystore * const keystore);

//add a hader and message key to the keystore
//NOTE: The entire keys are copied, not only the pointer
return_status header_and_message_keystore_add(
		header_and_message_keystore *keystore,
		const buffer_t * const message_key,
		const buffer_t * const header_key) __attribute__((warn_unused_result));

//remove a message key from the keystore
void header_and_message_keystore_remove(header_and_message_keystore *keystore, header_and_message_keystore_node *node);

//clear the entire keystore
void header_and_message_keystore_clear(header_and_message_keystore *keystore);

/*
 * Serialise a header_and_message_keystore into JSON. It get's a mempool_t buffer and stores a
 * tree of mcJSON objects into the buffer starting at pool->position
 */
mcJSON *header_and_message_keystore_json_export(
		header_and_message_keystore * const keystore,
		mempool_t * const pool) __attribute__((warn_unused_result));

/*
 * Deserialise a heade_and_message_keystore (import from JSON).
 */
int header_and_message_keystore_json_import(
		const mcJSON * const json,
		header_and_message_keystore * const keystore) __attribute__((warn_unused_result));
#endif
