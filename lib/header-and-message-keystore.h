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
#include <time.h>

#include "constants.h"
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
	time_t timestamp;
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
int header_and_message_keystore_add(
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
