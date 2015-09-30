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

#include "buffer.h"

#ifndef LIB_HEADER_AND_MESSAGE_KEY_STORE_H
#define LIB_HEADER_AND_MESSAGE_KEY_STORE_H
//the message key store is currently a double linked list with all the message keys that haven't been
//used yet. (the keys are stored to still be able to decrypt old messages that weren't received)

//node of the linked list
typedef struct header_and_message_keystore_node header_and_message_keystore_node;
struct header_and_message_keystore_node {
	header_and_message_keystore_node *previous;
	header_and_message_keystore_node *next;
	buffer_t message_key;
	unsigned char message_key_storage[crypto_secretbox_KEYBYTES];
	buffer_t header_key;
	unsigned char header_key_storage[crypto_aead_chacha20poly1305_KEYBYTES];
	time_t timestamp;
};

//header of the key store
typedef struct header_and_message_keystore {
	unsigned int length;
	header_and_message_keystore_node *head;
	header_and_message_keystore_node *tail;
} header_and_message_keystore;

//initialise a new keystore
header_and_message_keystore header_and_message_keystore_init();

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
#endif
