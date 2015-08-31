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

#include <string.h>

#include "header-and-message-keystore.h"

//create new keystore
header_and_message_keystore header_and_message_keystore_init() {
	header_and_message_keystore keystore;
	keystore.length = 0;
	keystore.head = NULL;
	keystore.tail = NULL;
	return keystore;
}

//add a message key to the keystore
//NOTE: The entire keys are copied, not only the pointer
int header_and_message_keystore_add(
		header_and_message_keystore *keystore,
		const unsigned char * const message_key,
		const unsigned char * const header_key) {
	header_and_message_keystore_node *new_node = sodium_malloc(sizeof(header_and_message_keystore_node));
	if (new_node == NULL) { //couldn't allocate memory
		return -1;
	}

	//set keys and timestamp
	new_node->timestamp = time(NULL);
	memcpy(new_node->message_key, message_key, crypto_secretbox_KEYBYTES);
	memcpy(new_node->header_key, header_key, crypto_aead_chacha20poly1305_KEYBYTES);

	if (keystore->length == 0) { //first node in the list
		new_node->previous = NULL;
		new_node->next = NULL;
		keystore->head = new_node;
		keystore->tail = new_node;

		//update length
		keystore->length++;
		return 0;
	}

	//add the new node to the tail of the list
	keystore->tail->next = new_node;
	new_node->previous = keystore->tail;
	new_node->next = NULL;
	keystore->tail = new_node;

	//update length
	keystore->length++;

	return 0;
}

//remove a set of header and message keys from the keystore
void header_and_message_keystore_remove(header_and_message_keystore *keystore, header_and_message_keystore_node *node) {
	if (node->next != NULL) { //node is not the tail
		node->next->previous = node->previous;
	} else { //node ist the tail
		keystore->tail = node->previous;
	}
	if (node->previous != NULL) { //node ist not the head
		node->previous->next = node->next;
	} else { //node is the head
		keystore->head = node->next;
	}

	//overwrite keys in memory
	sodium_memzero(node->message_key, crypto_secretbox_KEYBYTES);
	sodium_memzero(node->header_key, crypto_aead_chacha20poly1305_KEYBYTES);

	sodium_free(node);

	//update length
	keystore->length--;
}

//clear the entire keystore
void header_and_message_keystore_clear(header_and_message_keystore *keystore){
	while (keystore->length > 0) {
		header_and_message_keystore_remove(keystore, keystore->head);
	}
}
