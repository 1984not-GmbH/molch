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
		const buffer_t * const message_key,
		const buffer_t * const header_key) {
	//check buffer sizes
	if ((message_key->content_length != crypto_secretbox_KEYBYTES)
			|| (header_key->content_length != crypto_aead_chacha20poly1305_KEYBYTES)) {
		return -6;
	}
	header_and_message_keystore_node *new_node = sodium_malloc(sizeof(header_and_message_keystore_node));
	if (new_node == NULL) { //couldn't allocate memory
		return -1;
	}

	//initialise buffers with storage arrays
	buffer_init_with_pointer(new_node->message_key, new_node->message_key_storage, crypto_secretbox_KEYBYTES, 0);
	buffer_init_with_pointer(new_node->header_key, new_node->header_key_storage, crypto_aead_chacha20poly1305_KEYBYTES, 0);

	int status;
	//set keys and timestamp
	new_node->timestamp = time(NULL);
	status = buffer_clone(new_node->message_key, message_key);
	if (status != 0) {
		sodium_free(new_node);
		return status;
	}
	status = buffer_clone(new_node->header_key, header_key);
	if (status != 0) {
		sodium_free(new_node);
		return status;
	}

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
	if (node == NULL) {
		return;
	}

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

	//free node and overwrite with zero
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
