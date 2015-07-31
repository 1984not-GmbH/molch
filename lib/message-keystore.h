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

#ifndef MESSAGE_KEY_STORE_H
#define MESSAGE_KEY_STORE_H
//the message key store is currently a double linked list with all the message keys that haven't been
//used yet. (the keys are stored to still be able to decrypt old messages that weren't received)

//node of the linked list
typedef struct message_keystore_node message_keystore_node;
typedef struct message_keystore_node {
	message_keystore_node *previous;
	message_keystore_node *next;
	unsigned char message_key[crypto_secretbox_KEYBYTES];
	time_t timestamp;
} message_keystore_node;

//header of the key store
typedef struct message_keystore {
	unsigned int length;
	message_keystore_node *head;
	message_keystore_node *tail;
} message_keystore;

//initialise a new keystore
message_keystore message_keystore_init();

//add a message key to the keystore
//NOTE: The entire message key is copied, not only the pointer
int message_keystore_add(
		message_keystore *keystore,
		const unsigned char * const message_key);

//remove a message key from the keystore
void message_keystore_remove(message_keystore *keystore, message_keystore_node *node);

//clear the entire keystore
void message_keystore_clear(message_keystore *keystore);
#endif
