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

#include "../buffer/buffer.h"

#ifndef LIB_USER_STORE_H
#define LIB_USER_STORE_H

#define PREKEY_AMOUNT 100

//The user store stores a linked list of all users identified by their private keys
//This linked list is supposed to be stored once in a global variable.

//node of the linked list
typedef struct user_store_node user_store_node;
struct user_store_node {
	user_store_node *previous;
	user_store_node *next;
	buffer_t public_identity_key;
	unsigned char public_identity_key_storage[crypto_box_PUBLICKEYBYTES];
	buffer_t private_identity_key;
	unsigned char private_identity_key_storage[crypto_box_SECRETKEYBYTES];
	//FIXME those prekey should be replaced by it's own prekey store in the future
	//(this allows still having old prekeys around)
	buffer_t public_prekeys;
	unsigned char public_prekey_storage[PREKEY_AMOUNT * crypto_box_PUBLICKEYBYTES];
	buffer_t private_prekeys;
	unsigned char private_prekey_storage[PREKEY_AMOUNT * crypto_box_SECRETKEYBYTES];
};

//header of the user store
typedef struct user_store {
	size_t length;
	user_store_node *head;
	user_store_node *tail;
} user_store;

//create a new user store
user_store* user_store_create() __attribute__((warn_unused_result));

//destroy a user store
void user_store_destroy(user_store * const store);

//add a new user to the user store
//NOTE: The entire buffers are copied, not only the pointers.
int user_store_add(
		user_store * const keystore,
		const buffer_t * const public_identity,
		const buffer_t * const private_identity,
		const buffer_t * const public_prekeys,
		const buffer_t * const private_prekeys) __attribute__((warn_unused_result));

/*
 * Find a user for a given public identity key.
 *
 * Returns NULL if no user was found.
 */
user_store_node* user_store_find_node(user_store * const store, const buffer_t * const public_identity) __attribute__((warn_unused_result));

/*
 * List all of the users.
 *
 * Returns a buffer containing a list of all the public
 * identity keys of the user.
 *
 * The buffer is heap allocated, so don't forget to free it!
 */
buffer_t* user_store_list(user_store * const store) __attribute__((warn_unused_result));

/*
 * Remove a user from the user store.
 *
 * The user is identified by it's public identity key.
 */
void user_store_remove_by_key(user_store * const store, const buffer_t * const public_identity);

//remove a user from the user store
void user_store_remove(user_store * const store, user_store_node *node);

//clear the entire user store
void user_store_clear(user_store *keystore);
#endif
