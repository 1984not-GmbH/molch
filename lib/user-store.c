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

#include "user-store.h"

//create a new user_store
user_store* user_store_create() {
	user_store *store = sodium_malloc(sizeof(user_store));
	if (store == NULL) { //couldn't allocate memory
		return NULL;
	}
	store->length = 0;
	store->head = NULL;
	store->tail = NULL;
	//TODO check the result?
	sodium_mprotect_noaccess(store);
	return store;
}

//destroy a user store
void user_store_destroy(user_store* store) {
	user_store_clear(store);
	sodium_free(store);
}

//add a new user to the user store
//NOTE: The entire buffers are copied, not only the pointer
int user_store_add(
		user_store *store,
		const buffer_t * const public_identity,
		const buffer_t * const private_identity,
		const buffer_t * const public_prekeys,
		const buffer_t * const private_prekeys) {
	//check size of the input buffers
	if ((public_identity->content_length != crypto_box_PUBLICKEYBYTES)
			|| (private_identity->content_length != crypto_box_SECRETKEYBYTES)
			|| (public_prekeys->content_length != PREKEY_AMOUNT * crypto_box_PUBLICKEYBYTES)
			|| (private_prekeys->content_length != PREKEY_AMOUNT * crypto_box_SECRETKEYBYTES)) {
		return -6;
	}

	user_store_node *new_node = sodium_malloc(sizeof(user_store_node));
	if (new_node == NULL) { //couldn't allocate memory
		return -1;
	}

	int status;
	//fill the content (copy keys)
	buffer_init_with_pointer(new_node->public_identity_key, new_node->public_identity_key_storage, crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	status = buffer_clone(new_node->public_identity_key, public_identity);
	if (status != 0) {
		sodium_free(new_node);
		return status;
	}
	buffer_init_with_pointer(new_node->private_identity_key, new_node->private_identity_key_storage, crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	status = buffer_clone(new_node->private_identity_key, private_identity);
	if (status != 0) {
		sodium_free(new_node);
		return status;
	}

	//prekeys
	//copy them
	status = buffer_clone_to_raw(new_node->public_prekey_storage, sizeof(new_node->private_prekey_storage), public_prekeys);
	if (status != 0) {
		sodium_free(new_node);
		return status;
	}
	status = buffer_clone_to_raw(new_node->private_prekey_storage, sizeof(new_node->private_prekey_storage), private_prekeys);
	if (status != 0) {
		sodium_free(new_node);
		return status;
	}
	//initialize the buffers that point to it
	for (size_t i = 0; i < PREKEY_AMOUNT; i++) {
		buffer_init_with_pointer(&(new_node->public_prekeys[i]), &(new_node->public_prekey_storage[i * crypto_box_PUBLICKEYBYTES]), crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
		buffer_init_with_pointer(&(new_node->private_prekeys[i]), &(new_node->private_prekey_storage[i * crypto_box_SECRETKEYBYTES]), crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	}

	sodium_mprotect_readwrite(store); //unlock memory
	if (store->length == 0) { //first node in the list
		new_node->previous = NULL;
		new_node->next = NULL;
		store->head = new_node;
		store->tail = new_node;

		//update length
		store->length++;

		sodium_mprotect_noaccess(store);

		return 0;
	}

	//add the new node to the tail of the list
	sodium_mprotect_readwrite(store->tail);
	store->tail->next = new_node;
	sodium_mprotect_noaccess(store->tail);
	new_node->previous = store->tail;
	new_node->next = NULL;
	store->tail = new_node;


	//update length
	store->length++;

	//lock memory after usage
	sodium_mprotect_noaccess(new_node);
	sodium_mprotect_noaccess(store);

	return 0;
}

/*
 * Find a user for a given public identity key.
 *
 * Returns NULL if no user was found.
 */
user_store_node* user_store_find_node(user_store * const store, const buffer_t * const public_identity) {
	if (public_identity->content_length != crypto_box_PUBLICKEYBYTES) {
		return NULL;
	}

	sodium_mprotect_readonly(store);

	user_store_node *current_node = store->head;

	//search for the matching public identity key
	while (current_node != NULL) {
		sodium_mprotect_readonly(current_node);
		if (buffer_compare(current_node->public_identity_key, public_identity) == 0) {
			//match found
			sodium_mprotect_noaccess(current_node);
			break;
		}
		user_store_node *temp = current_node;
		current_node = current_node->next; //go on through the list
		sodium_mprotect_noaccess(temp);
	}
	sodium_mprotect_noaccess(store);

	return current_node;
}

/*
 * List all of the users.
 *
 * Returns a buffer containing a list of all the public
 * identity keys of the user.
 */
buffer_t* user_store_list(user_store * const store) {
	sodium_mprotect_readonly(store);
	buffer_t *list = buffer_create_on_heap(crypto_box_PUBLICKEYBYTES * store->length, crypto_box_PUBLICKEYBYTES * store->length);

	user_store_node *current_node = store->head;
	for (unsigned int i = 0; (i < store->length) && (current_node != NULL); i++) {
		sodium_mprotect_readonly(current_node);
		int status = buffer_copy(
				list,
				i * crypto_box_PUBLICKEYBYTES,
				current_node->public_identity_key,
				0,
				current_node->public_identity_key->content_length);
		if (status != 0) { //copying went wrong
			sodium_mprotect_noaccess(current_node);
			sodium_mprotect_noaccess(store);
			buffer_destroy_from_heap(list);

			return buffer_create_on_heap(0, 0);
		}
		user_store_node *next_node = current_node->next;
		sodium_mprotect_noaccess(current_node);
		current_node = next_node;
	}
	sodium_mprotect_noaccess(store);

	return list;
}

/*
 * Remove a user from the user store.
 *
 * The user is identified by it's public identity key.
 */
void user_store_remove_by_key(user_store * const store, const buffer_t * const public_identity) {
	user_store_node *node = user_store_find_node(store, public_identity);

	if (node == NULL) {
		return;
	}

	user_store_remove(store, node);
}

//remove a user form the user store
void user_store_remove(user_store *store, user_store_node *node) {
	if (node == NULL) {
		return;
	}

	sodium_mprotect_readwrite(store);
	sodium_mprotect_readonly(node);

	if (node->next != NULL) { //node is not the tail
		sodium_mprotect_readwrite(node->next);
		node->next->previous = node->previous;
		sodium_mprotect_noaccess(node->next);
	} else { //node ist the tail
		store->tail = node->previous;
	}
	if (node->previous != NULL) { //node ist not the head
		sodium_mprotect_readwrite(node->previous);
		node->previous->next = node->next;
		sodium_mprotect_noaccess(node->previous);
	} else { //node is the head
		store->head = node->next;
	}

	sodium_free(node);

	//update length
	store->length--;
	sodium_mprotect_noaccess(store);
}

//clear the entire user store
void user_store_clear(user_store *store){
	sodium_mprotect_readonly(store);
	while (store->length > 0) {
		user_store_remove(store, store->head);
		sodium_mprotect_readonly(store); //necessary because user_store_remove resets this
	}

	sodium_mprotect_noaccess(store);
}
