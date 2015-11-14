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

#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>
#include <assert.h>

#include "../../lib/user-store.h"
#include "../utils.h"
#include "../common.h"

int generate_prekeys(buffer_t * const private_prekeys, buffer_t * const public_prekeys) {
	if ((private_prekeys->buffer_length != (PREKEY_AMOUNT * crypto_box_SECRETKEYBYTES))
			|| (public_prekeys->buffer_length != (PREKEY_AMOUNT * crypto_box_PUBLICKEYBYTES))) {
		return -6;
	}

	private_prekeys->content_length = private_prekeys->buffer_length;
	public_prekeys->content_length = public_prekeys->buffer_length;

	int status;
	for (unsigned int i = 0; i < PREKEY_AMOUNT; i++) {
		status = crypto_box_keypair(
				public_prekeys->content + i * crypto_box_PUBLICKEYBYTES,
				private_prekeys->content + i * crypto_box_SECRETKEYBYTES);
		if (status != 0) {
			buffer_clear(public_prekeys);
			buffer_clear(private_prekeys);
			return status;
		}
	}
	return 0;
}


int main(void) {
	if (sodium_init() == -1) {
		return -1;
	}

	//create a user_store
	user_store *store = user_store_create();

	//check the content
	buffer_t *list = user_store_list(store);
	if (list->content_length != 0) {
		fprintf(stderr, "ERROR: List of users is not empty.\n");
		user_store_destroy(store);
		buffer_destroy_from_heap(list);

		return EXIT_FAILURE;
	}
	buffer_destroy_from_heap(list);

	int status;
	//create three users with prekeys and identity keys
	//first alice
	//alice identity key
	buffer_t *alice_private_identity = buffer_create(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	buffer_t *alice_public_identity = buffer_create(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	status = generate_and_print_keypair(
			alice_public_identity->content,
			alice_private_identity->content,
			"Alice",
			"identity");
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to generate Alice's identity keypair.\n");
		buffer_clear(alice_private_identity);
		return status;
	}

	//alice prekeys
	buffer_t *alice_private_prekeys = buffer_create(PREKEY_AMOUNT * crypto_box_SECRETKEYBYTES, PREKEY_AMOUNT * crypto_box_SECRETKEYBYTES);
	buffer_t *alice_public_prekeys = buffer_create(PREKEY_AMOUNT * crypto_box_PUBLICKEYBYTES, PREKEY_AMOUNT * crypto_box_PUBLICKEYBYTES);
	status = generate_prekeys(alice_private_prekeys, alice_public_prekeys);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to generate Alice's prekeys.\n");
		buffer_clear(alice_private_identity);
		buffer_clear(alice_private_prekeys);
		return status;
	}

	//make illegal access to a node in the user store
	user_store_node *alice_node = user_store_find_node(store, alice_public_identity);
	print_hex(alice_node->public_identity_key.content, alice_node->public_identity_key.content_length, 30); //this should crash because of an access violation

	user_store_destroy(store);
	return EXIT_SUCCESS;
}
