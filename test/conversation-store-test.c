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
#include <alloca.h>

#include "../lib/conversation-store.h"
#include "utils.h"

int test_add_conversation(conversation_store * const store) {
	//define key buffers
	//identity keys
	buffer_t *our_private_identity = buffer_create(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	buffer_t *our_public_identity = buffer_create(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	buffer_t *their_public_identity = buffer_create(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	//ephemeral keys
	buffer_t *our_private_ephemeral = buffer_create(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	buffer_t *our_public_ephemeral= buffer_create(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	buffer_t *their_public_ephemeral = buffer_create(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);

	//generate the keys
	int status;
	status = crypto_box_keypair(our_public_identity->content, our_private_identity->content);
	if (status != 0) {
		goto keygen_fail;
	}
	status = crypto_box_keypair(our_public_ephemeral->content, our_private_ephemeral->content);
	if (status != 0) {
		goto keygen_fail;
	}
	status = buffer_fill_random(their_public_identity, their_public_identity->buffer_length);
	if (status != 0) {
		goto keygen_fail;
	}
	status = buffer_fill_random(their_public_ephemeral, their_public_ephemeral->buffer_length);
	if (status != 0) {
		goto keygen_fail;
	}

	status = conversation_store_add(
			store,
			our_private_identity,
			our_public_identity,
			their_public_identity,
			our_private_ephemeral,
			our_public_ephemeral,
			their_public_ephemeral);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to add conversation to store. (%i)\n", status);
		goto fail;
	}

	return status;

keygen_fail:
	fprintf(stderr, "ERROR: Failed to generate keys. (%i)\n", status);
fail:
	//clear all the buffers
	buffer_clear(our_private_identity);
	buffer_clear(our_private_ephemeral);
	return status;
}

int main(void) {
	if (sodium_init() == -1) {
		return -1;
	}

	int status = EXIT_SUCCESS;
	conversation_store *store = malloc(sizeof(conversation_store));
	if (store == NULL) {
		fprintf(stderr, "ERROR: Failed to allocate memory!\n");
		goto cleanup;
	}

	printf("Initialize the conversation store.\n");
	conversation_store_init(store);

	// add five conversations
	printf("Add five conversations.\n");
	for (size_t i = 0; i < 5; i++) {
		printf("%zu\n", i);
		status = test_add_conversation(store);
		if (status != 0) {
			goto cleanup;
		}
		if (store->length != (i + 1)) {
			fprintf(stderr, "ERROR: Conversation store has incorrect length.\n");
			status = EXIT_FAILURE;
			goto cleanup;
		}
	}

	//show all the conversation ids
	printf("Conversation IDs (test of foreach):\n");
	conversation_store_foreach(store,
		printf("ID of the conversation No. %zu:\n", index);
		print_hex(value->id);
		putchar('\n');
	);

	//find node by id
	if (conversation_store_find_node(store, store->head->next->next->conversation->id)
			!= store->head->next->next) {
		fprintf(stderr, "ERROR: Failed to find node by ID.\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	printf("Found node by ID.\n");

	//remove nodes
	conversation_store_remove(store, store->head);
	printf("Removed head.\n");
	conversation_store_remove(store, store->tail);
	printf("Removed tail.\n");
	conversation_store_remove(store, store->head->next);

	if (store->length != 2) {
		fprintf(stderr, "ERROR: Failed to remove nodes.\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	printf("Successfully removed nodes.\n");

	//remove node by id
	conversation_store_remove_by_id(store, store->tail->conversation->id);
	if (store->length != 1) {
		fprintf(stderr, "ERROR: Failed to remove node by id.\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	printf("Successfully removed node by id.\n");

	//clear the conversation store
	printf("Clear the conversation store.\n");

cleanup:
	conversation_store_clear(store);
	free(store);
	return status;
}
