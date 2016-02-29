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
#include "../lib/json.h"
#include "utils.h"
#include "tracing.h"

int test_add_conversation(conversation_store * const store) {
	//define key buffers
	//identity keys
	buffer_t *our_private_identity = buffer_create_on_heap(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	buffer_t *our_public_identity = buffer_create_on_heap(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	buffer_t *their_public_identity = buffer_create_on_heap(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	//ephemeral keys
	buffer_t *our_private_ephemeral = buffer_create_on_heap(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	buffer_t *our_public_ephemeral= buffer_create_on_heap(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	buffer_t *their_public_ephemeral = buffer_create_on_heap(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);

	conversation_t *conversation = NULL;

	//generate the keys
	int status = 0;

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

	//create the conversation manually
	conversation = malloc(sizeof(conversation_t));
	if (conversation == NULL) {
		status = EXIT_FAILURE;
		goto cleanup;
	}

	conversation->next = NULL;
	conversation->previous = NULL;
	conversation->ratchet = NULL;

	//create the conversation id
	buffer_init_with_pointer(conversation->id, conversation->id_storage, CONVERSATION_ID_SIZE, CONVERSATION_ID_SIZE);

	status = buffer_fill_random(conversation->id, CONVERSATION_ID_SIZE);
	if (status != 0) {
		goto cleanup;
	}

	conversation->ratchet = ratchet_create(
			our_private_identity,
			our_public_identity,
			their_public_identity,
			our_private_ephemeral,
			our_public_ephemeral,
			their_public_ephemeral);
	if (conversation->ratchet == NULL) {
		status = EXIT_FAILURE;
		goto cleanup;
	}

	status = conversation_store_add(store, conversation);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to add conversation to store. (%i)\n", status);
		goto cleanup;
	}
	conversation = NULL;

	goto cleanup;

keygen_fail:
	fprintf(stderr, "ERROR: Failed to generate keys. (%i)\n", status);
cleanup:
	if (conversation != NULL) {
		conversation_destroy(conversation);
	}
	//destroy all the buffers
	buffer_destroy_from_heap(our_private_identity);
	buffer_destroy_from_heap(our_public_identity);
	buffer_destroy_from_heap(their_public_identity);
	buffer_destroy_from_heap(our_private_ephemeral);
	buffer_destroy_from_heap(our_public_ephemeral);
	buffer_destroy_from_heap(their_public_ephemeral);
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
	if (conversation_store_find_node(store, store->head->next->next->id)
			!= store->head->next->next) {
		fprintf(stderr, "ERROR: Failed to find node by ID.\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	printf("Found node by ID.\n");

	//test list export feature
	buffer_t *conversation_list = conversation_store_list(store);
	if ((conversation_list == NULL) || (conversation_list->content_length != (CONVERSATION_ID_SIZE * store->length))) {
		fprintf(stderr, "ERROR: Failed to get list of conversations.\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}

	//check for all conversations that they exist
	for (size_t i = 0; i < (conversation_list->content_length / CONVERSATION_ID_SIZE); i++) {
		buffer_create_with_existing_array(current_id, conversation_list->content + CONVERSATION_ID_SIZE * i, CONVERSATION_ID_SIZE);
		if (conversation_store_find_node(store, current_id) == NULL) {
			fprintf(stderr, "ERROR: Exported list of conversations was incorrect.\n");
			buffer_destroy_from_heap(conversation_list);
			status = EXIT_FAILURE;
			goto cleanup;
		}
	}
	buffer_destroy_from_heap(conversation_list);

	//test JSON export
	printf("Test JSON export!\n");
	mempool_t *pool = buffer_create_on_heap(100000, 0);
	mcJSON *json = conversation_store_json_export(store, pool);
	if (json == NULL) {
		fprintf(stderr, "ERROR: Failed to export JSON.\n");
		buffer_destroy_from_heap(pool);
		status = EXIT_FAILURE;
		goto cleanup;
	}
	buffer_t *output = mcJSON_PrintBuffered(json, 4000, true);
	if (output == NULL) {
		fprintf(stderr, "ERROR: Failed to print json.\n");
		buffer_destroy_from_heap(pool);
		buffer_destroy_from_heap(output);
		status = EXIT_FAILURE;
		goto cleanup;
	}
	printf("%.*s\n", (int)output->content_length, output->content);
	if (json->length != 5) {
		fprintf(stderr, "ERROR: Exported JSON doesn't contain all conversations.\n");
		buffer_destroy_from_heap(pool);
		buffer_destroy_from_heap(output);
		status = EXIT_FAILURE;
		goto cleanup;
	}
	buffer_destroy_from_heap(pool);

	//test JSON import
	conversation_store *imported_store = malloc(sizeof(conversation_store));
	if (imported_store == NULL) {
		fprintf(stderr, "ERROR: Failed to allocate memory.\n");
		buffer_destroy_from_heap(output);
		status = EXIT_FAILURE;
		goto cleanup;
	}
	JSON_INITIALIZE(imported_store, 100000, output, conversation_store_json_import, status);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to import from JSON.\n");
		free(imported_store);
		buffer_destroy_from_heap(output);
		goto cleanup;
	}
	//export the imported to json again
	JSON_EXPORT(imported_output, 100000, 4000, true, imported_store, conversation_store_json_export);
	if (imported_output == NULL) {
		fprintf(stderr, "ERROR: Failed to print imported output.\n");
		conversation_store_clear(imported_store);
		free(imported_store);
		buffer_destroy_from_heap(output);
		goto cleanup;
	}
	conversation_store_clear(imported_store);
	free(imported_store);
	//compare both JSON strings
	if (buffer_compare(imported_output, output) != 0) {
		fprintf(stderr, "ERROR: Imported conversation store is incorrect.\n");
		buffer_destroy_from_heap(output);
		buffer_destroy_from_heap(imported_output);
		goto cleanup;
	}
	buffer_destroy_from_heap(output);
	buffer_destroy_from_heap(imported_output);

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
	conversation_store_remove_by_id(store, store->tail->id);
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
