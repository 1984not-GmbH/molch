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
#include <string.h>
#include <assert.h>

#include "common.h"
#include "../lib/conversation.h"
#include "../lib/json.h"
#include "tracing.h"

int main(void) {
	int status = sodium_init();
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to initialize libsodium! (%i)\n", status);
		return status;
	}

	//create buffers
	buffer_t *charlie_private_identity = buffer_create_on_heap(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	buffer_t *charlie_public_identity = buffer_create_on_heap(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	buffer_t *charlie_private_ephemeral = buffer_create_on_heap(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	buffer_t *charlie_public_ephemeral = buffer_create_on_heap(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	buffer_t *dora_private_identity = buffer_create_on_heap(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	buffer_t *dora_public_identity = buffer_create_on_heap(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	buffer_t *dora_private_ephemeral = buffer_create_on_heap(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	buffer_t *dora_public_ephemeral = buffer_create_on_heap(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);

	//creating charlie's identity keypair
	buffer_create_from_string(charlie_string, "charlie");
	buffer_create_from_string(identity_string, "identity");

	status = generate_and_print_keypair(
			charlie_public_identity,
			charlie_private_identity,
			charlie_string,
			identity_string);
	if (status != 0) {
		goto cleanup;
	}

	//creating charlie's ephemeral keypair
	buffer_create_from_string(ephemeral_string, "ephemeral");
	status = generate_and_print_keypair(
			charlie_public_ephemeral,
			charlie_private_ephemeral,
			charlie_string,
			ephemeral_string);
	if (status != 0) {
		goto cleanup;
	}

	//creating dora's identity keypair
	buffer_create_from_string(dora_string, "dora");
	status = generate_and_print_keypair(
			dora_public_identity,
			dora_private_identity,
			dora_string,
			identity_string);
	if (status != 0) {
		goto cleanup;
	}

	//creating dora's ephemeral keypair
	status = generate_and_print_keypair(
			dora_public_ephemeral,
			dora_private_ephemeral,
			dora_string,
			ephemeral_string);
	if (status != 0) {
		goto cleanup;
	}

	//create charlie's conversation
	conversation_t *charlie_conversation = malloc(sizeof(conversation_t));
	if (charlie_conversation == NULL) {
		fprintf(stderr, "ERROR: Failed to allocate memory.\n");
		goto cleanup;
	}
	status = conversation_init(
			charlie_conversation,
			charlie_private_identity,
			charlie_public_identity,
			dora_public_identity,
			charlie_private_ephemeral,
			charlie_public_ephemeral,
			dora_public_ephemeral);
	buffer_clear(charlie_private_identity);
	buffer_clear(charlie_private_ephemeral);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to init Charlie's conversation.\n");
		free(charlie_conversation);
		goto cleanup;
	}
	if (charlie_conversation->id->content_length != CONVERSATION_ID_SIZE) {
		fprintf(stderr, "ERROR: Charlie's conversation has an incorrect ID length.\n");
		free(charlie_conversation);
		goto cleanup;
	}

	//create Dora's conversation
	conversation_t *dora_conversation = malloc(sizeof(conversation_t));
	if (dora_conversation == NULL) {
		fprintf(stderr, "ERROR: Failed to allocate memory!\n");
		conversation_deinit(charlie_conversation);
		free(charlie_conversation);

		goto cleanup;
	}
	status = conversation_init(
			dora_conversation,
			dora_private_identity,
			dora_public_identity,
			charlie_public_identity,
			dora_private_ephemeral,
			dora_public_ephemeral,
			charlie_public_ephemeral);
	buffer_clear(dora_private_identity);
	buffer_clear(dora_private_ephemeral);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to init Dora's conversation.\n");
		conversation_deinit(charlie_conversation);
		free(charlie_conversation);
		free(dora_conversation);
		goto cleanup;
	}
	if (dora_conversation->id->content_length != CONVERSATION_ID_SIZE) {
		fprintf(stderr, "ERROR: Dora's conversation has an incorrect ID length.\n");
		conversation_deinit(charlie_conversation);
		free(charlie_conversation);
		conversation_deinit(dora_conversation);
		free(dora_conversation);
		goto cleanup;
	}

	//test JSON export
	printf("Test JSON export!\n");
	mempool_t *pool = buffer_create_on_heap(10000, 0);
	mcJSON *json = conversation_json_export(charlie_conversation, pool);
	if (json == NULL) {
		fprintf(stderr, "ERROR: Failed to export into JSON!\n");
		buffer_destroy_from_heap(pool);
		conversation_deinit(charlie_conversation);
		free(charlie_conversation);
		conversation_deinit(dora_conversation);
		free(dora_conversation);
		goto cleanup;
	}
	if (json->length != 2) {
		fprintf(stderr, "ERROR: JSON for Charlie's conversation is invalid!");
		buffer_destroy_from_heap(pool);
		conversation_deinit(charlie_conversation);
		free(charlie_conversation);
		conversation_deinit(dora_conversation);
		free(dora_conversation);
		goto cleanup;
	}
	buffer_t *output = mcJSON_PrintBuffered(json, 4000, true);
	buffer_destroy_from_heap(pool);
	if (output == NULL) {
		fprintf(stderr, "ERROR: Failed to print JSON.\n");
		conversation_deinit(charlie_conversation);
		free(charlie_conversation);
		conversation_deinit(dora_conversation);
		free(dora_conversation);
		goto cleanup;
	}
	printf("%.*s\n", (int)output->content_length, (char*)output->content);

	//test JSON import
	conversation_t *imported_charlies_conversation = malloc(sizeof(conversation_t));
	if (imported_charlies_conversation == NULL) {
		fprintf(stderr, "ERROR: Memory allocation failed.\n");
		buffer_destroy_from_heap(output);
		conversation_deinit(charlie_conversation);
		free(charlie_conversation);
		conversation_deinit(dora_conversation);
		free(dora_conversation);
		goto cleanup;
	}
	JSON_INITIALIZE(imported_charlies_conversation, 10000, output, conversation_json_import, status);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to import Charlie's conversation form JSON.\n");
		buffer_destroy_from_heap(output);
		conversation_deinit(charlie_conversation);
		free(charlie_conversation);
		conversation_deinit(dora_conversation);
		free(dora_conversation);
		free(imported_charlies_conversation);
		goto cleanup;
	}
	//export the imported to JSON again
	JSON_EXPORT(imported_output, 10000, 4000, true, imported_charlies_conversation, conversation_json_export);
	if (imported_output == NULL) {
		fprintf(stderr, "ERROR: Failed to export Charlie's imported conversation to JSON.\n");
		buffer_destroy_from_heap(output);
		conversation_deinit(charlie_conversation);
		free(charlie_conversation);
		conversation_deinit(dora_conversation);
		free(dora_conversation);
		free(imported_charlies_conversation);
		goto cleanup;
	}
	//compare with original JSON
	if (buffer_compare(imported_output, output) != 0) {
		fprintf(stderr, "ERROR: Imported conversation is incorrect.\n");
		buffer_destroy_from_heap(imported_output);
		buffer_destroy_from_heap(output);
		conversation_deinit(charlie_conversation);
		free(charlie_conversation);
		conversation_deinit(dora_conversation);
		free(dora_conversation);
		conversation_deinit(imported_charlies_conversation);
		free(imported_charlies_conversation);
		goto cleanup;
	}
	buffer_destroy_from_heap(imported_output);
	buffer_destroy_from_heap(output);
	conversation_deinit(imported_charlies_conversation);
	free(imported_charlies_conversation);

	//now destroy the conversations again
	conversation_deinit(charlie_conversation);
	free(charlie_conversation);
	conversation_deinit(dora_conversation);
	free(dora_conversation);

cleanup:
	buffer_destroy_from_heap(charlie_private_identity);
	buffer_destroy_from_heap(charlie_public_identity);
	buffer_destroy_from_heap(charlie_private_ephemeral);
	buffer_destroy_from_heap(charlie_public_ephemeral);
	buffer_destroy_from_heap(dora_private_identity);
	buffer_destroy_from_heap(dora_public_identity);
	buffer_destroy_from_heap(dora_private_ephemeral);
	buffer_destroy_from_heap(dora_public_ephemeral);

	return status;
}
