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

int main(void) {
	int status = sodium_init();
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to initialize libsodium! (%i)\n", status);
		return status;
	}

	//creating charlie's identity keypair
	buffer_t *charlie_private_identity = buffer_create(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	buffer_t *charlie_public_identity = buffer_create(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	buffer_create_from_string(charlie_string, "charlie");
	buffer_create_from_string(identity_string, "identity");

	status = generate_and_print_keypair(
			charlie_public_identity,
			charlie_private_identity,
			charlie_string,
			identity_string);
	if (status != 0) {
		buffer_clear(charlie_private_identity);
		return status;
	}

	//creating charlie's ephemeral keypair
	buffer_t *charlie_private_ephemeral = buffer_create(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	buffer_t *charlie_public_ephemeral = buffer_create(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	buffer_create_from_string(ephemeral_string, "ephemeral");
	status = generate_and_print_keypair(
			charlie_public_ephemeral,
			charlie_private_ephemeral,
			charlie_string,
			ephemeral_string);
	if (status != 0) {
		buffer_clear(charlie_private_identity);
		buffer_clear(charlie_private_ephemeral);
		return status;
	}

	//creating dora's identity keypair
	buffer_t *dora_private_identity = buffer_create(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	buffer_t *dora_public_identity = buffer_create(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	buffer_create_from_string(dora_string, "dora");
	status = generate_and_print_keypair(
			dora_public_identity,
			dora_private_identity,
			dora_string,
			identity_string);
	if (status != 0) {
		buffer_clear(charlie_private_identity);
		buffer_clear(charlie_private_ephemeral);
		buffer_clear(dora_private_identity);
		return status;
	}

	//creating dora's ephemeral keypair
	buffer_t *dora_private_ephemeral = buffer_create(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	buffer_t *dora_public_ephemeral = buffer_create(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	status = generate_and_print_keypair(
			dora_public_ephemeral,
			dora_private_ephemeral,
			dora_string,
			ephemeral_string);
	if (status != 0) {
		buffer_clear(charlie_private_identity);
		buffer_clear(charlie_private_ephemeral);
		buffer_clear(dora_private_identity);
		buffer_clear(dora_private_ephemeral);
		return status;
	}

	//create charlie's conversation
	conversation_t *charlie_conversation = malloc(sizeof(conversation_t));
	if (charlie_conversation == NULL) {
		fprintf(stderr, "ERROR: Failed to allocate memory.\n");
		buffer_clear(charlie_private_identity);
		buffer_clear(charlie_private_ephemeral);
		buffer_clear(dora_private_identity);
		buffer_clear(dora_private_ephemeral);
		return EXIT_FAILURE;
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
		buffer_clear(dora_private_identity);
		buffer_clear(dora_private_ephemeral);
		free(charlie_conversation);
		return EXIT_FAILURE;
	}
	if (charlie_conversation->id->content_length != CONVERSATION_ID_SIZE) {
		fprintf(stderr, "ERROR: Charlie's conversation has an incorrect ID length.\n");
		buffer_clear(dora_private_identity);
		buffer_clear(dora_private_ephemeral);
		conversation_deinit(charlie_conversation);
		free(charlie_conversation);
		return EXIT_FAILURE;
	}

	//create Dora's conversation
	conversation_t *dora_conversation = malloc(sizeof(conversation_t));
	if (dora_conversation == NULL) {
		fprintf(stderr, "ERROR: Failed to allocate memory!\n");
		buffer_clear(dora_private_identity);
		buffer_clear(dora_private_ephemeral);
		conversation_deinit(charlie_conversation);
		free(charlie_conversation);

		return EXIT_FAILURE;
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
		return EXIT_FAILURE;
	}
	if (dora_conversation->id->content_length != CONVERSATION_ID_SIZE) {
		fprintf(stderr, "ERROR: Dora's conversation has an incorrect ID length.\n");
		conversation_deinit(charlie_conversation);
		free(charlie_conversation);
		conversation_deinit(dora_conversation);
		free(dora_conversation);
		return EXIT_FAILURE;
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
		return EXIT_FAILURE;
	}
	if (json->length != 2) {
		fprintf(stderr, "ERROR: JSON for Charlie's conversation is invalid!");
		buffer_destroy_from_heap(pool);
		conversation_deinit(charlie_conversation);
		free(charlie_conversation);
		conversation_deinit(dora_conversation);
		free(dora_conversation);
		return EXIT_FAILURE;
	}
	buffer_t *output = mcJSON_PrintBuffered(json, 4000, true);
	if (output == NULL) {
		fprintf(stderr, "ERROR: Failed to print JSON.\n");
		buffer_destroy_from_heap(pool);
		conversation_deinit(charlie_conversation);
		free(charlie_conversation);
		conversation_deinit(dora_conversation);
		free(dora_conversation);
		return EXIT_FAILURE;
	}
	printf("%.*s\n", (int)output->content_length, (char*)output->content);

	//test JSON import
	conversation_t *imported_charlies_conversation = malloc(sizeof(conversation_t));
	if (imported_charlies_conversation == NULL) {
		fprintf(stderr, "ERROR: Memory allocation failed.\n");
		buffer_destroy_from_heap(pool);
		buffer_destroy_from_heap(output);
		conversation_deinit(charlie_conversation);
		free(charlie_conversation);
		conversation_deinit(dora_conversation);
		free(dora_conversation);
		return EXIT_FAILURE;
	}
	status = conversation_json_import(imported_charlies_conversation, json);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to import Charlie's conversation form JSON.\n");
		buffer_destroy_from_heap(pool);
		buffer_destroy_from_heap(output);
		conversation_deinit(charlie_conversation);
		free(charlie_conversation);
		conversation_deinit(dora_conversation);
		free(dora_conversation);
		free(imported_charlies_conversation);
		return EXIT_FAILURE;
	}
	//export the imported to JSON again
	pool->position = 0; //reset the mempool
	mcJSON *imported_json = conversation_json_export(imported_charlies_conversation, pool);
	buffer_t *imported_output = mcJSON_PrintBuffered(imported_json, 4000, true);
	//compare with original JSON
	if (buffer_compare(imported_output, output) != 0) {
		fprintf(stderr, "ERROR: Imported conversation is incorrect.\n");
		buffer_destroy_from_heap(pool);
		buffer_destroy_from_heap(imported_output);
		buffer_destroy_from_heap(output);
		conversation_deinit(charlie_conversation);
		free(charlie_conversation);
		conversation_deinit(dora_conversation);
		free(dora_conversation);
		conversation_deinit(imported_charlies_conversation);
		free(imported_charlies_conversation);
		return EXIT_FAILURE;
	}
	buffer_destroy_from_heap(imported_output);
	buffer_destroy_from_heap(output);
	buffer_destroy_from_heap(pool);
	conversation_deinit(imported_charlies_conversation);
	free(imported_charlies_conversation);

	//now destroy the conversations again
	conversation_deinit(charlie_conversation);
	free(charlie_conversation);
	conversation_deinit(dora_conversation);
	free(dora_conversation);

	return EXIT_SUCCESS;
}
