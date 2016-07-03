/*
 * Molch, an implementation of the axolotl ratchet based on libsodium
 *
 * ISC License
 *
 * Copyright (C) 2015-2016 1984not Security GmbH
 * Author: Max Bruckner (FSMaxB)
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>
#include <string.h>
#include <assert.h>

#include "common.h"
#include "utils.h"
#include "../lib/conversation.h"
#include "../lib/json.h"
#include "tracing.h"

/*
 * Create a new conversation.
 *
 * Don't forget to destroy the return status with return_status_destroy_errors()
 * if an error has occurred.
 */
return_status create_conversation(
		conversation_t **const conversation,
		const buffer_t * const our_private_identity,
		const buffer_t * const our_public_identity,
		const buffer_t * const their_public_identity,
		const buffer_t * const our_private_ephemeral,
		const buffer_t * const our_public_ephemeral,
		const buffer_t * const their_public_ephemeral) {

	return_status status = return_status_init();

	//check input
	if ((conversation == NULL)
			|| (our_private_identity == NULL) || (our_private_identity->content_length != PRIVATE_KEY_SIZE)
			|| (our_public_identity == NULL) || (our_public_identity->content_length != PUBLIC_KEY_SIZE)
			|| (their_public_identity == NULL) || (their_public_identity->content_length != PUBLIC_KEY_SIZE)
			|| (our_private_ephemeral == NULL) || (our_public_ephemeral->content_length != PRIVATE_KEY_SIZE)
			|| (our_public_ephemeral == NULL) || (our_public_ephemeral->content_length != PUBLIC_KEY_SIZE)
			|| (their_public_ephemeral == NULL) || (their_public_ephemeral->content_length != PUBLIC_KEY_SIZE)) {
		throw(INVALID_INPUT, "Invalid input for conversation_create.");
	}

	*conversation = malloc(sizeof(conversation_t));
	if (conversation == NULL) {
		throw(ALLOCATION_FAILED, "Failed to allocate memory for conversation.");
	}

	//init_struct()
	buffer_init_with_pointer((*conversation)->id, (*conversation)->id_storage, CONVERSATION_ID_SIZE, CONVERSATION_ID_SIZE);
	(*conversation)->ratchet = NULL;
	(*conversation)->previous = NULL;
	(*conversation)->next = NULL;

	//create random id
	if (buffer_fill_random((*conversation)->id, CONVERSATION_ID_SIZE) != 0) {
		throw(BUFFER_ERROR, "Failed to create random conversation id.");
	}

	status = ratchet_create(
			&((*conversation)->ratchet),
			our_private_identity,
			our_public_identity,
			their_public_identity,
			our_private_ephemeral,
			our_public_ephemeral,
			their_public_ephemeral);
	throw_on_error(CREATION_ERROR, "Failed to create ratchet.");

cleanup:
	if (status.status != 0) {
		if ((conversation != NULL) && (*conversation != NULL)) {
			free(*conversation);
			*conversation = NULL;
		}
	}

	return status;
}

int main(void) {
	if (sodium_init() == -1) {
		fprintf(stderr, "ERROR: Failed to initialize libsodium! (-1)\n");
		return -1;
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

	//conversations
	conversation_t *charlie_conversation = NULL;
	conversation_t *dora_conversation = NULL;
	conversation_t *imported_charlies_conversation = NULL;

	return_status status = return_status_init();

	//creating charlie's identity keypair
	buffer_create_from_string(charlie_string, "charlie");
	buffer_create_from_string(identity_string, "identity");
	status = generate_and_print_keypair(
			charlie_public_identity,
			charlie_private_identity,
			charlie_string,
			identity_string);
	throw_on_error(KEYGENERATION_FAILED, "Failed to generate and print Charlie's identity keypair.");

	//creating charlie's ephemeral keypair
	buffer_create_from_string(ephemeral_string, "ephemeral");
	status = generate_and_print_keypair(
			charlie_public_ephemeral,
			charlie_private_ephemeral,
			charlie_string,
			ephemeral_string);
	throw_on_error(KEYGENERATION_FAILED, "Failed to generate and print Charlie's ephemeral keypair.");

	//creating dora's identity keypair
	buffer_create_from_string(dora_string, "dora");
	status = generate_and_print_keypair(
			dora_public_identity,
			dora_private_identity,
			dora_string,
			identity_string);
	throw_on_error(KEYGENERATION_FAILED, "Failed to generate and print Dora's identity keypair.");

	//creating dora's ephemeral keypair
	status = generate_and_print_keypair(
			dora_public_ephemeral,
			dora_private_ephemeral,
			dora_string,
			ephemeral_string);
	throw_on_error(KEYGENERATION_FAILED, "Failed to generate and print Dora's ephemeral keypair.");

	//create charlie's conversation
	status = create_conversation(
			&charlie_conversation,
			charlie_private_identity,
			charlie_public_identity,
			dora_public_identity,
			charlie_private_ephemeral,
			charlie_public_ephemeral,
			dora_public_ephemeral);
	buffer_clear(charlie_private_identity);
	buffer_clear(charlie_private_ephemeral);
	throw_on_error(INIT_ERROR, "Failed to init Chalie's conversation.");
	if (charlie_conversation->id->content_length != CONVERSATION_ID_SIZE) {
		throw(INCORRECT_DATA, "Charlie's conversation has an incorrect ID length.");
	}

	//create Dora's conversation
	status = create_conversation(
			&dora_conversation,
			dora_private_identity,
			dora_public_identity,
			charlie_public_identity,
			dora_private_ephemeral,
			dora_public_ephemeral,
			charlie_public_ephemeral);
	buffer_clear(dora_private_identity);
	buffer_clear(dora_private_ephemeral);
	throw_on_error(INIT_ERROR, "Failed to init Dora's conversation.");
	if (dora_conversation->id->content_length != CONVERSATION_ID_SIZE) {
		throw(INCORRECT_DATA, "Dora's conversation has an incorrect ID length.");
	}

	//test JSON export
	printf("Test JSON export!\n");
	mempool_t *pool = buffer_create_on_heap(10000, 0);
	mcJSON *json = conversation_json_export(charlie_conversation, pool);
	if (json == NULL) {
		buffer_destroy_from_heap(pool);
		throw(EXPORT_ERROR, "Failed to export as JSON.");
	}
	if (json->length != 2) {
		buffer_destroy_from_heap(pool);
		throw(INCORRECT_DATA, "JSON for Charlie's conversation is invalid.");
	}
	buffer_t *output = mcJSON_PrintBuffered(json, 4000, true);
	buffer_destroy_from_heap(pool);
	if (output == NULL) {
		throw(GENERIC_ERROR, "Failed to print JSON.");
	}
	printf("%.*s\n", (int)output->content_length, (char*)output->content);

	//test JSON import
	JSON_IMPORT(imported_charlies_conversation, 10000, output, conversation_json_import);
	if (imported_charlies_conversation == NULL) {
		buffer_destroy_from_heap(output);
		throw(IMPORT_ERROR, "Failed to import Charlie's conversation from JSON.");
	}
	//export the imported to JSON again
	JSON_EXPORT(imported_output, 10000, 4000, true, imported_charlies_conversation, conversation_json_export);
	if (imported_output == NULL) {
		buffer_destroy_from_heap(output);
		throw(EXPORT_ERROR, "Failed to export Charlie's imported conversation as JSON.");
	}
	//compare with original JSON
	if (buffer_compare(imported_output, output) != 0) {
		buffer_destroy_from_heap(imported_output);
		buffer_destroy_from_heap(output);
		throw(INCORRECT_DATA, "Imported conversation is incorrect.");
	}
	buffer_destroy_from_heap(imported_output);
	buffer_destroy_from_heap(output);

cleanup:
	if (charlie_conversation != NULL) {
		conversation_destroy(charlie_conversation);
	}
	if (dora_conversation != NULL) {
		conversation_destroy(dora_conversation);
	}
	if (imported_charlies_conversation != NULL) {
		conversation_destroy(imported_charlies_conversation);
	}

	buffer_destroy_from_heap(charlie_private_identity);
	buffer_destroy_from_heap(charlie_public_identity);
	buffer_destroy_from_heap(charlie_private_ephemeral);
	buffer_destroy_from_heap(charlie_public_ephemeral);
	buffer_destroy_from_heap(dora_private_identity);
	buffer_destroy_from_heap(dora_public_identity);
	buffer_destroy_from_heap(dora_private_ephemeral);
	buffer_destroy_from_heap(dora_public_ephemeral);

	on_error(
		print_errors(&status);
	);
	return_status_destroy_errors(&status);

	return status.status;
}
