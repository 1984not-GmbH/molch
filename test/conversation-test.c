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

return_status protobuf_export(const conversation_t * const conversation, buffer_t ** const export_buffer) __attribute__((warn_unused_result));
return_status protobuf_export(const conversation_t * const conversation, buffer_t ** const export_buffer) {
	return_status status = return_status_init();

	Conversation *exported_conversation = NULL;

	//check input
	if ((conversation == NULL) || (export_buffer == NULL)) {
		throw(INVALID_INPUT, "Invalid input to protobuf_export.");
	}

	//export the conversation
	status = conversation_export(conversation, &exported_conversation);
	throw_on_error(EXPORT_ERROR, "Failed to export conversation.");

	size_t export_size = conversation__get_packed_size(exported_conversation);
	*export_buffer = buffer_create_on_heap(export_size, 0);
	(*export_buffer)->content_length = conversation__pack(exported_conversation, (*export_buffer)->content);
	if (export_size != (*export_buffer)->content_length) {
		throw(PROTOBUF_PACK_ERROR, "Failed to pack protobuf-c struct into buffer.");
	}

cleanup:
	if (exported_conversation != NULL) {
		conversation__free_unpacked(exported_conversation, &protobuf_c_allocators);
	}

	//rest will be freed in main
	return status;
}

return_status protobuf_import(
		conversation_t ** const conversation,
		const buffer_t * const import_buffer) __attribute__((warn_unused_result));
return_status protobuf_import(
		conversation_t ** const conversation,
		const buffer_t * const import_buffer) {
	return_status status = return_status_init();

	Conversation *conversation_protobuf = NULL;

	//check input
	if ((conversation == NULL) || (import_buffer == NULL)) {
		throw(INVALID_INPUT, "Invalid input to protobuf_import.");
	}

	conversation_protobuf = conversation__unpack(
		&protobuf_c_allocators,
		import_buffer->content_length,
		import_buffer->content);
	if (conversation_protobuf == NULL) {
		throw(PROTOBUF_UNPACK_ERROR, "Failed to unpack conversation from protobuf.");
	}
	throw_on_failed_alloc(conversation_protobuf);

	status = conversation_import(conversation, conversation_protobuf);
	throw_on_error(IMPORT_ERROR, "Failed to import conversation.");

cleanup:
	if (conversation_protobuf != NULL) {
		conversation__free_unpacked(conversation_protobuf, &protobuf_c_allocators);
		conversation_protobuf = NULL;
	}

	return status;
}

/*
 * Create a new conversation.
 *
 * Don't forget to destroy the return status with return_status_destroy_errors()
 * if an error has occurred.
 */
static return_status create_conversation(
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
	on_error {
		if (conversation != NULL) {
			free_and_null_if_valid(*conversation);
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

	//Protobuf export buffers
	buffer_t *protobuf_export_buffer = NULL;
	buffer_t *protobuf_second_export_buffer = NULL;

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

	//test protobuf-c export
	printf("Export to Protobuf-C\n");
	status = protobuf_export(charlie_conversation, &protobuf_export_buffer);
	throw_on_error(EXPORT_ERROR, "Failed to export charlie's conversation to protobuf-c.");

	print_hex(protobuf_export_buffer);
	puts("\n");

	conversation_destroy(charlie_conversation);
	charlie_conversation = NULL;

	//import
	printf("Import from Protobuf-C\n");
	status = protobuf_import(&charlie_conversation, protobuf_export_buffer);
	throw_on_error(IMPORT_ERROR, "Failed to imoport Charlie's conversation from Protobuf-C.");

	//export again
	printf("Export again\n");
	status = protobuf_export(charlie_conversation, &protobuf_second_export_buffer);
	throw_on_error(EXPORT_ERROR, "Failed to export charlie's conversation to protobuf-c.");

	//compare
	if (buffer_compare(protobuf_export_buffer, protobuf_second_export_buffer) != 0) {
		throw(EXPORT_ERROR, "Both exported buffers are not the same.");
	}
	printf("Both exported buffers are identitcal.\n\n");

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

	buffer_destroy_from_heap_and_null_if_valid(protobuf_export_buffer);
	buffer_destroy_from_heap_and_null_if_valid(protobuf_second_export_buffer);

	buffer_destroy_from_heap_and_null_if_valid(charlie_private_identity);
	buffer_destroy_from_heap_and_null_if_valid(charlie_public_identity);
	buffer_destroy_from_heap_and_null_if_valid(charlie_private_ephemeral);
	buffer_destroy_from_heap_and_null_if_valid(charlie_public_ephemeral);
	buffer_destroy_from_heap_and_null_if_valid(dora_private_identity);
	buffer_destroy_from_heap_and_null_if_valid(dora_public_identity);
	buffer_destroy_from_heap_and_null_if_valid(dora_private_ephemeral);
	buffer_destroy_from_heap_and_null_if_valid(dora_public_ephemeral);

	on_error {
		print_errors(&status);
	}
	return_status_destroy_errors(&status);

	return status.status;
}
