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

#include <cstdio>
#include <cstdlib>
#include <sodium.h>
#include <exception>
#include <iostream>

#include "common.hpp"
#include "utils.hpp"
#include "../lib/molch-exception.hpp"
#include "../lib/conversation.hpp"
#include "../lib/destroyers.hpp"

return_status protobuf_export(conversation_t * const conversation, Buffer ** const export_buffer) noexcept __attribute__((warn_unused_result));
return_status protobuf_export(conversation_t * const conversation, Buffer ** const export_buffer) noexcept {
	return_status status = return_status_init();

	Conversation *exported_conversation = nullptr;

	//check input
	if ((conversation == nullptr) || (export_buffer == nullptr)) {
		THROW(INVALID_INPUT, "Invalid input to protobuf_export.");
	}

	//export the conversation
	status = conversation_export(conversation, &exported_conversation);
	THROW_on_error(EXPORT_ERROR, "Failed to export conversation.");

	{
		size_t export_size = conversation__get_packed_size(exported_conversation);
		*export_buffer = Buffer::create(export_size, 0);
		(*export_buffer)->content_length = conversation__pack(exported_conversation, (*export_buffer)->content);
		if (export_size != (*export_buffer)->content_length) {
			THROW(PROTOBUF_PACK_ERROR, "Failed to pack protobuf-c struct into buffer.");
		}
	}

cleanup:
	if (exported_conversation != nullptr) {
		conversation__free_unpacked(exported_conversation, &protobuf_c_allocators);
	}

	//rest will be freed in main
	return status;
}

return_status protobuf_import(
		conversation_t ** const conversation,
		Buffer * const import_buffer) noexcept __attribute__((warn_unused_result));
return_status protobuf_import(
		conversation_t ** const conversation,
		Buffer * const import_buffer) noexcept {
	return_status status = return_status_init();

	Conversation *conversation_protobuf = nullptr;

	//check input
	if ((conversation == nullptr) || (import_buffer == nullptr)) {
		THROW(INVALID_INPUT, "Invalid input to protobuf_import.");
	}

	conversation_protobuf = conversation__unpack(
		&protobuf_c_allocators,
		import_buffer->content_length,
		import_buffer->content);
	if (conversation_protobuf == nullptr) {
		THROW(PROTOBUF_UNPACK_ERROR, "Failed to unpack conversation from protobuf.");
	}
	THROW_on_failed_alloc(conversation_protobuf);

	status = conversation_import(conversation, conversation_protobuf);
	THROW_on_error(IMPORT_ERROR, "Failed to import conversation.");

cleanup:
	if (conversation_protobuf != nullptr) {
		conversation__free_unpacked(conversation_protobuf, &protobuf_c_allocators);
		conversation_protobuf = nullptr;
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
		Buffer * const our_private_identity,
		Buffer * const our_public_identity,
		Buffer * const their_public_identity,
		Buffer * const our_private_ephemeral,
		Buffer * const our_public_ephemeral,
		Buffer * const their_public_ephemeral) noexcept {

	return_status status = return_status_init();

	//check input
	if ((conversation == nullptr)
			|| (our_private_identity == nullptr) || (our_private_identity->content_length != PRIVATE_KEY_SIZE)
			|| (our_public_identity == nullptr) || (our_public_identity->content_length != PUBLIC_KEY_SIZE)
			|| (their_public_identity == nullptr) || (their_public_identity->content_length != PUBLIC_KEY_SIZE)
			|| (our_private_ephemeral == nullptr) || (our_public_ephemeral->content_length != PRIVATE_KEY_SIZE)
			|| (our_public_ephemeral == nullptr) || (our_public_ephemeral->content_length != PUBLIC_KEY_SIZE)
			|| (their_public_ephemeral == nullptr) || (their_public_ephemeral->content_length != PUBLIC_KEY_SIZE)) {
		THROW(INVALID_INPUT, "Invalid input for conversation_create.");
	}

	*conversation = reinterpret_cast<conversation_t*>(malloc(sizeof(conversation_t)));
	if (conversation == nullptr) {
		THROW(ALLOCATION_FAILED, "Failed to allocate memory for conversation.");
	}

	//init_struct()
	(*conversation)->id.init((*conversation)->id_storage, CONVERSATION_ID_SIZE, CONVERSATION_ID_SIZE);
	(*conversation)->ratchet = nullptr;
	(*conversation)->previous = nullptr;
	(*conversation)->next = nullptr;

	//create random id
	if ((*conversation)->id.fillRandom(CONVERSATION_ID_SIZE) != 0) {
		THROW(BUFFER_ERROR, "Failed to create random conversation id.");
	}

	try {
		(*conversation)->ratchet = new Ratchet(
				*our_private_identity,
				*our_public_identity,
				*their_public_identity,
				*our_private_ephemeral,
				*our_public_ephemeral,
				*their_public_ephemeral);
	} catch (const MolchException& exception) {
		status = exception.toReturnStatus();
		goto cleanup;
	} catch (const std::exception& exception) {
		THROW(EXCEPTION, exception.what());
	}

cleanup:
	on_error {
		if (conversation != nullptr) {
			free_and_null_if_valid(*conversation);
		}
	}

	return status;
}

int main(void) noexcept {
	if (sodium_init() == -1) {
		fprintf(stderr, "ERROR: Failed to initialize libsodium! (-1)\n");
		return -1;
	}

	//create buffers
	Buffer *charlie_private_identity = Buffer::create(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	Buffer *charlie_public_identity = Buffer::create(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	Buffer *charlie_private_ephemeral = Buffer::create(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	Buffer *charlie_public_ephemeral = Buffer::create(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	Buffer *dora_private_identity = Buffer::create(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	Buffer *dora_public_identity = Buffer::create(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	Buffer *dora_private_ephemeral = Buffer::create(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	Buffer *dora_public_ephemeral = Buffer::create(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);

	//Protobuf export buffers
	Buffer *protobuf_export_buffer = nullptr;
	Buffer *protobuf_second_export_buffer = nullptr;

	//conversations
	conversation_t *charlie_conversation = nullptr;
	conversation_t *dora_conversation = nullptr;
	conversation_t *imported_charlies_conversation = nullptr;

	return_status status = return_status_init();

	try {
		//creating charlie's identity keypair
		generate_and_print_keypair(
			*charlie_public_identity,
			*charlie_private_identity,
			"Charlie",
			"identity");

		//creating charlie's ephemeral keypair
		generate_and_print_keypair(
			*charlie_public_ephemeral,
			*charlie_private_ephemeral,
			"Charlie",
			"ephemeral");

		//creating dora's identity keypair
		generate_and_print_keypair(
			*dora_public_identity,
			*dora_private_identity,
			"Dora",
			"identity");

		//creating dora's ephemeral keypair
		generate_and_print_keypair(
			*dora_public_ephemeral,
			*dora_private_ephemeral,
			"Dora",
			"ephemeral");
	} catch (const MolchException& exception) {
		status = exception.toReturnStatus();
		goto cleanup;
	} catch (const std::exception& exception) {
		THROW(EXCEPTION, exception.what());
	}

	//create charlie's conversation
	status = create_conversation(
			&charlie_conversation,
			charlie_private_identity,
			charlie_public_identity,
			dora_public_identity,
			charlie_private_ephemeral,
			charlie_public_ephemeral,
			dora_public_ephemeral);
	charlie_private_identity->clear();
	charlie_private_ephemeral->clear();
	THROW_on_error(INIT_ERROR, "Failed to init Chalie's conversation.");
	if ((charlie_conversation == NULL) || (charlie_conversation->id.content_length != CONVERSATION_ID_SIZE)) {
		THROW(INCORRECT_DATA, "Charlie's conversation has an incorrect ID length.");
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
	dora_private_identity->clear();
	dora_private_ephemeral->clear();
	THROW_on_error(INIT_ERROR, "Failed to init Dora's conversation.");
	if ((dora_conversation == NULL) || (dora_conversation->id.content_length != CONVERSATION_ID_SIZE)) {
		THROW(INCORRECT_DATA, "Dora's conversation has an incorrect ID length.");
	}

	//test protobuf-c export
	printf("Export to Protobuf-C\n");
	status = protobuf_export(charlie_conversation, &protobuf_export_buffer);
	THROW_on_error(EXPORT_ERROR, "Failed to export charlie's conversation to protobuf-c.");

	std::cout << protobuf_export_buffer->toHex();
	puts("\n");

	conversation_destroy(charlie_conversation);
	charlie_conversation = nullptr;

	//import
	printf("Import from Protobuf-C\n");
	status = protobuf_import(&charlie_conversation, protobuf_export_buffer);
	THROW_on_error(IMPORT_ERROR, "Failed to imoport Charlie's conversation from Protobuf-C.");

	//export again
	printf("Export again\n");
	status = protobuf_export(charlie_conversation, &protobuf_second_export_buffer);
	THROW_on_error(EXPORT_ERROR, "Failed to export charlie's conversation to protobuf-c.");

	//compare
	if ((protobuf_export_buffer == NULL) || (protobuf_export_buffer->compare(protobuf_second_export_buffer) != 0)) {
		THROW(EXPORT_ERROR, "Both exported buffers are not the same.");
	}
	printf("Both exported buffers are identitcal.\n\n");

cleanup:
	if (charlie_conversation != nullptr) {
		conversation_destroy(charlie_conversation);
	}
	if (dora_conversation != nullptr) {
		conversation_destroy(dora_conversation);
	}
	if (imported_charlies_conversation != nullptr) {
		conversation_destroy(imported_charlies_conversation);
	}

	buffer_destroy_and_null_if_valid(protobuf_export_buffer);
	buffer_destroy_and_null_if_valid(protobuf_second_export_buffer);

	buffer_destroy_and_null_if_valid(charlie_private_identity);
	buffer_destroy_and_null_if_valid(charlie_public_identity);
	buffer_destroy_and_null_if_valid(charlie_private_ephemeral);
	buffer_destroy_and_null_if_valid(charlie_public_ephemeral);
	buffer_destroy_and_null_if_valid(dora_private_identity);
	buffer_destroy_and_null_if_valid(dora_public_identity);
	buffer_destroy_and_null_if_valid(dora_private_ephemeral);
	buffer_destroy_and_null_if_valid(dora_public_ephemeral);

	on_error {
		print_errors(status);
	}
	return_status_destroy_errors(&status);

	return status.status;
}
