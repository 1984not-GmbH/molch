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
#include <memory>

#include "common.hpp"
#include "utils.hpp"
#include "../lib/molch-exception.hpp"
#include "../lib/conversation.hpp"
#include "../lib/destroyers.hpp"

std::unique_ptr<Buffer> protobuf_export(const ConversationT& conversation) {
	//export the conversation
	auto exported_conversation = conversation.exportProtobuf();

	size_t export_size = conversation__get_packed_size(exported_conversation.get());
	auto export_buffer = std::make_unique<Buffer>(export_size, 0);
	export_buffer->content_length = conversation__pack(exported_conversation.get(), export_buffer->content);
	if (export_size != export_buffer->content_length) {
		throw MolchException(PROTOBUF_PACK_ERROR, "Failed to pack protobuf-c struct into buffer.");
	}

	return export_buffer;
}

std::unique_ptr<ConversationT> protobuf_import(const Buffer& import_buffer) {
	auto conversation_protobuf = std::unique_ptr<Conversation,ConversationDeleter>(conversation__unpack(
		&protobuf_c_allocators,
		import_buffer.content_length,
		import_buffer.content));
	if (!conversation_protobuf) {
		throw MolchException(PROTOBUF_UNPACK_ERROR, "Failed to unpack conversation from protobuf.");
	}

	return std::make_unique<ConversationT>(*conversation_protobuf);
}

int main(void) noexcept {
	try {
		if (sodium_init() == -1) {
			throw MolchException(INIT_ERROR, "Failed to initialize libsodium!\n");
		}

		//creating charlie's identity keypair
		Buffer charlie_private_identity(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
		Buffer charlie_public_identity(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
		exception_on_invalid_buffer(charlie_private_identity);
		exception_on_invalid_buffer(charlie_public_identity);
		generate_and_print_keypair(
			charlie_public_identity,
			charlie_private_identity,
			"Charlie",
			"identity");

		//creating charlie's ephemeral keypair
		Buffer charlie_private_ephemeral(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
		Buffer charlie_public_ephemeral(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
		exception_on_invalid_buffer(charlie_private_ephemeral);
		exception_on_invalid_buffer(charlie_public_ephemeral);
		generate_and_print_keypair(
			charlie_public_ephemeral,
			charlie_private_ephemeral,
			"Charlie",
			"ephemeral");

		//creating dora's identity keypair
		Buffer dora_private_identity(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
		Buffer dora_public_identity(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
		exception_on_invalid_buffer(dora_private_identity);
		exception_on_invalid_buffer(dora_public_identity);
		generate_and_print_keypair(
			dora_public_identity,
			dora_private_identity,
			"Dora",
			"identity");

		//creating dora's ephemeral keypair
		Buffer dora_private_ephemeral(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
		Buffer dora_public_ephemeral(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
		exception_on_invalid_buffer(dora_private_ephemeral);
		exception_on_invalid_buffer(dora_public_ephemeral);
		generate_and_print_keypair(
			dora_public_ephemeral,
			dora_private_ephemeral,
			"Dora",
			"ephemeral");

		//create charlie's conversation
		auto charlie_conversation = std::make_unique<ConversationT>(
				charlie_private_identity,
				charlie_public_identity,
				dora_public_identity,
				charlie_private_ephemeral,
				charlie_public_ephemeral,
				dora_public_ephemeral);
		if (!charlie_conversation || !charlie_conversation->id.contains(CONVERSATION_ID_SIZE)) {
			throw MolchException(INCORRECT_DATA, "Charlie's conversation has an incorrect ID length.");
		}

		//create Dora's conversation
		auto dora_conversation = std::make_unique<ConversationT>(
				dora_private_identity,
				dora_public_identity,
				charlie_public_identity,
				dora_private_ephemeral,
				dora_public_ephemeral,
				charlie_public_ephemeral);
		if (!dora_conversation || !dora_conversation->id.contains(CONVERSATION_ID_SIZE)) {
			throw MolchException(INCORRECT_DATA, "Dora's conversation has an incorrect ID length.");
		}

		//test protobuf-c export
		printf("Export to Protobuf-C\n");
		auto protobuf_export_buffer = protobuf_export(*charlie_conversation);

		std::cout << protobuf_export_buffer->toHex();
		puts("\n");

		charlie_conversation.reset();

		//import
		printf("Import from Protobuf-C\n");
		charlie_conversation = protobuf_import(*protobuf_export_buffer);

		//export again
		printf("Export again\n");
		auto protobuf_second_export_buffer = protobuf_export(*charlie_conversation);

		//compare
		if (!protobuf_export_buffer || (*protobuf_export_buffer != *protobuf_second_export_buffer)) {
			throw MolchException(EXPORT_ERROR, "Both exported buffers are not the same.");
		}
		printf("Both exported buffers are identitcal.\n\n");
	} catch (const MolchException& exception) {
		exception.print(std::cerr) << std::endl;
		return EXIT_FAILURE;
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
