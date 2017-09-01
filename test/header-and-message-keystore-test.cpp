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

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <sodium.h>
#include <cassert>
#include <iostream>
#include <exception>
#include <iterator>

#include "../lib/header-and-message-keystore.hpp"
#include "../lib/molch-exception.hpp"
#include "../lib/destroyers.hpp"
#include "utils.hpp"
#include "common.hpp"

using namespace Molch;

static void protobuf_export(
			HeaderAndMessageKeyStore& keystore,
			std::vector<Buffer>& export_buffers) {
	ProtobufPool pool;
	auto exported_bundles{keystore.exportProtobuf(pool)};

	export_buffers = std::vector<Buffer>();

	//create all the export buffers
	for (const auto& key_bundle : exported_bundles) {
		auto export_size{key_bundle__get_packed_size(key_bundle)};
		Buffer export_buffer{export_size, 0};
		export_buffer.setSize(key_bundle__pack(key_bundle, byte_to_uchar(export_buffer.data())));
		if (export_buffer.size() != export_size) {
			throw Molch::Exception{status_type::PROTOBUF_PACK_ERROR, "Packed buffer has incorrect length."};
		}
		export_buffers.push_back(export_buffer);
	}
}

static void protobuf_import(
		ProtobufPool& pool,
		HeaderAndMessageKeyStore& keystore,
		const std::vector<Buffer>& exported_buffers) {
	auto pool_protoc_allocator{pool.getProtobufCAllocator()};
	auto key_bundles_array{std::unique_ptr<ProtobufCKeyBundle*[]>(new ProtobufCKeyBundle*[exported_buffers.size()])};
	//parse all the exported protobuf buffers
	size_t index{0};
	for (const auto& exported_buffer : exported_buffers) {
		key_bundles_array[index] = key_bundle__unpack(
						&pool_protoc_allocator,
						exported_buffer.size(),
						byte_to_uchar(exported_buffer.data()));
		if (key_bundles_array[index] == nullptr) {
			throw Molch::Exception{status_type::PROTOBUF_UNPACK_ERROR, "Failed to unpack key bundle."};
		}

		index++;
	}

	//now do the actual import
	keystore = HeaderAndMessageKeyStore{{key_bundles_array.get(), exported_buffers.size()}};
}

void protobuf_empty_store(void) {
	printf("Testing im-/export of empty header and message keystore.\n");

	HeaderAndMessageKeyStore store;

	//export it
	ProtobufPool pool;
	auto exported_bundles{store.exportProtobuf(pool)};

	if (!exported_bundles.empty()) {
		throw Molch::Exception{status_type::INCORRECT_DATA, "Exported data is not empty."};
	}

	//import it
	store = HeaderAndMessageKeyStore{exported_bundles};

	printf("Successful.\n");
}

int main(void) {
	try {
		if (sodium_init() == -1) {
			throw Molch::Exception{status_type::INIT_ERROR, "Failed to initialize libsodium."};
		}

		// buffers for exporting protobuf-c
		std::vector<Buffer> protobuf_export_buffers;
		std::vector<Buffer> protobuf_second_export_buffers;

		//initialise message keystore
		HeaderAndMessageKeyStore keystore;
		assert(keystore.keys.size() == 0);

		//add keys to the keystore
		for (size_t i{0}; i < 6; i++) {
			//create new keys
			HeaderKey header_key;
			header_key.fillRandom();
			MessageKey message_key;
			message_key.fillRandom();

			//print the new header key
			printf("New Header Key No. %zu:\n", i);
			header_key.printHex(std::cout) << std::endl;

			//print the new message key
			printf("New message key No. %zu:\n", i);
			message_key.printHex(std::cout) << std::endl;

			//add keys to the keystore
			keystore.add(header_key, message_key);
			message_key.clear();
			header_key.clear();

			keystore.print(std::cout);

			assert(keystore.keys.size() == (i + 1));
		}

		//Protobuf-C export
		printf("Test Protobuf-C export:\n");
		protobuf_export(keystore, protobuf_export_buffers);

		puts("[\n");
		for (const auto& buffer : protobuf_export_buffers) {
			buffer.printHex(std::cout) << ",\n";
		}
		puts("]\n\n");

		printf("Import from Protobuf-C\n");
		keystore.keys.clear();
		ProtobufPool pool;
		protobuf_import(pool, keystore, protobuf_export_buffers);

		//now export again
		printf("Export imported as Protobuf-C\n");
		protobuf_export(keystore, protobuf_second_export_buffers);

		//compare both exports
		printf("Compare\n");
		if (protobuf_export_buffers.size() != protobuf_second_export_buffers.size()) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Both exports contain different amounts of keys."};
		}
		for (size_t index = 0; index < protobuf_export_buffers.size(); index++) {
			if (protobuf_export_buffers[index] != protobuf_second_export_buffers[index]) {
				throw Molch::Exception{status_type::INCORRECT_DATA, "First and second export are not identical."};
			}
		}

		//remove key from the head
		printf("Remove head!\n");
		keystore.keys.erase(std::cbegin(keystore.keys));
		assert(keystore.keys.size() == (protobuf_export_buffers.size() - 1));
		keystore.print(std::cout);

		//remove key from the tail
		printf("Remove Tail:\n");
		keystore.keys.pop_back();
		assert(keystore.keys.size() == (protobuf_export_buffers.size() - 2));
		keystore.print(std::cout);

		//remove from inside
		printf("Remove from inside:\n");
		keystore.keys.erase(std::cbegin(keystore.keys) + 1);
		assert(keystore.keys.size() == (protobuf_export_buffers.size() - 3));
		keystore.print(std::cout);

		protobuf_empty_store();

		//clear the keystore
		printf("Clear the keystore:\n");
		keystore.keys.clear();
		assert(keystore.keys.size() == 0);
		keystore.print(std::cout);
	} catch (const Molch::Exception& exception) {
		exception.print(std::cerr) << std::endl;
		return EXIT_FAILURE;
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
