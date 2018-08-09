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
#include "../lib/destroyers.hpp"
#include "utils.hpp"
#include "common.hpp"

using namespace Molch;

static void protobuf_export(
			HeaderAndMessageKeyStore& keystore,
			std::vector<Buffer>& export_buffers) {
	Arena pool;
	auto exported_bundles{keystore.exportProtobuf(pool)};

	export_buffers = std::vector<Buffer>();

	//create all the export buffers
	for (const auto& key_bundle : exported_bundles) {
		auto export_size{molch__protobuf__key_bundle__get_packed_size(key_bundle)};
		Buffer export_buffer{export_size, 0};
		TRY_VOID(export_buffer.setSize(molch__protobuf__key_bundle__pack(key_bundle, byte_to_uchar(export_buffer.data()))));
		if (export_buffer.size() != export_size) {
			throw Molch::Exception{status_type::PROTOBUF_PACK_ERROR, "Packed buffer has incorrect length."};
		}
		export_buffers.push_back(export_buffer);
	}
}

static void protobuf_import(
		Arena& pool,
		HeaderAndMessageKeyStore& keystore,
		const std::vector<Buffer>& exported_buffers) {
	auto pool_protoc_allocator{pool.getProtobufCAllocator()};
	auto key_bundles_array{std::unique_ptr<ProtobufCKeyBundle*[]>(new ProtobufCKeyBundle*[exported_buffers.size()])};
	//parse all the exported protobuf buffers
	size_t index{0};
	for (const auto& exported_buffer : exported_buffers) {
		key_bundles_array[index] = molch__protobuf__key_bundle__unpack(
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

static void protobuf_empty_store() {
	printf("Testing im-/export of empty header and message keystore.\n");

	HeaderAndMessageKeyStore store;

	//export it
	Arena pool;
	auto exported_bundles{store.exportProtobuf(pool)};

	if (!exported_bundles.empty()) {
		throw Molch::Exception{status_type::INCORRECT_DATA, "Exported data is not empty."};
	}

	//import it
	store = HeaderAndMessageKeyStore{exported_bundles};

	printf("Successful.\n");
}

static void testSortingAndDeprecation() {
	HeaderAndMessageKeyStore sorted_store;

	std::cout << "Check if Keystore is sorted properly" << std::endl;
	for (seconds index{10}; index > 0s; --index) {
		EmptyableHeaderKey header_key;
		header_key.fillRandom();
		MessageKey message_key;
		message_key.fillRandom();
		sorted_store.add(HeaderAndMessageKey{header_key, message_key, index});
	}

	std::cout << "Sorted store:" << std::endl;
	sorted_store.print(std::cout) << std::endl;

	auto last_date{0s};
	for (const auto& key_bundle : sorted_store.keys()) {
		if (last_date >= key_bundle.expirationDate()) {
			throw Exception{status_type::INCORRECT_DATA, "The header and message keystore ist not sorted."};
		}

		last_date = key_bundle.expirationDate();
	}

	std::cout << "Test removing outdated keys:" << std::endl;
	sorted_store.add(HeaderAndMessageKey(EmptyableHeaderKey{}, MessageKey{}));
	sorted_store.removeOutdatedAndTrimSize();
	sorted_store.print(std::cout) << std::endl;
	if (sorted_store.keys().size() != 1) {
		throw Exception{status_type::INCORRECT_DATA, "The old keys weren't removed properly."};
	}
	std::cout << "Outdated keys successfully removed" << std::endl;
}

static void testSizeLimit() {
	HeaderAndMessageKeyStore too_big;

	std::cout << "Try to make too big header and message keystore:" << std::endl;
	for (size_t i{0}; i < (2 * header_and_message_store_maximum_keys); ++i) {
		too_big.add(HeaderAndMessageKey{EmptyableHeaderKey{}, MessageKey{}});
	}

	if (too_big.keys().size() != header_and_message_store_maximum_keys) {
		throw Exception{status_type::INCORRECT_DATA, "The key store is too big (1)."};
	}

	too_big.add(too_big);
	if (too_big.keys().size() != header_and_message_store_maximum_keys) {
		throw Exception{status_type::INCORRECT_DATA, "The key store is too big (2)."};
	}

	std::cout << "Successfully prevented too big keystore" << std::endl;
}

int main() {
	try {
		TRY_VOID(Molch::sodium_init());

		// buffers for exporting protobuf-c
		std::vector<Buffer> protobuf_export_buffers;
		std::vector<Buffer> protobuf_second_export_buffers;

		//initialise message keystore
		HeaderAndMessageKeyStore keystore;
		assert(keystore.keys().empty());

		//add keys to the keystore
		for (size_t i{0}; i < 6; i++) {
			//create new keys
			EmptyableHeaderKey header_key;
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

			keystore.print(std::cout);

			assert(keystore.keys().size() == (i + 1));
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
		keystore.clear();
		Arena pool;
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
		keystore.remove(0);
		assert(keystore.keys().size() == (protobuf_export_buffers.size() - 1));
		keystore.print(std::cout);

		//remove key from the tail
		printf("Remove Tail:\n");
		keystore.remove(keystore.keys().size() - 1);
		assert(keystore.keys().size() == (protobuf_export_buffers.size() - 2));
		keystore.print(std::cout);

		//remove from inside
		printf("Remove from inside:\n");
		keystore.remove(1);
		assert(keystore.keys().size() == (protobuf_export_buffers.size() - 3));
		keystore.print(std::cout);

		protobuf_empty_store();

		//clear the keystore
		printf("Clear the keystore:\n");
		keystore.clear();
		assert(keystore.keys().empty());
		keystore.print(std::cout);

		testSortingAndDeprecation();
		testSizeLimit();
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
