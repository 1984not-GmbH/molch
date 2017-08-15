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

extern "C" {
	#include <key_bundle.pb-c.h>
}

#include "../lib/header-and-message-keystore.hpp"
#include "../lib/zeroed_malloc.hpp"
#include "../lib/molch-exception.hpp"
#include "../lib/destroyers.hpp"
#include "utils.hpp"
#include "common.hpp"

static void free_keybundle_array(KeyBundle**& bundles, size_t length) {
	if (bundles != nullptr) {
		for (size_t i = 0; i < length; i++) {
			if (bundles[i] != nullptr) {
				key_bundle__free_unpacked(bundles[i], &protobuf_c_allocators);
				bundles[i] = nullptr;
			}
		}
		zeroed_free_and_null_if_valid(bundles);
	}
}

static void protobuf_export(
			HeaderAndMessageKeyStore& keystore,
			std::vector<Buffer>& export_buffers) {
	KeyBundle** key_bundles = nullptr;
	size_t bundles_size;

	try {
		keystore.exportProtobuf(key_bundles, bundles_size);

		export_buffers = std::vector<Buffer>();

		//create all the export buffers
		for (size_t i = 0; i < bundles_size; i++) {
			size_t export_size = key_bundle__get_packed_size(key_bundles[i]);
			Buffer export_buffer(export_size, 0);
			exception_on_invalid_buffer(export_buffer);

			export_buffer.content_length = key_bundle__pack(key_bundles[i], export_buffer.content);
			if (export_buffer.content_length != export_size) {
				throw MolchException(PROTOBUF_PACK_ERROR, "Packed buffer has incorrect length.");
			}
			export_buffers.push_back(export_buffer);
		}
	} catch (const std::exception& exception) {
		free_keybundle_array(key_bundles, bundles_size);

		throw exception;
	}

	free_keybundle_array(key_bundles, bundles_size);
}

static void protobuf_import(
		HeaderAndMessageKeyStore& keystore,
		const std::vector<Buffer>& exported_buffers) {
	auto key_bundles = std::vector<std::unique_ptr<KeyBundle,KeyBundleDeleter>>();
	key_bundles.reserve(exported_buffers.size());

	//parse all the exported protobuf buffers
	for (const auto& exported_buffer : exported_buffers) {
		auto key_bundle = std::unique_ptr<KeyBundle,KeyBundleDeleter>(
					key_bundle__unpack(
						&protobuf_c_allocators,
						exported_buffer.content_length,
						exported_buffer.content));
		if (!key_bundle) {
			throw MolchException(PROTOBUF_UNPACK_ERROR, "Failed to unpack key bundle.");
		}

		key_bundles.push_back(std::move(key_bundle));
	}

	auto key_bundles_array = std::unique_ptr<KeyBundle*[]>(new KeyBundle*[exported_buffers.size()]);
	for (size_t i = 0; i < exported_buffers.size(); i++) {
		key_bundles_array[i] = key_bundles[i].get();
	}

	//now do the actual import
	keystore = HeaderAndMessageKeyStore(key_bundles_array.get(), exported_buffers.size());
}

void protobuf_empty_store(void) {
	printf("Testing im-/export of empty header and message keystore.\n");

	HeaderAndMessageKeyStore store;

	KeyBundle **exported = nullptr;
	size_t exported_length = 0;

	//export it
	store.exportProtobuf(exported, exported_length);

	if ((exported != nullptr) || (exported_length != 0)) {
		throw MolchException(INCORRECT_DATA, "Exported data is not empty.");
	}

	//import it
	store = HeaderAndMessageKeyStore(exported, exported_length);

	printf("Successful.\n");
}

int main(void) {
	try {
		if (sodium_init() == -1) {
			throw MolchException(INIT_ERROR, "Failed to initialize libsodium.");
		}

		//buffer for message keys
		Buffer header_key(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
		Buffer message_key(MESSAGE_KEY_SIZE, MESSAGE_KEY_SIZE);

		// buffers for exporting protobuf-c
		std::vector<Buffer> protobuf_export_buffers;
		std::vector<Buffer> protobuf_second_export_buffers;

		//initialise message keystore
		HeaderAndMessageKeyStore keystore;
		assert(keystore.keys.size() == 0);

		int status_int = 0;
		exception_on_invalid_buffer(header_key);
		exception_on_invalid_buffer(message_key);
		//add keys to the keystore
		for (size_t i = 0; i < 6; i++) {
			//create new keys
			status_int = header_key.fillRandom(header_key.getBufferLength());
			if (status_int != 0) {
				throw MolchException(KEYGENERATION_FAILED, "Failed to create header key.");
			}
			status_int = message_key.fillRandom(message_key.getBufferLength());
			if (status_int != 0) {
				throw MolchException(KEYGENERATION_FAILED, "Failed to create header key.");
			}

			//print the new header key
			printf("New Header Key No. %zu:\n", i);
			std::cout << header_key.toHex();
			putchar('\n');

			//print the new message key
			printf("New message key No. %zu:\n", i);
			std::cout << message_key.toHex();
			putchar('\n');

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
			std::cout << buffer.toHex();
			puts(",\n");
		}
		puts("]\n\n");

		printf("Import from Protobuf-C\n");
		keystore.keys.clear();
		protobuf_import(keystore, protobuf_export_buffers);

		//now export again
		printf("Export imported as Protobuf-C\n");
		protobuf_export(keystore, protobuf_second_export_buffers);

		//compare both exports
		printf("Compare\n");
		if (protobuf_export_buffers.size() != protobuf_second_export_buffers.size()) {
			throw MolchException(INCORRECT_DATA, "Both exports contain different amounts of keys.");
		}
		for (size_t index = 0; index < protobuf_export_buffers.size(); index++) {
			if (protobuf_export_buffers[index].compare(&protobuf_second_export_buffers[index]) != 0) {
				throw MolchException(INCORRECT_DATA, "First and second export are not identical.");
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
	} catch (const MolchException& exception) {
		exception.print(std::cerr) << std::endl;
		return EXIT_FAILURE;
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
