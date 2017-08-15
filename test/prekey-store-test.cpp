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
#include <iostream>
#include <exception>

#include "../lib/prekey-store.hpp"
#include "../lib/constants.h"
#include "../lib/molch-exception.hpp"
#include "../lib/destroyers.hpp"
#include "utils.hpp"

static void free_prekey_array(Prekey**& prekeys, size_t length) {
	if (prekeys != nullptr) {
		for (size_t i = 0; i < length; i++) {
			if (prekeys[i] != nullptr) {
				prekey__free_unpacked(prekeys[i], &protobuf_c_allocators);
				prekeys[i] = nullptr;
			}
		}
		zeroed_free_and_null_if_valid(prekeys);
	}
}

static void protobuf_export(
		PrekeyStore& store,
		std::vector<Buffer>& key_buffers,
		std::vector<Buffer>& deprecated_key_buffers) {
	Prekey** keypairs = nullptr;
	Prekey** deprecated_keypairs = nullptr;
	size_t keypairs_size;
	size_t deprecated_keypairs_size;

	try {
		store.exportProtobuf(
			keypairs,
			keypairs_size,
			deprecated_keypairs,
			deprecated_keypairs_size);

		//export all the keypairs
		key_buffers = std::vector<Buffer>();
		key_buffers.reserve(keypairs_size);
		for (size_t i = 0; i < keypairs_size; i++) {
			size_t export_size = prekey__get_packed_size(keypairs[i]);
			key_buffers.emplace_back(export_size, 0);
			exception_on_invalid_buffer(key_buffers[i]);

			key_buffers[i].content_length = prekey__pack(keypairs[i], key_buffers[i].content);
		}

		//export all the deprecated keypairs
		deprecated_key_buffers = std::vector<Buffer>();
		deprecated_key_buffers.reserve(deprecated_keypairs_size);
		for (size_t i = 0; i < deprecated_keypairs_size; i++) {
			size_t export_size = prekey__get_packed_size(deprecated_keypairs[i]);
			deprecated_key_buffers.emplace_back(export_size, 0);
			exception_on_invalid_buffer(deprecated_key_buffers[i]);

			deprecated_key_buffers[i].content_length = prekey__pack(deprecated_keypairs[i], deprecated_key_buffers[i].content);
		}
	} catch (const std::exception& exception) {
		free_prekey_array(keypairs, keypairs_size);
		free_prekey_array(deprecated_keypairs, deprecated_keypairs_size);

		throw exception;
	}

	free_prekey_array(keypairs, keypairs_size);
	free_prekey_array(deprecated_keypairs, deprecated_keypairs_size);
}

static void protobuf_import(
		std::unique_ptr<PrekeyStore>& store,
		const std::vector<Buffer>& keypair_buffers,
		const std::vector<Buffer>& deprecated_keypair_buffers) {
	//parse the normal prekey protobufs
	auto keypairs = std::vector<std::unique_ptr<Prekey,PrekeyDeleter>>();
	keypairs.reserve(keypair_buffers.size());
	for (const auto& keypair_buffer : keypair_buffers) {
		auto keypair = std::unique_ptr<Prekey,PrekeyDeleter>(
			prekey__unpack(
				&protobuf_c_allocators,
				keypair_buffer.content_length,
				keypair_buffer.content));
		if (!keypair) {
			throw MolchException(PROTOBUF_UNPACK_ERROR, "Failed to unpack prekey from protobuf.");
		}

		keypairs.push_back(std::move(keypair));
	}

	//parse the deprecated prekey protobufs
	auto deprecated_keypairs = std::vector<std::unique_ptr<Prekey,PrekeyDeleter>>();
	deprecated_keypairs.reserve(deprecated_keypair_buffers.size());
	for (const auto& keypair_buffer : deprecated_keypair_buffers) {
		auto keypair = std::unique_ptr<Prekey,PrekeyDeleter>(
			prekey__unpack(
				&protobuf_c_allocators,
				keypair_buffer.content_length,
				keypair_buffer.content));
		if (!keypair) {
			throw MolchException(PROTOBUF_UNPACK_ERROR, "Failed to unpack deprecated prekey from protobuf.");
		}

		deprecated_keypairs.push_back(std::move(keypair));
	}

	//make arrays with the pointers
	auto keypairs_array = std::unique_ptr<Prekey*[]>(new Prekey*[keypair_buffers.size()]);
	for (size_t i = 0; i < keypair_buffers.size(); i++) {
		keypairs_array[i] = keypairs[i].get();
	}
	auto deprecated_keypairs_array = std::unique_ptr<Prekey*[]>(new Prekey*[deprecated_keypair_buffers.size()]);
	for (size_t i = 0; i < deprecated_keypair_buffers.size(); i++) {
		deprecated_keypairs_array[i] = deprecated_keypairs[i].get();
	}

	//now do the import
	store.reset(new PrekeyStore(
		keypairs_array.get(),
		keypairs.size(),
		deprecated_keypairs_array.get(),
		deprecated_keypairs.size()));
}

void protobuf_no_deprecated_keys(void) {
	printf("Testing im-/export of prekey store without deprecated keys.\n");

	Prekey **exported = nullptr;
	size_t exported_length = 0;
	try {
		Prekey **deprecated = nullptr;
		size_t deprecated_length = 0;

		PrekeyStore store;

		//export it
		store.exportProtobuf(exported, exported_length, deprecated, deprecated_length);

		if ((deprecated != nullptr) || (deprecated_length != 0)) {
			throw MolchException(INCORRECT_DATA, "Exported deprecated prekeys are not empty.");
		}

		//import it
		store = PrekeyStore(
			exported,
			exported_length,
			deprecated,
			deprecated_length);

		printf("Successful.\n");
	} catch (const std::exception& exception) {
		free_prekey_array(exported, exported_length);

		throw exception;
	}

	free_prekey_array(exported, exported_length);
}

int main(void) {
	try {
		if (sodium_init() == -1) {
			throw MolchException(INIT_ERROR, "Failed to initialize libsodium.");
		}

		Buffer public_prekey(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
		Buffer private_prekey1(PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
		Buffer private_prekey2(PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
		Buffer prekey_list(PREKEY_AMOUNT * PUBLIC_KEY_SIZE, PREKEY_AMOUNT * PUBLIC_KEY_SIZE);


		auto store = std::make_unique<PrekeyStore>();

		exception_on_invalid_buffer(public_prekey);
		exception_on_invalid_buffer(private_prekey1);
		exception_on_invalid_buffer(private_prekey2);
		exception_on_invalid_buffer(prekey_list);


		store->list(prekey_list);
		printf("Prekey list:\n");
		std::cout << prekey_list.toHex();
		putchar('\n');

		//compare the public keys with the ones in the prekey store
		for (size_t i = 0; i < PREKEY_AMOUNT; i++) {
			if (prekey_list.comparePartial(PUBLIC_KEY_SIZE * i, &(*store->prekeys)[i].public_key, 0, PUBLIC_KEY_SIZE) != 0) {
				throw MolchException(INCORRECT_DATA, "Key list doesn't match the prekey store.");
			}
		}
		printf("Prekey list matches the prekey store!\n");

		//get a private key
		const size_t prekey_index = 10;
		if (public_prekey.cloneFrom(&(*store->prekeys)[prekey_index].public_key) != 0) {
			throw MolchException(BUFFER_ERROR, "Failed to clone public key.");
		}

		store->getPrekey(public_prekey, private_prekey1);
		printf("Get a Prekey:\n");
		printf("Public key:\n");
		std::cout << public_prekey.toHex();
		printf("Private key:\n");
		std::cout << private_prekey1.toHex();
		putchar('\n');

		if (store->deprecated_prekeys.empty()) {
			throw MolchException(GENERIC_ERROR, "Failed to deprecate requested key.");
		}

		if ((public_prekey.compare(&store->deprecated_prekeys[0].public_key) != 0)
				|| (private_prekey1.compare(&store->deprecated_prekeys[0].private_key) != 0)) {
			throw MolchException(INCORRECT_DATA, "Deprecated key is incorrect.");
		}

		if ((*store->prekeys)[prekey_index].public_key.compare(&public_prekey) == 0) {
			throw MolchException(KEYGENERATION_FAILED, "Failed to generate new key for deprecated one.");
		}
		printf("Successfully deprecated requested key!\n");

		//check if the prekey can be obtained from the deprecated keys
		store->getPrekey(public_prekey, private_prekey2);

		if (private_prekey1.compare(&private_prekey2) != 0) {
			throw MolchException(INCORRECT_DATA, "Prekey from the deprecated area didn't match.");
		}
		printf("Successfully got prekey from the deprecated area!\n");

		//try to get a nonexistent key
		if (public_prekey.fillRandom(PUBLIC_KEY_SIZE) != 0) {
			throw MolchException(KEYGENERATION_FAILED, "Failed to generate invalid public prekey.");
		}
		bool found = true;
		try {
			store->getPrekey(public_prekey, private_prekey1);
		} catch (const MolchException& exception) {
			found = false;
		}
		if (found) {
			throw MolchException(GENERIC_ERROR, "Didn't complain about invalid public key.");
		}
		printf("Detected invalid public prekey!\n");

		//Protobuf-C export
		printf("Protobuf-C export\n");
		std::vector<Buffer> protobuf_export_prekeys_buffers;
		std::vector<Buffer> protobuf_export_deprecated_prekeys_buffers;
		protobuf_export(
			*store,
			protobuf_export_prekeys_buffers,
			protobuf_export_deprecated_prekeys_buffers);

		printf("Prekeys:\n");
		puts("[\n");
		for (size_t i = 0; i < protobuf_export_prekeys_buffers.size(); i++) {
			std::cout << protobuf_export_prekeys_buffers[i].toHex();
			puts(",\n");
		}
		puts("]\n\n");

		printf("Deprecated Prekeys:\n");
		puts("[\n");
		for (size_t i = 0; i < protobuf_export_deprecated_prekeys_buffers.size(); i++) {
			std::cout << protobuf_export_deprecated_prekeys_buffers[i].toHex();
			puts(",\n");
		}
		puts("]\n\n");

		store.reset();

		printf("Import from Protobuf-C\n");
		protobuf_import(
			store,
			protobuf_export_prekeys_buffers,
			protobuf_export_deprecated_prekeys_buffers);

		printf("Protobuf-C export again\n");
		std::vector<Buffer> protobuf_second_export_prekeys_buffers;
		std::vector<Buffer> protobuf_second_export_deprecated_prekeys_buffers;
		protobuf_export(
			*store,
			protobuf_second_export_prekeys_buffers,
			protobuf_second_export_deprecated_prekeys_buffers);

		//compare both prekey lists
		printf("Compare normal prekeys\n");
		if (protobuf_export_prekeys_buffers.size() != protobuf_second_export_prekeys_buffers.size()) {
			throw MolchException(INCORRECT_DATA, "Both prekey exports contain different amounts of keys.");
		}
		for (size_t i = 0; i < protobuf_export_prekeys_buffers.size(); i++) {
			if (protobuf_export_prekeys_buffers[i].compare(&protobuf_second_export_prekeys_buffers[i]) != 0) {
				throw MolchException(INCORRECT_DATA, "First and second prekey export are not identical.");
			}
		}

		//compare both deprecated prekey lists
		printf("Compare deprecated prekeys\n");
		if (protobuf_export_deprecated_prekeys_buffers.size() != protobuf_second_export_deprecated_prekeys_buffers.size()) {
			throw MolchException(INCORRECT_DATA, "Both depcated prekey exports contain different amounts of keys.");
		}
		for (size_t i = 0; i < protobuf_export_deprecated_prekeys_buffers.size(); i++) {
			if (protobuf_export_deprecated_prekeys_buffers[i].compare(&protobuf_second_export_deprecated_prekeys_buffers[i]) != 0) {
				throw MolchException(INCORRECT_DATA, "First and second deprecated prekey export are not identical.");
			}
		}

		//test the automatic deprecation of old keys
		if (public_prekey.cloneFrom(&(*store->prekeys)[PREKEY_AMOUNT-1].public_key) != 0) {
			throw MolchException(BUFFER_ERROR, "Failed to clone public key.");
		}

		(*store->prekeys)[PREKEY_AMOUNT-1].expiration_date -= 365 * 24 * 3600; //one year
		store->oldest_expiration_date = (*store->prekeys)[PREKEY_AMOUNT - 1].expiration_date;

		store->rotate();

		if (store->deprecated_prekeys.back().public_key.compare(&public_prekey) != 0) {
			throw MolchException(GENERIC_ERROR, "Failed to deprecate outdated key.");
		}
		printf("Successfully deprecated outdated key!\n");

		//test the automatic removal of old deprecated keys!
		if (public_prekey.cloneFrom(&store->deprecated_prekeys[1].public_key) != 0) {
			throw MolchException(BUFFER_ERROR, "Failed to clone public key.");
		}

		store->deprecated_prekeys[1].expiration_date -= 24 * 3600;
		store->oldest_deprecated_expiration_date = store->deprecated_prekeys[1].expiration_date;

		store->rotate();

		if (store->deprecated_prekeys.size() != 1) {
			throw MolchException(GENERIC_ERROR, "Failed to remove outdated key.");
		}
		printf("Successfully removed outdated deprecated key!\n");

		protobuf_no_deprecated_keys();
	} catch (const MolchException& exception) {
		exception.print(std::cerr) << std::endl;
		return EXIT_FAILURE;
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
