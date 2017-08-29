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

#include "../lib/user-store.hpp"
#include "../lib/destroyers.hpp"
#include "utils.hpp"
#include "common.hpp"

using namespace Molch;

static std::vector<Buffer> protobuf_export(UserStore& store) {
	ProtobufPool pool;
	auto exported_users{store.exportProtobuf(pool)};
	auto users{exported_users.data()};
	auto length{narrow(exported_users.size())};

	std::vector<Buffer> export_buffers;
	export_buffers.reserve(length);

	//unpack all the users
	for (size_t i{0}; i < length; i++) {
		auto unpacked_size{user__get_packed_size(users[i])};
		export_buffers.push_back(Buffer(unpacked_size, 0));
		export_buffers.back().size = user__pack(users[i], byte_to_uchar(export_buffers.back().content));
	}

	return export_buffers;
}

UserStore protobuf_import(ProtobufPool& pool, const std::vector<Buffer> buffers) {
	//allocate the user array output array
	std::unique_ptr<ProtobufCUser*[]> user_array;
	if (!buffers.empty()) {
		user_array = std::unique_ptr<ProtobufCUser*[]>(new ProtobufCUser*[buffers.size()]);
	}

	auto pool_protoc_allocator{pool.getProtobufCAllocator()};
	//unpack all the conversations
	size_t index{0};
	for (const auto& buffer : buffers) {
		user_array[index] = user__unpack(&pool_protoc_allocator, buffer.size, byte_to_uchar(buffer.content));
		if (user_array[index] == nullptr) {
			throw Molch::Exception{status_type::PROTOBUF_UNPACK_ERROR, "Failed to unpack user from protobuf."};
		}
		index++;
	}

	//import
	return UserStore({user_array.get(), narrow(buffers.size())});
}

void protobuf_empty_store(void) {
	printf("Testing im-/export of empty user store.\n");
	UserStore store;

	//export it
	ProtobufPool pool;
	auto exported{store.exportProtobuf(pool)};

	if (!exported.empty()) {
		throw Molch::Exception{status_type::INCORRECT_DATA, "Exported data is not empty."};
	}

	//import it
	store = UserStore(exported);
	printf("Successful.\n");
}

int main(void) {
	try {
		if (sodium_init() == -1) {
			throw Molch::Exception{status_type::INIT_ERROR, "Failed to initialize libsodium."};
		}

		//create a user_store
		UserStore store;

		//check the content
		auto list{store.list()};
		if (list.size != 0) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "List of users is not empty."};
		}
		list.clear();

		//create alice
		PublicSigningKey alice_public_signing_key;
		store.add(Molch::User(&alice_public_signing_key));
		{
			auto alice_user{store.find(alice_public_signing_key)};
			MasterKeys::Unlocker unlocker{alice_user->master_keys};
			alice_user->master_keys.print(std::cout) << std::endl;
		}
		printf("Successfully created Alice to the user store.\n");

		//check length of the user store
		if (store.size() != 1) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "User store has incorrect length."};
		}
		printf("Length of the user store matches.");

		//list user store
		list = store.list();
		if (list.compareToRaw(alice_public_signing_key.span()) != 0) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Failed to list users."};
		}
		list.clear();
		printf("Successfully listed users.\n");

		//create bob
		PublicSigningKey bob_public_signing_key;
		store.add(Molch::User(&bob_public_signing_key));
		printf("Successfully created Bob.\n");

		//check length of the user store
		if (store.size() != 2) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "User store has incorrect length."};
		}
		printf("Length of the user store matches.");

		//list user store
		list = store.list();
		if ((list.compareToRawPartial(0, alice_public_signing_key.span(), 0, PUBLIC_MASTER_KEY_SIZE) != 0)
				|| (list.compareToRawPartial(PUBLIC_MASTER_KEY_SIZE, bob_public_signing_key.span(), 0, PUBLIC_MASTER_KEY_SIZE) != 0)) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Failed to list users."};
		}
		list.clear();
		printf("Successfully listed users.\n");

		//create charlie
		PublicSigningKey charlie_public_signing_key;
		store.add(Molch::User(&charlie_public_signing_key));
		printf("Successfully added Charlie to the user store.\n");

		//check length of the user store
		if (store.size() != 3) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "User store has incorrect length."};
		}
		printf("Length of the user store matches.");

		//list user store
		list = store.list();
		if ((list.compareToRawPartial(0, alice_public_signing_key.span(), 0, PUBLIC_MASTER_KEY_SIZE) != 0)
				|| (list.compareToRawPartial(PUBLIC_MASTER_KEY_SIZE, bob_public_signing_key.span(), 0, PUBLIC_MASTER_KEY_SIZE) != 0)
				|| (list.compareToRawPartial(2 * PUBLIC_MASTER_KEY_SIZE, charlie_public_signing_key.span(), 0, PUBLIC_MASTER_KEY_SIZE) != 0)) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Failed to list users."};
		}
		list.clear();
		printf("Successfully listed users.\n");

		//find node
		{
			Molch::User *bob_node{nullptr};
			bob_node = store.find(bob_public_signing_key);
			if (bob_node == nullptr) {
				throw Molch::Exception{status_type::NOT_FOUND, "Failed to find Bob's node."};
			}
			printf("Node found.\n");

			if (bob_node->public_signing_key != bob_public_signing_key) {
				throw Molch::Exception{status_type::INCORRECT_DATA, "Bob's data from the user store doesn't match."};
			}
			printf("Data from the node matches.\n");

			//remove a user identified by it's key
			store.remove(bob_public_signing_key);
			//check the length
			if (store.size() != 2) {
				throw Molch::Exception{status_type::INCORRECT_DATA, "User store has incorrect length."};
			}
			printf("Length of the user store matches.");
			//check the user list
			list = store.list();
			if ((list.compareToRawPartial(0, alice_public_signing_key.span(), 0, PUBLIC_MASTER_KEY_SIZE) != 0)
					|| (list.compareToRawPartial(PUBLIC_MASTER_KEY_SIZE, charlie_public_signing_key.span(), 0, PUBLIC_MASTER_KEY_SIZE) != 0)) {
				throw Molch::Exception{status_type::INCORRECT_DATA, "Removing user failed."};
			}
			list.clear();
			printf("Successfully removed user.\n");

			//recreate bob
			store.add(Molch::User(&bob_public_signing_key));
			printf("Successfully recreated Bob.\n");

			//now find bob again
			bob_node = store.find(bob_public_signing_key);
			if (bob_node == nullptr) {
				throw Molch::Exception{status_type::NOT_FOUND, "Failed to find Bob's node."};
			}
			printf("Bob's node found again.\n");

			//remove bob by it's node
			store.remove(bob_node);
			//check the length
			if (store.size() != 2) {
				throw Molch::Exception{status_type::INCORRECT_DATA, "User store has incorrect length."};
			}
			printf("Length of the user store matches.");
		}


		//test Protobuf-C export
		printf("Export to Protobuf-C\n");
		auto protobuf_export_buffers{protobuf_export(store)};

		//print the exported data
		puts("[\n");
		for (size_t i{0}; i < protobuf_export_buffers.size(); i++) {
			protobuf_export_buffers[i].printHex(std::cout);
			puts(",\n");
		}
		puts("]\n\n");

		store.clear();

		//import from Protobuf-C
		printf("Import from Protobuf-C\n");
		ProtobufPool pool;
		store = protobuf_import(pool, protobuf_export_buffers);

		//export again
		printf("Export to Protobuf-C\n");
		auto protobuf_second_export_buffers{protobuf_export(store)};

		//compare
		if (protobuf_export_buffers.size() != protobuf_second_export_buffers.size()) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Both exports have different sizes."};
		}
		for (size_t i{0}; i < protobuf_export_buffers.size(); i++) {
			if (protobuf_export_buffers[i] != protobuf_second_export_buffers[i]) {
				throw Molch::Exception{status_type::INCORRECT_DATA, "Buffers don't match."};
			}
		}
		printf("Both exports match.\n");

		//check the user list
		list = store.list();
		if ((list.compareToRawPartial(0, alice_public_signing_key.span(), 0, PUBLIC_MASTER_KEY_SIZE) != 0)
				|| (list.compareToRawPartial(PUBLIC_MASTER_KEY_SIZE, charlie_public_signing_key.span(), 0, PUBLIC_MASTER_KEY_SIZE) != 0)) {
			throw Molch::Exception{status_type::REMOVE_ERROR, "Removing user failed."};
		}
		list.clear();
		printf("Successfully removed user.\n");

		//clear the user store
		store.clear();
		//check the length
		if (store.size() != 0) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "User store has incorrect length."};
		}
		printf("Successfully cleared user store.\n");

		protobuf_empty_store();
	} catch (const Molch::Exception& exception) {
		exception.print(std::cerr) << std::endl;
		return EXIT_FAILURE;
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
