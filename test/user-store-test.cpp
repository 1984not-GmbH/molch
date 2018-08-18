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
	Arena pool;
	TRY_WITH_RESULT(exported_users_result, store.exportProtobuf(pool));
	const auto& exported_users{exported_users_result.value()};
	auto users{exported_users.data()};
	auto length{exported_users.size()};

	std::vector<Buffer> export_buffers;
	export_buffers.reserve(length);

	//unpack all the users
	for (size_t i{0}; i < length; i++) {
		auto unpacked_size{molch__protobuf__user__get_packed_size(users[i])};
		export_buffers.emplace_back(unpacked_size, 0);
		TRY_VOID(export_buffers.back().setSize(molch__protobuf__user__pack(users[i], byte_to_uchar(export_buffers.back().data()))));
	}

	return export_buffers;
}

static UserStore protobuf_import(Arena& pool, const std::vector<Buffer> buffers) {
	//allocate the user array output array
	std::unique_ptr<ProtobufCUser*[]> user_array;
	if (!buffers.empty()) {
		user_array = std::unique_ptr<ProtobufCUser*[]>(new ProtobufCUser*[buffers.size()]);
	}

	auto pool_protoc_allocator{pool.getProtobufCAllocator()};
	//unpack all the conversations
	size_t index{0};
	for (const auto& buffer : buffers) {
		user_array[index] = molch__protobuf__user__unpack(&pool_protoc_allocator, buffer.size(), byte_to_uchar(buffer.data()));
		if (user_array[index] == nullptr) {
			throw Molch::Exception{status_type::PROTOBUF_UNPACK_ERROR, "Failed to unpack user from protobuf."};
		}
		index++;
	}

	//import
	TRY_WITH_RESULT(imported_user_store, UserStore::import({user_array.get(), buffers.size()}));
	return std::move(imported_user_store.value());
}

static void protobuf_empty_store() {
	printf("Testing im-/export of empty user store.\n");
	UserStore store;

	//export it
	Arena arena;
	TRY_WITH_RESULT(exported_result, store.exportProtobuf(arena));
	const auto& exported{exported_result.value()};

	if (not exported.empty()) {
		throw Molch::Exception{status_type::INCORRECT_DATA, "Exported data is not empty."};
	}

	//import it
	TRY_WITH_RESULT(imported_store, UserStore::import(exported));
	printf("Successful.\n");
}

int main() {
	try {
		TRY_VOID(Molch::sodium_init());

		//create a user_store
		UserStore store;

		//check the content
		TRY_WITH_RESULT(list1_result, store.list());
		const auto& list1{list1_result.value()};
		if (not list1.empty()) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "List of users is not empty."};
		}

		//create alice
		PublicSigningKey alice_public_signing_key;
		{
			TRY_WITH_RESULT(alice_user_result, Molch::User::create());
			auto& alice_user{alice_user_result.value()};
			alice_public_signing_key = alice_user.id();
			store.add(std::move(alice_user));
			auto found_user{store.find(alice_public_signing_key)};
			MasterKeys::Unlocker unlocker{found_user->masterKeys()};
			found_user->masterKeys().print(std::cout) << std::endl;
		}
		printf("Successfully created Alice to the user store.\n");

		//check length of the user store
		if (store.size() != 1) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "User store has incorrect length."};
		}
		printf("Length of the user store matches.");

		//list user store
		TRY_WITH_RESULT(list2_result, store.list());
		const auto& list2{list2_result.value()};
		TRY_WITH_RESULT(first_comparison, list2.compareToRaw(alice_public_signing_key))
		if (!first_comparison.value()) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Failed to list users."};
		}
		printf("Successfully listed users.\n");

		//create bob
		PublicSigningKey bob_public_signing_key;
		{
			TRY_WITH_RESULT(bob_user_result, Molch::User::create());
			auto& bob_user{bob_user_result.value()};
			bob_public_signing_key = bob_user.id();
			store.add(std::move(bob_user));
		}
		printf("Successfully created Bob.\n");

		//check length of the user store
		if (store.size() != 2) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "User store has incorrect length."};
		}
		printf("Length of the user store matches.");

		//list user store
		TRY_WITH_RESULT(list3_result, store.list());
		const auto& list3{list3_result.value()};
		{
			TRY_WITH_RESULT(list_alice_comparison, list3.compareToRawPartial(0, alice_public_signing_key, 0, PUBLIC_MASTER_KEY_SIZE));
			TRY_WITH_RESULT(list_bob_comparison, list3.compareToRawPartial(PUBLIC_MASTER_KEY_SIZE, bob_public_signing_key, 0, PUBLIC_MASTER_KEY_SIZE));
			if (!list_alice_comparison.value() || !list_bob_comparison.value()) {
				throw Molch::Exception{status_type::INCORRECT_DATA, "Failed to list users."};
			}
		}
		printf("Successfully listed users.\n");

		//create charlie
		PublicSigningKey charlie_public_signing_key;
		{
			TRY_WITH_RESULT(charlie_user_result, Molch::User::create());
			auto& charlie_user{charlie_user_result.value()};
			charlie_public_signing_key = charlie_user.id();
			store.add(std::move(charlie_user));
		}
		printf("Successfully added Charlie to the user store.\n");

		//check length of the user store
		if (store.size() != 3) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "User store has incorrect length."};
		}
		printf("Length of the user store matches.");

		//list user store
		TRY_WITH_RESULT(list4_result, store.list());
		const auto& list4{list4_result.value()};
		{
			TRY_WITH_RESULT(list_alice_comparison, list4.compareToRawPartial(0, alice_public_signing_key, 0, PUBLIC_MASTER_KEY_SIZE));
			TRY_WITH_RESULT(list_bob_comparison, list4.compareToRawPartial(PUBLIC_MASTER_KEY_SIZE, bob_public_signing_key, 0, PUBLIC_MASTER_KEY_SIZE));
			TRY_WITH_RESULT(list_charlie_comparison, list4.compareToRawPartial(2 * PUBLIC_MASTER_KEY_SIZE, charlie_public_signing_key, 0, PUBLIC_MASTER_KEY_SIZE));
			if (!list_alice_comparison.value() || !list_bob_comparison.value() || !list_charlie_comparison.value()) {
				throw Molch::Exception{status_type::INCORRECT_DATA, "Failed to list users."};
			}
		}
		printf("Successfully listed users.\n");

		//find node
		{
			Molch::User *bob_node{nullptr};
			bob_node = store.find(bob_public_signing_key);
			if (bob_node == nullptr) {
				throw Molch::Exception{status_type::NOT_FOUND, "Failed to find Bob's node."};
			}
			printf("Node found.\n");

			if (bob_node->id() != bob_public_signing_key) {
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
			TRY_WITH_RESULT(list5_result, store.list());
			const auto& list5{list5_result.value()};
			{
				TRY_WITH_RESULT(list_alice_comparison, list5.compareToRawPartial(0, alice_public_signing_key, 0, PUBLIC_MASTER_KEY_SIZE));
				TRY_WITH_RESULT(list_charlie_comparison, list5.compareToRawPartial(PUBLIC_MASTER_KEY_SIZE, charlie_public_signing_key, 0, PUBLIC_MASTER_KEY_SIZE));
				if (!list_alice_comparison.value() || !list_charlie_comparison.value()) {
					throw Molch::Exception{status_type::INCORRECT_DATA, "Removing user failed."};
				}
			}
			printf("Successfully removed user.\n");

			//recreate bob
			{
				TRY_WITH_RESULT(recreated_bob_result, Molch::User::create());
				auto& recreated_bob{recreated_bob_result.value()};
				bob_public_signing_key = recreated_bob.id();
				store.add(std::move(recreated_bob));
			}
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
			std::cout << protobuf_export_buffers[i];
			puts(",\n");
		}
		puts("]\n\n");

		store.clear();

		//import from Protobuf-C
		printf("Import from Protobuf-C\n");
		Arena pool;
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
		TRY_WITH_RESULT(list6_result, store.list());
		const auto& list6{list6_result.value()};
		{
			TRY_WITH_RESULT(list_alice_comparison, list6.compareToRawPartial(0, alice_public_signing_key, 0, PUBLIC_MASTER_KEY_SIZE));
			TRY_WITH_RESULT(list_charlie_comparison, list6.compareToRawPartial(PUBLIC_MASTER_KEY_SIZE, charlie_public_signing_key, 0, PUBLIC_MASTER_KEY_SIZE));
			if (!list_alice_comparison.value() || !list_charlie_comparison.value()) {
				throw Molch::Exception{status_type::REMOVE_ERROR, "Removing user failed."};
			}
		}
		printf("Successfully removed user.\n");

		//clear the user store
		store.clear();
		//check the length
		if (store.size() != 0) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "User store has incorrect length."};
		}
		printf("Successfully cleared user store.\n");

		protobuf_empty_store();
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
