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

static void free_user_array(User**& users, size_t length) {
	if (users != nullptr) {
		for (size_t i = 0; i < length; i++) {
			if (users[i] != nullptr) {
				user__free_unpacked(users[i], &protobuf_c_allocators);
				users[i] = nullptr;
			}
		}
		zeroed_free_and_null_if_valid(users);
	}
}

static std::vector<Buffer> protobuf_export(UserStore& store) {
	User** users = nullptr;
	size_t length = 0;

	std::vector<Buffer> export_buffers;

	try {
		store.exportProtobuf(users, length);

		export_buffers.reserve(length);

		//unpack all the users
		for (size_t i = 0; i < length; i++) {
			size_t unpacked_size = user__get_packed_size(users[i]);
			export_buffers.push_back(Buffer(unpacked_size, 0));
			exception_on_invalid_buffer(export_buffers.back());

			export_buffers.back().content_length = user__pack(users[i], export_buffers.back().content);
		}
	} catch (const std::exception& exception) {
		free_user_array(users, length);
		throw exception;
	}

	free_user_array(users, length);
	return export_buffers;
}

UserStore protobuf_import(const std::vector<Buffer> buffers) {
	auto users = std::vector<std::unique_ptr<User,UserDeleter>>();
	users.reserve(buffers.size());

	//unpack all the conversations
	for (const auto& buffer : buffers) {
		users.push_back(std::unique_ptr<User,UserDeleter>(
					user__unpack(&protobuf_c_allocators, buffer.content_length, buffer.content)));
		if (!users.back()) {
			throw MolchException(PROTOBUF_UNPACK_ERROR, "Failed to unpack user from protobuf.");
		}
	}

	//allocate the user array output array
	std::unique_ptr<User*[]> user_array;
	if (!buffers.empty()) {
		user_array = std::unique_ptr<User*[]>(new User*[buffers.size()]);
	}

	size_t index = 0;
	for (const auto& user : users) {
		user_array[index] = user.get();
		index++;
	}

	//import
	return UserStore(user_array.get(), buffers.size());
}

void protobuf_empty_store(void) {
	printf("Testing im-/export of empty user store.\n");

	User **exported = nullptr;
	size_t exported_length = 0;

	UserStore store;

	//export it
	store.exportProtobuf(exported, exported_length);

	if ((exported != nullptr) || (exported_length != 0)) {
		throw MolchException(INCORRECT_DATA, "Exported data is not empty.");
	}

	//import it
	store = UserStore(exported, exported_length);
	printf("Successful.\n");
}

int main(void) {
	try {
		if (sodium_init() == -1) {
			throw MolchException(INIT_ERROR, "Failed to initialize libsodium.");
		}

		//create a user_store
		UserStore store;

		//check the content
		auto list = store.list();
		if (list->content_length != 0) {
			throw MolchException(INCORRECT_DATA, "List of users is not empty.");
		}
		list.reset();

		//create alice
		Buffer alice_public_signing_key(PUBLIC_MASTER_KEY_SIZE, PUBLIC_MASTER_KEY_SIZE);
		exception_on_invalid_buffer(alice_public_signing_key);
		std::cout << "BEFORE alice store.add()" << std::endl;
		store.add(UserStoreNode(&alice_public_signing_key));
		std::cout << "AFTER alice store.add()" << std::endl;
		{
			auto alice_user = store.find(alice_public_signing_key);
			MasterKeys::Unlocker unlocker{alice_user->master_keys};
			alice_user->master_keys.print(std::cout) << std::endl;
		}
		printf("Successfully created Alice to the user store.\n");

		//check length of the user store
		if (store.size() != 1) {
			throw MolchException(INCORRECT_DATA, "User store has incorrect length.");
		}
		printf("Length of the user store matches.");

		//list user store
		list = store.list();
		if (!list) {
			throw MolchException(INCORRECT_DATA, "Failed to list users, user list is nullptr.");
		}
		if (*list != alice_public_signing_key) {
			throw MolchException(INCORRECT_DATA, "Failed to list users.");
		}
		list.reset();
		printf("Successfully listed users.\n");

		//create bob
		Buffer bob_public_signing_key(PUBLIC_MASTER_KEY_SIZE, PUBLIC_MASTER_KEY_SIZE);
		exception_on_invalid_buffer(bob_public_signing_key);
		std::cout << "BEFORE bob store.add()" << std::endl;
		store.add(UserStoreNode(&bob_public_signing_key));
		std::cout << "AFTER bob store.add()" << std::endl;
		printf("Successfully created Bob.\n");

		//check length of the user store
		if (store.size() != 2) {
			throw MolchException(INCORRECT_DATA, "User store has incorrect length.");
		}
		printf("Length of the user store matches.");

		//list user store
		list = store.list();
		if (!list) {
			throw MolchException(INCORRECT_DATA, "Failed to list users, user list is nullptr.");
		}
		if ((list->comparePartial(0, &alice_public_signing_key, 0, PUBLIC_MASTER_KEY_SIZE) != 0)
				|| (list->comparePartial(PUBLIC_MASTER_KEY_SIZE, &bob_public_signing_key, 0, PUBLIC_MASTER_KEY_SIZE) != 0)) {
			throw MolchException(INCORRECT_DATA, "Failed to list users.");
		}
		list.reset();
		printf("Successfully listed users.\n");

		//create charlie
		Buffer charlie_public_signing_key(PUBLIC_MASTER_KEY_SIZE, PUBLIC_MASTER_KEY_SIZE);
		exception_on_invalid_buffer(charlie_public_signing_key);
		std::cout << "BEFORE charlie store.add()" << std::endl;
		store.add(UserStoreNode(&charlie_public_signing_key));
		printf("Successfully added Charlie to the user store.\n");
		std::cout << "AFTER charlie store.add()" << std::endl;

		//check length of the user store
		if (store.size() != 3) {
			throw MolchException(INCORRECT_DATA, "User store has incorrect length.");
		}
		printf("Length of the user store matches.");

		//list user store
		list = store.list();
		if (!list) {
			throw MolchException(INCORRECT_DATA, "Failed to list users, user list is nullptr.");
		}
		if ((list->comparePartial(0, &alice_public_signing_key, 0, PUBLIC_MASTER_KEY_SIZE) != 0)
				|| (list->comparePartial(PUBLIC_MASTER_KEY_SIZE, &bob_public_signing_key, 0, PUBLIC_MASTER_KEY_SIZE) != 0)
				|| (list->comparePartial(2 * PUBLIC_MASTER_KEY_SIZE, &charlie_public_signing_key, 0, PUBLIC_MASTER_KEY_SIZE) != 0)) {
			throw MolchException(INCORRECT_DATA, "Failed to list users.");
		}
		list.reset();
		printf("Successfully listed users.\n");

		//find node
		{
			UserStoreNode *bob_node = nullptr;
			bob_node = store.find(bob_public_signing_key);
			if (bob_node == nullptr) {
				throw MolchException(NOT_FOUND, "Failed to find Bob's node.");
			}
			printf("Node found.\n");

			if (bob_node->public_signing_key != bob_public_signing_key) {
				throw MolchException(INCORRECT_DATA, "Bob's data from the user store doesn't match.");
			}
			printf("Data from the node matches.\n");

			//remove a user identified by it's key
			store.remove(bob_public_signing_key);
			//check the length
			if (store.size() != 2) {
				throw MolchException(INCORRECT_DATA, "User store has incorrect length.");
			}
			printf("Length of the user store matches.");
			//check the user list
			list = store.list();
			if (!list) {
				throw MolchException(INCORRECT_DATA, "Failed to list users, user list is nullptr.");
			}
			if ((list->comparePartial(0, &alice_public_signing_key, 0, PUBLIC_MASTER_KEY_SIZE) != 0)
					|| (list->comparePartial(PUBLIC_MASTER_KEY_SIZE, &charlie_public_signing_key, 0, PUBLIC_MASTER_KEY_SIZE) != 0)) {
				throw MolchException(INCORRECT_DATA, "Removing user failed.");
			}
			list.reset();
			printf("Successfully removed user.\n");

			//recreate bob
			std::cout << "BEFORE recreating bob store.add()" << std::endl;
			store.add(UserStoreNode(&bob_public_signing_key));
			std::cout << "AFTER recreating bob store.add()" << std::endl;
			printf("Successfully recreated Bob.\n");

			//now find bob again
			bob_node = store.find(bob_public_signing_key);
			if (bob_node == nullptr) {
				throw MolchException(NOT_FOUND, "Failed to find Bob's node.");
			}
			printf("Bob's node found again.\n");

			//remove bob by it's node
			store.remove(bob_node);
			//check the length
			if (store.size() != 2) {
				throw MolchException(INCORRECT_DATA, "User store has incorrect length.");
			}
			printf("Length of the user store matches.");
		}


		//test Protobuf-C export
		printf("Export to Protobuf-C\n");
		auto protobuf_export_buffers = protobuf_export(store);

		//print the exported data
		puts("[\n");
		for (size_t i = 0; i < protobuf_export_buffers.size(); i++) {
			std::cout << protobuf_export_buffers[i].toHex();
			puts(",\n");
		}
		puts("]\n\n");

		store.clear();

		//import from Protobuf-C
		printf("Import from Protobuf-C\n");
		store = protobuf_import(protobuf_export_buffers);

		//export again
		printf("Export to Protobuf-C\n");
		auto protobuf_second_export_buffers = protobuf_export(store);

		//compare
		if (protobuf_export_buffers.size() != protobuf_second_export_buffers.size()) {
			throw MolchException(INCORRECT_DATA, "Both exports have different sizes.");
		}
		for (size_t i = 0; i < protobuf_export_buffers.size(); i++) {
			if (protobuf_export_buffers[i] != protobuf_second_export_buffers[i]) {
				throw MolchException(INCORRECT_DATA, "Buffers don't match.");
			}
		}
		printf("Both exports match.\n");

		//check the user list
		list = store.list();
		if ((list->comparePartial(0, &alice_public_signing_key, 0, PUBLIC_MASTER_KEY_SIZE) != 0)
				|| (list->comparePartial(PUBLIC_MASTER_KEY_SIZE, &charlie_public_signing_key, 0, PUBLIC_MASTER_KEY_SIZE) != 0)) {
			throw MolchException(REMOVE_ERROR, "Removing user failed.");
		}
		list.reset();
		printf("Successfully removed user.\n");

		//clear the user store
		store.clear();
		//check the length
		if (store.size() != 0) {
			throw MolchException(INCORRECT_DATA, "User store has incorrect length.");
		}
		printf("Successfully cleared user store.\n");

		protobuf_empty_store();
	} catch (const MolchException& exception) {
		exception.print(std::cerr) << std::endl;
		return EXIT_FAILURE;
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
