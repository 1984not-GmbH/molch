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

#include "../lib/key-derivation.hpp"
#include "../lib/constants.h"
#include "../lib/molch-exception.hpp"
#include "utils.hpp"
#include "common.hpp"

using namespace Molch;

int main(void) {
	try {
		if (sodium_init() == -1) {
			throw Molch::Exception{status_type::INIT_ERROR, "Initialize libsodium."};
		}

		//create Alice's keypair
		PublicKey alice_public_ephemeral;
		PrivateKey alice_private_ephemeral;
		generate_and_print_keypair(
			alice_public_ephemeral,
			alice_private_ephemeral,
			"Alice",
			"ephemeral");

		//create Bob's keypair
		PublicKey bob_public_ephemeral;
		PrivateKey bob_private_ephemeral;
		generate_and_print_keypair(
			bob_public_ephemeral,
			bob_private_ephemeral,
			"Bob",
			"ephemeral");

		//create previous root key
		RootKey previous_root_key;
		previous_root_key.fillRandom();

		//print previous root key
		printf("Previous root key (%zu Bytes):\n", previous_root_key.size());
		previous_root_key.printHex(std::cout) << std::endl;

		//derive root and chain key for Alice
		RootKey alice_root_key;
		ChainKey alice_chain_key;
		HeaderKey alice_header_key;
		derive_root_next_header_and_chain_keys(
			alice_root_key,
			alice_header_key,
			alice_chain_key,
			alice_private_ephemeral,
			alice_public_ephemeral,
			bob_public_ephemeral,
			previous_root_key,
			Ratchet::Role::ALICE);

		//print Alice's root and chain key
		printf("Alice's root key (%zu Bytes):\n", alice_root_key.size());
		alice_root_key.printHex(std::cout);
		printf("Alice's chain key (%zu Bytes):\n", alice_chain_key.size());
		alice_chain_key.printHex(std::cout);
		printf("Alice's header key (%zu Bytes):\n", alice_header_key.size());
		alice_header_key.printHex(std::cout) << std::endl;

		//derive root and chain key for Bob
		RootKey bob_root_key;
		ChainKey bob_chain_key;
		HeaderKey bob_header_key;
		derive_root_next_header_and_chain_keys(
			bob_root_key,
			bob_header_key,
			bob_chain_key,
			bob_private_ephemeral,
			bob_public_ephemeral,
			alice_public_ephemeral,
			previous_root_key,
			Ratchet::Role::BOB);

		//print Bob's root and chain key
		printf("Bob's root key (%zu Bytes):\n", bob_root_key.size());
		bob_root_key.printHex(std::cout);
		printf("Bob's chain key (%zu Bytes):\n", bob_chain_key.size());
		bob_chain_key.printHex(std::cout);
		printf("Bob's header key (%zu Bytes):\n", bob_header_key.size());
		bob_header_key.printHex(std::cout) << std::endl;

		//compare Alice's and Bob's root keys
		if (alice_root_key == bob_root_key) {
			printf("Alice's and Bob's root keys match.\n");
		} else {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Alice's and Bob's root keys don't match."};
		}
		alice_root_key.clear();
		bob_root_key.clear();

		//compare Alice's and Bob's chain keys
		if (alice_chain_key == bob_chain_key) {
			printf("Alice's and Bob's chain keys match.\n");
		} else {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Alice's and Bob's chain keys don't match."};
		}

		//compare Alice's and Bob's header keys
		if (alice_header_key == bob_header_key) {
			printf("Alice's and Bob's header keys match.\n");
		} else {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Alice's and Bob's header keys don't match."};
		}
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
