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
#include "utils.hpp"
#include "common.hpp"

using namespace Molch;

int main() {
	try {
		TRY_VOID(Molch::sodium_init());

		//create Alice's keypair
		EmptyablePublicKey alice_public_ephemeral;
		EmptyablePrivateKey alice_private_ephemeral;
		generate_and_print_keypair(
			alice_public_ephemeral,
			alice_private_ephemeral,
			"Alice",
			"ephemeral");

		//create Bob's keypair
		EmptyablePublicKey bob_public_ephemeral;
		EmptyablePrivateKey bob_private_ephemeral;
		generate_and_print_keypair(
			bob_public_ephemeral,
			bob_private_ephemeral,
			"Bob",
			"ephemeral");

		//create previous root key
		EmptyableRootKey previous_root_key;
		previous_root_key.fillRandom();

		//print previous root key
		printf("Previous root key (%zu Bytes):\n", previous_root_key.size());
		previous_root_key.printHex(std::cout) << std::endl;

		//derive root and chain key for Alice
		const auto alice_derived_keys{derive_root_next_header_and_chain_keys(
			alice_private_ephemeral,
			alice_public_ephemeral,
			bob_public_ephemeral,
			previous_root_key,
			Ratchet::Role::ALICE)};

		//print Alice's root and chain key
		printf("Alice's root key:\n");
		alice_derived_keys.root_key.printHex(std::cout);
		printf("Alice's chain key:\n");
		alice_derived_keys.chain_key.printHex(std::cout);
		printf("Alice's header key:\n");
		alice_derived_keys.next_header_key.printHex(std::cout) << std::endl;

		//derive root and chain key for Bob
		const auto bob_derived_keys{derive_root_next_header_and_chain_keys(
			bob_private_ephemeral,
			bob_public_ephemeral,
			alice_public_ephemeral,
			previous_root_key,
			Ratchet::Role::BOB)};

		//print Bob's root and chain key
		printf("Bob's root key:\n");
		bob_derived_keys.root_key.printHex(std::cout);
		printf("Bob's chain key:\n");
		bob_derived_keys.chain_key.printHex(std::cout);
		printf("Bob's header key:\n");
		bob_derived_keys.next_header_key.printHex(std::cout) << std::endl;

		//compare Alice's and Bob's root keys
		if (alice_derived_keys.root_key == bob_derived_keys.root_key) {
			printf("Alice's and Bob's root keys match.\n");
		} else {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Alice's and Bob's root keys don't match."};
		}

		//compare Alice's and Bob's chain keys
		if (alice_derived_keys.chain_key == bob_derived_keys.chain_key) {
			printf("Alice's and Bob's chain keys match.\n");
		} else {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Alice's and Bob's chain keys don't match."};
		}

		//compare Alice's and Bob's header keys
		if (alice_derived_keys.next_header_key == bob_derived_keys.next_header_key) {
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
