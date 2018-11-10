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
#include "molch/constants.h"
#include "utils.hpp"
#include "common.hpp"
#include "exception.hpp"

using namespace Molch;

int main() {
	try {
		TRY_VOID(Molch::sodium_init());

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
		EmptyableRootKey previous_root_key;
		randombytes_buf(previous_root_key);
		previous_root_key.empty = false;

		//print previous root key
		std::cout << "Previous root key (" << previous_root_key.size() << "%zu Bytes):\n";
		std::cout << previous_root_key << std::endl;

		//derive root and chain key for Alice
		TRY_WITH_RESULT(alice_derived_keys_result, derive_root_next_header_and_chain_keys(
			alice_private_ephemeral,
			alice_public_ephemeral,
			bob_public_ephemeral,
			previous_root_key,
			Ratchet::Role::ALICE));
		const auto& alice_derived_keys{alice_derived_keys_result.value()};

		//print Alice's root and chain key
		std::cout << "Alice's root key:\n";
		std::cout << alice_derived_keys.root_key;
		std::cout << "Alice's chain key:\n";
		std::cout << alice_derived_keys.chain_key;
		std::cout << "Alice's header key:\n";
		std::cout << alice_derived_keys.next_header_key << std::endl;

		//derive root and chain key for Bob
		TRY_WITH_RESULT(bob_derived_keys_result, derive_root_next_header_and_chain_keys(
			bob_private_ephemeral,
			bob_public_ephemeral,
			alice_public_ephemeral,
			previous_root_key,
			Ratchet::Role::BOB));
		const auto& bob_derived_keys{bob_derived_keys_result.value()};

		//print Bob's root and chain key
		std::cout << "Bob's root key:\n";
		std::cout << bob_derived_keys.root_key;
		std::cout << "Bob's chain key:\n";
		std::cout << bob_derived_keys.chain_key;
		std::cout << "Bob's header key:\n";
		std::cout << bob_derived_keys.next_header_key << std::endl;

		//compare Alice's and Bob's root keys
		if (alice_derived_keys.root_key == bob_derived_keys.root_key) {
			std::cout << "Alice's and Bob's root keys match.\n";
		} else {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Alice's and Bob's root keys don't match."};
		}

		//compare Alice's and Bob's chain keys
		if (alice_derived_keys.chain_key == bob_derived_keys.chain_key) {
			std::cout << "Alice's and Bob's chain keys match.\n";
		} else {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Alice's and Bob's chain keys don't match."};
		}

		//compare Alice's and Bob's header keys
		if (alice_derived_keys.next_header_key == bob_derived_keys.next_header_key) {
			std::cout << "Alice's and Bob's header keys match.\n";
		} else {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Alice's and Bob's header keys don't match."};
		}
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
