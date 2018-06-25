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
		Molch::sodium_init();

		//create Alice's identity keypair
		PublicKey alice_public_identity;
		PrivateKey alice_private_identity;
		generate_and_print_keypair(
			alice_public_identity,
			alice_private_identity,
			"Alice",
			"identity");

		//create Alice's ephemeral keypair
		PublicKey alice_public_ephemeral;
		PrivateKey alice_private_ephemeral;
		generate_and_print_keypair(
			alice_public_ephemeral,
			alice_private_ephemeral,
			"Alice",
			"ephemeral");

		//create Bob's identity keypair
		PublicKey bob_public_identity;
		PrivateKey bob_private_identity;
		generate_and_print_keypair(
			bob_public_identity,
			bob_private_identity,
			"Bob",
			"identity");

		//create Bob's ephemeral keypair
		PublicKey bob_public_ephemeral;
		PrivateKey bob_private_ephemeral;
		generate_and_print_keypair(
			bob_public_ephemeral,
			bob_private_ephemeral,
			"Bob",
			"ephemeral");

		//derive Alice's initial root and chain key
		RootKey alice_root_key;
		ChainKey alice_send_chain_key;
		ChainKey alice_receive_chain_key;
		HeaderKey alice_send_header_key;
		HeaderKey alice_receive_header_key;
		HeaderKey alice_next_send_header_key;
		HeaderKey alice_next_receive_header_key;
		derive_initial_root_chain_and_header_keys(
			alice_root_key,
			alice_send_chain_key,
			alice_receive_chain_key,
			alice_send_header_key,
			alice_receive_header_key,
			alice_next_send_header_key,
			alice_next_receive_header_key,
			alice_private_identity,
			alice_public_identity,
			bob_public_identity,
			alice_private_ephemeral,
			alice_public_ephemeral,
			bob_public_ephemeral,
			Ratchet::Role::ALICE);
		alice_private_identity.clear();
		alice_private_ephemeral.clear();

		//print Alice's initial root and chain key
		printf("Alice's initial root key (%zu Bytes):\n", alice_root_key.size());
		alice_root_key.printHex(std::cout) << std::endl;
		printf("Alice's initial send chain key (%zu Bytes):\n", alice_send_chain_key.size());
		alice_send_chain_key.printHex(std::cout) << std::endl;
		printf("Alice's initial receive chain key (%zu Bytes):\n", alice_receive_chain_key.size());
		alice_receive_chain_key.printHex(std::cout) << std::endl;
		printf("Alice's initial send header key (%zu Bytes):\n", alice_send_header_key.size());
		alice_send_header_key.printHex(std::cout) << std::endl;
		printf("Alice's initial receive header key (%zu Bytes):\n", alice_receive_header_key.size());
		alice_receive_header_key.printHex(std::cout) << std::endl;
		printf("Alice's initial next send header key (%zu Bytes):\n", alice_next_send_header_key.size());
		alice_next_send_header_key.printHex(std::cout) << std::endl;
		printf("Alice's initial next receive header key (%zu Bytes):\n", alice_next_receive_header_key.size());
		alice_next_receive_header_key.printHex(std::cout) << std::endl;

		//derive Bob's initial root and chain key
		RootKey bob_root_key;
		ChainKey bob_send_chain_key;
		ChainKey bob_receive_chain_key;
		HeaderKey bob_send_header_key;
		HeaderKey bob_receive_header_key;
		HeaderKey bob_next_send_header_key;
		HeaderKey bob_next_receive_header_key;
		derive_initial_root_chain_and_header_keys(
			bob_root_key,
			bob_send_chain_key,
			bob_receive_chain_key,
			bob_send_header_key,
			bob_receive_header_key,
			bob_next_send_header_key,
			bob_next_receive_header_key,
			bob_private_identity,
			bob_public_identity,
			alice_public_identity,
			bob_private_ephemeral,
			bob_public_ephemeral,
			alice_public_ephemeral,
			Ratchet::Role::BOB);
		bob_private_identity.clear();
		bob_private_ephemeral.clear();

		//print Bob's initial root and chain key
		printf("Bob's initial root key (%zu Bytes):\n", bob_root_key.size());
		bob_root_key.printHex(std::cout) << std::endl;
		printf("Bob's initial send chain key (%zu Bytes):\n", bob_send_chain_key.size());
		bob_send_chain_key.printHex(std::cout) << std::endl;
		printf("Bob's initial receive chain key (%zu Bytes):\n", bob_receive_chain_key.size());
		bob_receive_chain_key.printHex(std::cout) << std::endl;
		printf("Bob's initial send header key (%zu Bytes):\n", bob_send_header_key.size());
		bob_send_header_key.printHex(std::cout) << std::endl;
		printf("Bob's initial receive header key (%zu Bytes):\n", bob_receive_header_key.size());
		bob_receive_header_key.printHex(std::cout) << std::endl;
		printf("Bob's initial next send header key (%zu Bytes):\n", bob_next_send_header_key.size());
		bob_next_send_header_key.printHex(std::cout) << std::endl;
		printf("Bob's initial next receive header key (%zu Bytes):\n", bob_next_receive_header_key.size());
		bob_next_receive_header_key.printHex(std::cout) << std::endl;

		//compare Alice's and Bob's initial root key
		if (alice_root_key != bob_root_key) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Alice's and Bob's initial root keys don't match."};
		}
		printf("Alice's and Bob's initial root keys match.\n");

		alice_root_key.clear();
		bob_root_key.clear();

		//compare Alice's and Bob's initial chain keys
		if (alice_send_chain_key != bob_receive_chain_key) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Alice's and Bob's initial chain keys don't match."};
		}
		printf("Alice's and Bob's initial chain keys match.\n");

		alice_send_chain_key.clear();
		bob_receive_chain_key.clear();

		if (alice_receive_chain_key != bob_send_chain_key) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Alice's and Bob's initial chain keys don't match."};
		}
		printf("Alice's and Bob's initial chain keys match.\n");

		//compare Alice's and Bob's initial header keys 1/2
		if (alice_send_header_key != bob_receive_header_key) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Alice's initial send and Bob's initial receive header keys don't match."};
		}
		printf("Alice's initial send and Bob's initial receive header keys match.\n");

		alice_send_header_key.clear();
		bob_receive_header_key.clear();

		//compare Alice's and Bob's initial header keys 2/2
		if (alice_receive_header_key != bob_send_header_key) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Alice's initial receive and Bob's initial send header keys don't match."};
		}
		printf("Alice's initial receive and Bob's initial send header keys match.\n");

		alice_receive_header_key.clear();
		bob_send_header_key.clear();

		//compare Alice's and Bob's initial next header keys 1/2
		if (alice_next_send_header_key != bob_next_receive_header_key) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Alice's initial next send and Bob's initial next receive header keys don't match."};
		}
		printf("Alice's initial next send and Bob's initial next receive header keys match.\n");
		alice_next_send_header_key.clear();
		bob_next_receive_header_key.clear();

		//compare Alice's and Bob's initial next header keys 2/2
		if (alice_next_receive_header_key != bob_next_send_header_key) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Alice's initial next receive and Bob's initial next send header keys don't match."};
		}
		printf("Alice's initial next receive and Bob's initial next send header keys match.\n");
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
