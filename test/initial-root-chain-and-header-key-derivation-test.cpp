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

int main(void) noexcept {
	try {
		if (sodium_init() == -1) {
			throw MolchException(INIT_ERROR, "Failed to initialize libsodium.");
		}

		//create Alice's identity keypair
		Buffer alice_public_identity(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
		Buffer alice_private_identity(PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
		exception_on_invalid_buffer(alice_public_identity);
		exception_on_invalid_buffer(alice_private_identity);
		generate_and_print_keypair(
			alice_public_identity,
			alice_private_identity,
			"Alice",
			"identity");

		//create Alice's ephemeral keypair
		Buffer alice_public_ephemeral(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
		Buffer alice_private_ephemeral(PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
		exception_on_invalid_buffer(alice_public_ephemeral);
		exception_on_invalid_buffer(alice_private_ephemeral);
		generate_and_print_keypair(
			alice_public_ephemeral,
			alice_private_ephemeral,
			"Alice",
			"ephemeral");

		//create Bob's identity keypair
		Buffer bob_public_identity(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
		Buffer bob_private_identity(PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
		exception_on_invalid_buffer(bob_public_identity);
		exception_on_invalid_buffer(bob_private_identity);
		generate_and_print_keypair(
			bob_public_identity,
			bob_private_identity,
			"Bob",
			"identity");

		//create Bob's ephemeral keypair
		Buffer bob_public_ephemeral(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
		Buffer bob_private_ephemeral(PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
		exception_on_invalid_buffer(bob_public_ephemeral);
		exception_on_invalid_buffer(bob_private_ephemeral);
		generate_and_print_keypair(
			bob_public_ephemeral,
			bob_private_ephemeral,
			"Bob",
			"ephemeral");

		//derive Alice's initial root and chain key
		Buffer alice_root_key(ROOT_KEY_SIZE, ROOT_KEY_SIZE);
		Buffer alice_send_chain_key(CHAIN_KEY_SIZE, CHAIN_KEY_SIZE);
		Buffer alice_receive_chain_key(CHAIN_KEY_SIZE, CHAIN_KEY_SIZE);
		Buffer alice_send_header_key(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
		Buffer alice_receive_header_key(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
		Buffer alice_next_send_header_key(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
		Buffer alice_next_receive_header_key(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
		exception_on_invalid_buffer(alice_root_key);
		exception_on_invalid_buffer(alice_send_chain_key);
		exception_on_invalid_buffer(alice_receive_chain_key);
		exception_on_invalid_buffer(alice_send_header_key);
		exception_on_invalid_buffer(alice_receive_header_key);
		exception_on_invalid_buffer(alice_next_send_header_key);
		exception_on_invalid_buffer(alice_next_receive_header_key);
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
			true);
		alice_private_identity.clear();
		alice_private_ephemeral.clear();

		//print Alice's initial root and chain key
		printf("Alice's initial root key (%zu Bytes):\n", alice_root_key.content_length);
		std::cout << alice_root_key.toHex();
		putchar('\n');
		printf("Alice's initial send chain key (%zu Bytes):\n", alice_send_chain_key.content_length);
		std::cout << alice_send_chain_key.toHex();
		putchar('\n');
		printf("Alice's initial receive chain key (%zu Bytes):\n", alice_receive_chain_key.content_length);
		std::cout << alice_receive_chain_key.toHex();
		putchar('\n');
		printf("Alice's initial send header key (%zu Bytes):\n", alice_send_header_key.content_length);
		std::cout << alice_send_header_key.toHex();
		putchar('\n');
		printf("Alice's initial receive header key (%zu Bytes):\n", alice_receive_header_key.content_length);
		std::cout << alice_receive_header_key.toHex();
		printf("Alice's initial next send header key (%zu Bytes):\n", alice_next_send_header_key.content_length);
		std::cout << alice_next_send_header_key.toHex();
		putchar('\n');
		printf("Alice's initial next receive header key (%zu Bytes):\n", alice_next_receive_header_key.content_length);
		std::cout << alice_next_receive_header_key.toHex();
		putchar('\n');

		//derive Bob's initial root and chain key
		Buffer bob_root_key(ROOT_KEY_SIZE, ROOT_KEY_SIZE);
		Buffer bob_send_chain_key(CHAIN_KEY_SIZE, CHAIN_KEY_SIZE);
		Buffer bob_receive_chain_key(CHAIN_KEY_SIZE, CHAIN_KEY_SIZE);
		Buffer bob_send_header_key(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
		Buffer bob_receive_header_key(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
		Buffer bob_next_send_header_key(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
		Buffer bob_next_receive_header_key(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
		exception_on_invalid_buffer(bob_root_key);
		exception_on_invalid_buffer(bob_send_chain_key);
		exception_on_invalid_buffer(bob_receive_chain_key);
		exception_on_invalid_buffer(bob_send_header_key);
		exception_on_invalid_buffer(bob_receive_header_key);
		exception_on_invalid_buffer(bob_next_send_header_key);
		exception_on_invalid_buffer(bob_next_receive_header_key);
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
			false);
		bob_private_identity.clear();
		bob_private_ephemeral.clear();

		//print Bob's initial root and chain key
		printf("Bob's initial root key (%zu Bytes):\n", bob_root_key.content_length);
		std::cout << bob_root_key.toHex();
		putchar('\n');
		printf("Bob's initial send chain key (%zu Bytes):\n", bob_send_chain_key.content_length);
		std::cout << bob_send_chain_key.toHex();
		putchar('\n');
		printf("Bob's initial receive chain key (%zu Bytes):\n", bob_receive_chain_key.content_length);
		std::cout << bob_receive_chain_key.toHex();
		putchar('\n');
		printf("Bob's initial send header key (%zu Bytes):\n", bob_send_header_key.content_length);
		std::cout << bob_send_header_key.toHex();
		putchar('\n');
		printf("Bob's initial receive header key (%zu Bytes):\n", bob_receive_header_key.content_length);
		std::cout << bob_receive_header_key.toHex();
		printf("Bob's initial next send header key (%zu Bytes):\n", bob_next_send_header_key.content_length);
		std::cout << bob_next_send_header_key.toHex();
		putchar('\n');
		printf("Bob's initial next receive header key (%zu Bytes):\n", bob_next_receive_header_key.content_length);
		std::cout << bob_next_receive_header_key.toHex();
		putchar('\n');

		//compare Alice's and Bob's initial root key
		if (alice_root_key.compare(&bob_root_key) != 0) {
			throw MolchException(INCORRECT_DATA, "Alice's and Bob's initial root keys don't match.");
		}
		printf("Alice's and Bob's initial root keys match.\n");

		alice_root_key.clear();
		bob_root_key.clear();

		//compare Alice's and Bob's initial chain keys
		if (alice_send_chain_key.compare(&bob_receive_chain_key) != 0) {
			throw MolchException(INCORRECT_DATA, "Alice's and Bob's initial chain keys don't match.");
		}
		printf("Alice's and Bob's initial chain keys match.\n");

		alice_send_chain_key.clear();
		bob_receive_chain_key.clear();

		if (alice_receive_chain_key.compare(&bob_send_chain_key) != 0) {
			throw MolchException(INCORRECT_DATA, "Alice's and Bob's initial chain keys don't match.");
		}
		printf("Alice's and Bob's initial chain keys match.\n");

		//compare Alice's and Bob's initial header keys 1/2
		if (alice_send_header_key.compare(&bob_receive_header_key) != 0) {
			throw MolchException(INCORRECT_DATA, "Alice's initial send and Bob's initial receive header keys don't match.");
		}
		printf("Alice's initial send and Bob's initial receive header keys match.\n");

		alice_send_header_key.clear();
		bob_receive_header_key.clear();

		//compare Alice's and Bob's initial header keys 2/2
		if (alice_receive_header_key.compare(&bob_send_header_key) != 0) {
			throw MolchException(INCORRECT_DATA, "Alice's initial receive and Bob's initial send header keys don't match.");
		}
		printf("Alice's initial receive and Bob's initial send header keys match.\n");

		alice_receive_header_key.clear();
		bob_send_header_key.clear();

		//compare Alice's and Bob's initial next header keys 1/2
		if (alice_next_send_header_key.compare(&bob_next_receive_header_key) != 0) {
			throw MolchException(INCORRECT_DATA, "Alice's initial next send and Bob's initial next receive header keys don't match.");
		}
		printf("Alice's initial next send and Bob's initial next receive header keys match.\n");
		alice_next_send_header_key.clear();
		bob_next_receive_header_key.clear();

		//compare Alice's and Bob's initial next header keys 2/2
		if (alice_next_receive_header_key.compare(&bob_next_send_header_key) != 0) {
			throw MolchException(INCORRECT_DATA, "Alice's initial next receive and Bob's initial next send header keys don't match.");
		}
		printf("Alice's initial next receive and Bob's initial next send header keys match.\n");
	} catch (const MolchException& exception) {
		exception.print(std::cerr) << std::endl;
		return EXIT_FAILURE;
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
