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

#include "../lib/key-derivation.h"
#include "../lib/constants.h"
#include "utils.h"
#include "common.h"

int main(void) noexcept {
	if (sodium_init() == -1) {
		return -1;
	}

	return_status status = return_status_init();

	//create key buffers
	Buffer alice_public_ephemeral(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	Buffer alice_private_ephemeral(PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
	Buffer bob_public_ephemeral(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	Buffer bob_private_ephemeral(PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
	Buffer previous_root_key(ROOT_KEY_SIZE, ROOT_KEY_SIZE);
	Buffer alice_root_key(ROOT_KEY_SIZE, ROOT_KEY_SIZE);
	Buffer alice_chain_key(CHAIN_KEY_SIZE, CHAIN_KEY_SIZE);
	Buffer alice_header_key(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	Buffer bob_root_key(ROOT_KEY_SIZE, ROOT_KEY_SIZE);
	Buffer bob_chain_key(CHAIN_KEY_SIZE, CHAIN_KEY_SIZE);
	Buffer bob_header_key(HEADER_KEY_SIZE, HEADER_KEY_SIZE);

	throw_on_invalid_buffer(alice_public_ephemeral);
	throw_on_invalid_buffer(alice_private_ephemeral);
	throw_on_invalid_buffer(bob_public_ephemeral);
	throw_on_invalid_buffer(bob_private_ephemeral);
	throw_on_invalid_buffer(previous_root_key);
	throw_on_invalid_buffer(alice_root_key);
	throw_on_invalid_buffer(alice_chain_key);
	throw_on_invalid_buffer(alice_header_key);
	throw_on_invalid_buffer(bob_root_key);
	throw_on_invalid_buffer(bob_chain_key);
	throw_on_invalid_buffer(bob_header_key);

	//create Alice's keypair
	status = generate_and_print_keypair(
			alice_public_ephemeral,
			alice_private_ephemeral,
			"Alice",
			"ephemeral");
	THROW_on_error(KEYGENERATION_FAILED, "Failed to generate and print Alice's ephemeral keypair.");

	//create Bob's keypair
	status = generate_and_print_keypair(
			bob_public_ephemeral,
			bob_private_ephemeral,
			"Bob",
			"ephemeral");
	THROW_on_error(KEYGENERATION_FAILED, "Failed to generate and print Bob's ephemeral keypair.");

	//create previous root key
	if (previous_root_key.fillRandom(ROOT_KEY_SIZE) != 0) {
		THROW(KEYGENERATION_FAILED, "Failed to generate previous root key.");
	}

	//print previous root key
	printf("Previous root key (%zu Bytes):\n", previous_root_key.content_length);
	print_hex(previous_root_key);
	putchar('\n');

	//derive root and chain key for Alice
	status = derive_root_next_header_and_chain_keys(
			alice_root_key,
			alice_header_key,
			alice_chain_key,
			alice_private_ephemeral,
			alice_public_ephemeral,
			bob_public_ephemeral,
			previous_root_key,
			true);
	THROW_on_error(KEYDERIVATION_FAILED, "Failed to derive root, next header and chain key for Alice.");

	//print Alice's root and chain key
	printf("Alice's root key (%zu Bytes):\n", alice_root_key.content_length);
	print_hex(alice_root_key);
	printf("Alice's chain key (%zu Bytes):\n", alice_chain_key.content_length);
	print_hex(alice_chain_key);
	printf("Alice's header key (%zu Bytes):\n", alice_header_key.content_length);
	print_hex(alice_header_key);
	putchar('\n');

	//derive root and chain key for Bob
	status = derive_root_next_header_and_chain_keys(
			bob_root_key,
			bob_header_key,
			bob_chain_key,
			bob_private_ephemeral,
			bob_public_ephemeral,
			alice_public_ephemeral,
			previous_root_key,
			false);
	THROW_on_error(KEYDERIVATION_FAILED, "Failed to derive root, next header and chain key for Bob.");

	//print Bob's root and chain key
	printf("Bob's root key (%zu Bytes):\n", bob_root_key.content_length);
	print_hex(bob_root_key);
	printf("Bob's chain key (%zu Bytes):\n", bob_chain_key.content_length);
	print_hex(bob_chain_key);
	printf("Bob's header key (%zu Bytes):\n", bob_header_key.content_length);
	print_hex(bob_header_key);
	putchar('\n');

	//compare Alice's and Bob's root keys
	if (alice_root_key == bob_root_key) {
		printf("Alice's and Bob's root keys match.\n");
	} else {
		THROW(INCORRECT_DATA, "Alice's and Bob's root keys don't match.");
	}
	alice_root_key.clear();
	bob_root_key.clear();

	//compare Alice's and Bob's chain keys
	if (alice_chain_key == bob_chain_key) {
		printf("Alice's and Bob's chain keys match.\n");
	} else {
		THROW(INCORRECT_DATA, "Alice's and Bob's chain keys don't match.");
	}

	//compare Alice's and Bob's header keys
	if (alice_header_key == bob_header_key) {
		printf("Alice's and Bob's header keys match.\n");
	} else {
		THROW(INCORRECT_DATA, "Alice's and Bob's header keys don't match.");
	}

cleanup:
	on_error {
		print_errors(status);
	}
	return_status_destroy_errors(&status);

	return status.status;
}
