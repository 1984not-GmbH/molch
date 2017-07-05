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

#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>

#include "../lib/key-derivation.h"
#include "../lib/constants.h"
#include "utils.h"
#include "common.h"

int main(void) {
	if (sodium_init() == -1) {
		return -1;
	}

	return_status status = return_status_init();

	//create buffers
	//alice keys
	buffer_t *alice_public_identity = buffer_create_on_heap(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	buffer_t *alice_private_identity = buffer_create_on_heap(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	buffer_t *alice_public_ephemeral = buffer_create_on_heap(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	buffer_t *alice_private_ephemeral = buffer_create_on_heap(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	buffer_t *alice_root_key = buffer_create_on_heap(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	buffer_t *alice_send_chain_key = buffer_create_on_heap(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	buffer_t *alice_receive_chain_key = buffer_create_on_heap(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	buffer_t *alice_send_header_key = buffer_create_on_heap(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	buffer_t *alice_receive_header_key = buffer_create_on_heap(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	buffer_t *alice_next_send_header_key = buffer_create_on_heap(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	buffer_t *alice_next_receive_header_key = buffer_create_on_heap(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	//bobs keys
	buffer_t *bob_public_identity = buffer_create_on_heap(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	buffer_t *bob_private_identity = buffer_create_on_heap(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	buffer_t *bob_public_ephemeral = buffer_create_on_heap(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	buffer_t *bob_private_ephemeral = buffer_create_on_heap(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	buffer_t *bob_root_key = buffer_create_on_heap(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	buffer_t *bob_send_chain_key = buffer_create_on_heap(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	buffer_t *bob_receive_chain_key = buffer_create_on_heap(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	buffer_t *bob_send_header_key = buffer_create_on_heap(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	buffer_t *bob_receive_header_key = buffer_create_on_heap(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	buffer_t *bob_next_send_header_key = buffer_create_on_heap(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	buffer_t *bob_next_receive_header_key = buffer_create_on_heap(HEADER_KEY_SIZE, HEADER_KEY_SIZE);

	//create Alice's identity keypair
	buffer_create_from_string(alice_string, "Alice");
	buffer_create_from_string(identity_string, "identity");
	status = generate_and_print_keypair(
			alice_public_identity,
			alice_private_identity,
			alice_string,
			identity_string);
	throw_on_error(KEYGENERATION_FAILED, "Failed to generate and print Alice's identity keypair.");

	//create Alice's ephemeral keypair
	buffer_create_from_string(ephemeral_string, "ephemeral");
	status = generate_and_print_keypair(
			alice_public_ephemeral,
			alice_private_ephemeral,
			alice_string,
			ephemeral_string);
	throw_on_error(KEYGENERATION_FAILED, "Failed to generate and print Alice's ephemeral keypair.");

	//create Bob's identity keypair
	buffer_create_from_string(bob_string, "Bob");
	status = generate_and_print_keypair(
			bob_public_identity,
			bob_private_identity,
			bob_string,
			identity_string);
	throw_on_error(KEYGENERATION_FAILED, "Failed to generate and print Bob's identity keypair.");

	//create Bob's ephemeral keypair
	status = generate_and_print_keypair(
			bob_public_ephemeral,
			bob_private_ephemeral,
			bob_string,
			ephemeral_string);
	throw_on_error(KEYGENERATION_FAILED, "Failed to generate and print Bob's ephemeral keypair.");

	//derive Alice's initial root and chain key
	status = derive_initial_root_chain_and_header_keys(
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
	buffer_clear(alice_private_identity);
	buffer_clear(alice_private_ephemeral);
	throw_on_error(KEYDERIVATION_FAILED, "Failed to derive Alice's initial root and chain key.");

	//print Alice's initial root and chain key
	printf("Alice's initial root key (%zu Bytes):\n", alice_root_key->content_length);
	print_hex(alice_root_key);
	putchar('\n');
	printf("Alice's initial send chain key (%zu Bytes):\n", alice_send_chain_key->content_length);
	print_hex(alice_send_chain_key);
	putchar('\n');
	printf("Alice's initial receive chain key (%zu Bytes):\n", alice_receive_chain_key->content_length);
	print_hex(alice_receive_chain_key);
	putchar('\n');
	printf("Alice's initial send header key (%zu Bytes):\n", alice_send_header_key->content_length);
	print_hex(alice_send_header_key);
	putchar('\n');
	printf("Alice's initial receive header key (%zu Bytes):\n", alice_receive_header_key->content_length);
	print_hex(alice_receive_header_key);
	printf("Alice's initial next send header key (%zu Bytes):\n", alice_next_send_header_key->content_length);
	print_hex(alice_next_send_header_key);
	putchar('\n');
	printf("Alice's initial next receive header key (%zu Bytes):\n", alice_next_receive_header_key->content_length);
	print_hex(alice_next_receive_header_key);
	putchar('\n');

	//derive Bob's initial root and chain key
	status = derive_initial_root_chain_and_header_keys(
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
	buffer_clear(bob_private_identity);
	buffer_clear(bob_private_ephemeral);
	throw_on_error(KEYDERIVATION_FAILED, "Failed to derive Bob's initial root and chain key.");

	//print Bob's initial root and chain key
	printf("Bob's initial root key (%zu Bytes):\n", bob_root_key->content_length);
	print_hex(bob_root_key);
	putchar('\n');
	printf("Bob's initial send chain key (%zu Bytes):\n", bob_send_chain_key->content_length);
	print_hex(bob_send_chain_key);
	putchar('\n');
	printf("Bob's initial receive chain key (%zu Bytes):\n", bob_receive_chain_key->content_length);
	print_hex(bob_receive_chain_key);
	putchar('\n');
	printf("Bob's initial send header key (%zu Bytes):\n", bob_send_header_key->content_length);
	print_hex(bob_send_header_key);
	putchar('\n');
	printf("Bob's initial receive header key (%zu Bytes):\n", bob_receive_header_key->content_length);
	print_hex(bob_receive_header_key);
	printf("Bob's initial next send header key (%zu Bytes):\n", bob_next_send_header_key->content_length);
	print_hex(bob_next_send_header_key);
	putchar('\n');
	printf("Bob's initial next receive header key (%zu Bytes):\n", bob_next_receive_header_key->content_length);
	print_hex(bob_next_receive_header_key);
	putchar('\n');

	//compare Alice's and Bob's initial root key
	if (buffer_compare(alice_root_key, bob_root_key) != 0) {
		throw(INCORRECT_DATA, "Alice's and Bob's initial root keys don't match.");
	}
	printf("Alice's and Bob's initial root keys match.\n");

	buffer_clear(alice_root_key);
	buffer_clear(bob_root_key);

	//compare Alice's and Bob's initial chain keys
	if (buffer_compare(alice_send_chain_key, bob_receive_chain_key) != 0) {
		throw(INCORRECT_DATA, "Alice's and Bob's initial chain keys don't match.");
	}
	printf("Alice's and Bob's initial chain keys match.\n");

	buffer_clear(alice_send_chain_key);
	buffer_clear(bob_receive_chain_key);

	if (buffer_compare(alice_receive_chain_key, bob_send_chain_key) != 0) {
		throw(INCORRECT_DATA, "Alice's and Bob's initial chain keys don't match.");
	}
	printf("Alice's and Bob's initial chain keys match.\n");

	//compare Alice's and Bob's initial header keys 1/2
	if (buffer_compare(alice_send_header_key, bob_receive_header_key) != 0) {
		throw(INCORRECT_DATA, "Alice's initial send and Bob's initial receive header keys don't match.");
	}
	printf("Alice's initial send and Bob's initial receive header keys match.\n");

	buffer_clear(alice_send_header_key);
	buffer_clear(bob_receive_header_key);

	//compare Alice's and Bob's initial header keys 2/2
	if (buffer_compare(alice_receive_header_key, bob_send_header_key) != 0) {
		throw(INCORRECT_DATA, "Alice's initial receive and Bob's initial send header keys don't match.");
	}
	printf("Alice's initial receive and Bob's initial send header keys match.\n");

	buffer_clear(alice_receive_header_key);
	buffer_clear(bob_send_header_key);

	//compare Alice's and Bob's initial next header keys 1/2
	if (buffer_compare(alice_next_send_header_key, bob_next_receive_header_key) != 0) {
		throw(INCORRECT_DATA, "Alice's initial next send and Bob's initial next receive header keys don't match.");
	}
	printf("Alice's initial next send and Bob's initial next receive header keys match.\n");
	buffer_clear(alice_next_send_header_key);
	buffer_clear(bob_next_receive_header_key);

	//compare Alice's and Bob's initial next header keys 2/2
	if (buffer_compare(alice_next_receive_header_key, bob_next_send_header_key) != 0) {
		throw(INCORRECT_DATA, "Alice's initial next receive and Bob's initial next send header keys don't match.");
	}
	printf("Alice's initial next receive and Bob's initial next send header keys match.\n");

cleanup:
	//alice keys
	buffer_destroy_from_heap_and_null_if_valid(alice_public_identity);
	buffer_destroy_from_heap_and_null_if_valid(alice_private_identity);
	buffer_destroy_from_heap_and_null_if_valid(alice_public_ephemeral);
	buffer_destroy_from_heap_and_null_if_valid(alice_private_ephemeral);
	buffer_destroy_from_heap_and_null_if_valid(alice_root_key);
	buffer_destroy_from_heap_and_null_if_valid(alice_send_chain_key);
	buffer_destroy_from_heap_and_null_if_valid(alice_receive_chain_key);
	buffer_destroy_from_heap_and_null_if_valid(alice_send_header_key);
	buffer_destroy_from_heap_and_null_if_valid(alice_receive_header_key);
	buffer_destroy_from_heap_and_null_if_valid(alice_next_send_header_key);
	buffer_destroy_from_heap_and_null_if_valid(alice_next_receive_header_key);
	//bobs keys
	buffer_destroy_from_heap_and_null_if_valid(bob_public_identity);
	buffer_destroy_from_heap_and_null_if_valid(bob_private_identity);
	buffer_destroy_from_heap_and_null_if_valid(bob_public_ephemeral);
	buffer_destroy_from_heap_and_null_if_valid(bob_private_ephemeral);
	buffer_destroy_from_heap_and_null_if_valid(bob_root_key);
	buffer_destroy_from_heap_and_null_if_valid(bob_send_chain_key);
	buffer_destroy_from_heap_and_null_if_valid(bob_receive_chain_key);
	buffer_destroy_from_heap_and_null_if_valid(bob_send_header_key);
	buffer_destroy_from_heap_and_null_if_valid(bob_receive_header_key);
	buffer_destroy_from_heap_and_null_if_valid(bob_next_send_header_key);
	buffer_destroy_from_heap_and_null_if_valid(bob_next_receive_header_key);

	on_error {
		print_errors(&status);
	}
	return_status_destroy_errors(&status);

	return status.status;
}
