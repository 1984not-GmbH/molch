/* Molch, an implementation of the axolotl ratchet based on libsodium
 *  Copyright (C) 2015-2016 1984not Security GmbH
 *  Author: Max Bruckner (FSMaxB)
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>

#include "../lib/key-derivation.h"
#include "utils.h"
#include "common.h"
#include "tracing.h"

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
	buffer_t *alice_send_header_key = buffer_create_on_heap(crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
	buffer_t *alice_receive_header_key = buffer_create_on_heap(crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
	buffer_t *alice_next_send_header_key = buffer_create_on_heap(crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
	buffer_t *alice_next_receive_header_key = buffer_create_on_heap(crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
	//bobs keys
	buffer_t *bob_public_identity = buffer_create_on_heap(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	buffer_t *bob_private_identity = buffer_create_on_heap(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	buffer_t *bob_public_ephemeral = buffer_create_on_heap(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	buffer_t *bob_private_ephemeral = buffer_create_on_heap(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	buffer_t *bob_root_key = buffer_create_on_heap(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	buffer_t *bob_send_chain_key = buffer_create_on_heap(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	buffer_t *bob_receive_chain_key = buffer_create_on_heap(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	buffer_t *bob_send_header_key = buffer_create_on_heap(crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
	buffer_t *bob_receive_header_key = buffer_create_on_heap(crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
	buffer_t *bob_next_send_header_key = buffer_create_on_heap(crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
	buffer_t *bob_next_receive_header_key = buffer_create_on_heap(crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);

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
	buffer_destroy_from_heap(alice_public_identity);
	buffer_destroy_from_heap(alice_private_identity);
	buffer_destroy_from_heap(alice_public_ephemeral);
	buffer_destroy_from_heap(alice_private_ephemeral);
	buffer_destroy_from_heap(alice_root_key);
	buffer_destroy_from_heap(alice_send_chain_key);
	buffer_destroy_from_heap(alice_receive_chain_key);
	buffer_destroy_from_heap(alice_send_header_key);
	buffer_destroy_from_heap(alice_receive_header_key);
	buffer_destroy_from_heap(alice_next_send_header_key);
	buffer_destroy_from_heap(alice_next_receive_header_key);
	//bobs keys
	buffer_destroy_from_heap(bob_public_identity);
	buffer_destroy_from_heap(bob_private_identity);
	buffer_destroy_from_heap(bob_public_ephemeral);
	buffer_destroy_from_heap(bob_private_ephemeral);
	buffer_destroy_from_heap(bob_root_key);
	buffer_destroy_from_heap(bob_send_chain_key);
	buffer_destroy_from_heap(bob_receive_chain_key);
	buffer_destroy_from_heap(bob_send_header_key);
	buffer_destroy_from_heap(bob_receive_header_key);
	buffer_destroy_from_heap(bob_next_send_header_key);
	buffer_destroy_from_heap(bob_next_receive_header_key);

	on_error(
		print_errors(&status);
	);
	return_status_destroy_errors(&status);

	return status.status;
}
