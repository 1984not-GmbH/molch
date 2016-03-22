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

	int status;

	//create key buffers
	buffer_t *alice_public_ephemeral = buffer_create_on_heap(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	buffer_t *alice_private_ephemeral = buffer_create_on_heap(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	buffer_t *bob_public_ephemeral = buffer_create_on_heap(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	buffer_t *bob_private_ephemeral = buffer_create_on_heap(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	buffer_t *previous_root_key = buffer_create_on_heap(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	buffer_t *alice_root_key = buffer_create_on_heap(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	buffer_t *alice_chain_key = buffer_create_on_heap(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	buffer_t *alice_header_key = buffer_create_on_heap(crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
	buffer_t *bob_root_key = buffer_create_on_heap(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	buffer_t *bob_chain_key = buffer_create_on_heap(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	buffer_t *bob_header_key = buffer_create_on_heap(crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);

	//create Alice's keypair
	buffer_create_from_string(alice_string, "Alice");
	buffer_create_from_string(ephemeral_string, "ephemeral");
	status = generate_and_print_keypair(
			alice_public_ephemeral,
			alice_private_ephemeral,
			alice_string,
			ephemeral_string);
	if (status != 0) {
		goto cleanup;
	}

	//create Bob's keypair
	buffer_create_from_string(bob_string, "Bob");
	status = generate_and_print_keypair(
			bob_public_ephemeral,
			bob_private_ephemeral,
			bob_string,
			ephemeral_string);
	if (status != 0) {
		goto cleanup;
	}

	//create previous root key
	status = buffer_fill_random(previous_root_key, crypto_secretbox_KEYBYTES);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to generate previous root key. (%i)\n", status);
		goto cleanup;
	}

	//print previous root key
	printf("Previous root key (%zu Bytes):\n", previous_root_key->content_length);
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
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to derive root and chain key for Alice. (%i)\n", status);
		goto cleanup;
	}

	//print Alice's root and chain key
	printf("Alice's root key (%zu Bytes):\n", alice_root_key->content_length);
	print_hex(alice_root_key);
	printf("Alice's chain key (%zu Bytes):\n", alice_chain_key->content_length);
	print_hex(alice_chain_key);
	printf("Alice's header key (%zu Bytes):\n", alice_header_key->content_length);
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
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to derive root and chain key for Bob. (%i)\n", status);
		goto cleanup;
	}

	//print Bob's root and chain key
	printf("Bob's root key (%zu Bytes):\n", bob_root_key->content_length);
	print_hex(bob_root_key);
	printf("Bob's chain key (%zu Bytes):\n", bob_chain_key->content_length);
	print_hex(bob_chain_key);
	printf("Bob's header key (%zu Bytes):\n", bob_header_key->content_length);
	print_hex(bob_header_key);
	putchar('\n');

	//compare Alice's and Bob's root keys
	if (buffer_compare(alice_root_key, bob_root_key) == 0) {
		printf("Alice's and Bob's root keys match.\n");
	} else {
		fprintf(stderr, "ERROR: Alice's and Bob's root keys don't match.\n");
		status = -1;
		goto cleanup;
	}
	buffer_clear(alice_root_key);
	buffer_clear(bob_root_key);

	//compare Alice's and Bob's chain keys
	if (buffer_compare(alice_chain_key, bob_chain_key) == 0) {
		printf("Alice's and Bob's chain keys match.\n");
	} else {
		fprintf(stderr, "ERROR: Alice's and Bob's chain keys don't match.\n");
		status = -1;
		goto cleanup;
	}

	//compare Alice's and Bob's header keys
	if (buffer_compare(alice_header_key, bob_header_key) == 0) {
		printf("Alice's and Bob's header keys match.\n");
	} else {
		fprintf(stderr, "ERROR: Alice's and Bob's header keys don't match.\n");
		status = -1;
		goto cleanup;
	}

cleanup:
	buffer_destroy_from_heap(alice_public_ephemeral);
	buffer_destroy_from_heap(alice_private_ephemeral);
	buffer_destroy_from_heap(bob_public_ephemeral);
	buffer_destroy_from_heap(bob_private_ephemeral);
	buffer_destroy_from_heap(previous_root_key);
	buffer_destroy_from_heap(alice_root_key);
	buffer_destroy_from_heap(alice_chain_key);
	buffer_destroy_from_heap(alice_header_key);
	buffer_destroy_from_heap(bob_root_key);
	buffer_destroy_from_heap(bob_chain_key);
	buffer_destroy_from_heap(bob_header_key);

	return status;
}
