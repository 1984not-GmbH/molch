/* Molch, an implementation of the axolotl ratchet based on libsodium
 *  Copyright (C) 2015  Max Bruckner (FSMaxB)
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

int main(void) {
	sodium_init();

	int status;

	//create Alice's identity keypair
	unsigned char alice_public_identity[crypto_box_PUBLICKEYBYTES];
	unsigned char alice_private_identity[crypto_box_SECRETKEYBYTES];
	status = generate_and_print_keypair(
			alice_public_identity,
			alice_private_identity,
			"Alice",
			"identity");
	if (status != 0) {
		sodium_memzero(alice_private_identity, sizeof(alice_private_identity));
		return status;
	}

	//create Alice's ephemeral keypair
	unsigned char alice_public_ephemeral[crypto_box_PUBLICKEYBYTES];
	unsigned char alice_private_ephemeral[crypto_box_SECRETKEYBYTES];
	status = generate_and_print_keypair(
			alice_public_ephemeral,
			alice_private_ephemeral,
			"Alice",
			"ephemeral");
	if (status != 0) {
		sodium_memzero(alice_private_identity, sizeof(alice_private_identity));
		sodium_memzero(alice_private_ephemeral, sizeof(alice_private_ephemeral));
		return status;
	}

	//create Bob's identity keypair
	unsigned char bob_public_identity[crypto_box_PUBLICKEYBYTES];
	unsigned char bob_private_identity[crypto_box_SECRETKEYBYTES];
	status = generate_and_print_keypair(
			bob_public_identity,
			bob_private_identity,
			"Bob",
			"identity");
	if (status != 0) {
		sodium_memzero(alice_private_identity, sizeof(alice_private_identity));
		sodium_memzero(alice_private_ephemeral, sizeof(alice_private_ephemeral));
		sodium_memzero(bob_private_identity, sizeof(bob_private_identity));
		return status;
	}

	//create Bob's ephemeral keypair
	unsigned char bob_public_ephemeral[crypto_box_PUBLICKEYBYTES];
	unsigned char bob_private_ephemeral[crypto_box_SECRETKEYBYTES];
	status = generate_and_print_keypair(
			bob_public_ephemeral,
			bob_private_ephemeral,
			"Bob",
			"ephemeral");
	if (status != 0) {
		sodium_memzero(alice_private_identity, sizeof(alice_private_identity));
		sodium_memzero(alice_private_ephemeral, sizeof(alice_private_ephemeral));
		sodium_memzero(bob_private_identity, sizeof(bob_private_identity));
		sodium_memzero(bob_private_ephemeral, sizeof(bob_private_ephemeral));
		return status;
	}

	//derive Alice's initial root and chain key
	unsigned char alice_root_key[crypto_secretbox_KEYBYTES];
	unsigned char alice_send_chain_key[crypto_secretbox_KEYBYTES];
	unsigned char alice_receive_chain_key[crypto_secretbox_KEYBYTES];
	unsigned char alice_send_header_key[crypto_aead_chacha20poly1305_KEYBYTES];
	unsigned char alice_receive_header_key[crypto_aead_chacha20poly1305_KEYBYTES];
	unsigned char alice_next_send_header_key[crypto_aead_chacha20poly1305_KEYBYTES];
	unsigned char alice_next_receive_header_key[crypto_aead_chacha20poly1305_KEYBYTES];
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
	sodium_memzero(alice_private_identity, sizeof(alice_private_identity));
	sodium_memzero(alice_private_ephemeral, sizeof(alice_private_ephemeral));
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to derive Alice's initial root and chain key. (%i)\n", status);
		sodium_memzero(alice_root_key, sizeof(alice_root_key));
		sodium_memzero(alice_send_chain_key, sizeof(alice_send_chain_key));
		sodium_memzero(alice_receive_chain_key, sizeof(alice_receive_chain_key));
		sodium_memzero(alice_send_header_key, sizeof(alice_send_header_key));
		sodium_memzero(alice_receive_header_key, sizeof(alice_receive_header_key));
		sodium_memzero(alice_next_send_header_key, sizeof(alice_next_send_header_key));
		sodium_memzero(alice_next_receive_header_key, sizeof(alice_next_receive_header_key));

		sodium_memzero(bob_private_identity, sizeof(bob_private_identity));
		sodium_memzero(bob_private_ephemeral, sizeof(bob_private_ephemeral));

		return status;
	}

	//print Alice's initial root and chain key
	printf("Alice's initial root key (%zi Bytes):\n", sizeof(alice_root_key));
	print_hex(alice_root_key, sizeof(alice_root_key), 30);
	putchar('\n');
	printf("Alice's initial send chain key (%zi Bytes):\n", sizeof(alice_send_chain_key));
	print_hex(alice_send_chain_key, sizeof(alice_send_chain_key), 30);
	putchar('\n');
	printf("Alice's initial receive chain key (%zi Bytes):\n", sizeof(alice_receive_chain_key));
	print_hex(alice_receive_chain_key, sizeof(alice_receive_chain_key), 30);
	putchar('\n');
	printf("Alice's initial send header key (%zi Bytes):\n", sizeof(alice_send_header_key));
	print_hex(alice_send_header_key, sizeof(alice_send_header_key), 30);
	putchar('\n');
	printf("Alice's initial receive header key (%zi Bytes):\n", sizeof(alice_receive_header_key));
	print_hex(alice_receive_header_key, sizeof(alice_receive_header_key), 30);
	printf("Alice's initial next send header key (%zi Bytes):\n", sizeof(alice_next_send_header_key));
	print_hex(alice_next_send_header_key, sizeof(alice_next_send_header_key), 30);
	putchar('\n');
	printf("Alice's initial next receive header key (%zi Bytes):\n", sizeof(alice_next_receive_header_key));
	print_hex(alice_next_receive_header_key, sizeof(alice_next_receive_header_key), 30);
	putchar('\n');

	//derive Bob's initial root and chain key
	unsigned char bob_root_key[crypto_secretbox_KEYBYTES];
	unsigned char bob_send_chain_key[crypto_secretbox_KEYBYTES];
	unsigned char bob_receive_chain_key[crypto_secretbox_KEYBYTES];
	unsigned char bob_send_header_key[crypto_aead_chacha20poly1305_KEYBYTES];
	unsigned char bob_receive_header_key[crypto_aead_chacha20poly1305_KEYBYTES];
	unsigned char bob_next_send_header_key[crypto_aead_chacha20poly1305_KEYBYTES];
	unsigned char bob_next_receive_header_key[crypto_aead_chacha20poly1305_KEYBYTES];
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
	sodium_memzero(bob_private_identity, sizeof(bob_private_identity));
	sodium_memzero(bob_private_ephemeral, sizeof(bob_private_ephemeral));
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to derive Bob's initial root and chain key. (%i)", status);
		sodium_memzero(alice_root_key, sizeof(alice_root_key));
		sodium_memzero(alice_send_chain_key, sizeof(alice_send_chain_key));
		sodium_memzero(alice_receive_chain_key, sizeof(alice_receive_chain_key));
		sodium_memzero(alice_send_header_key, sizeof(alice_send_header_key));
		sodium_memzero(alice_receive_header_key, sizeof(alice_receive_header_key));
		sodium_memzero(alice_next_send_header_key, sizeof(alice_next_send_header_key));
		sodium_memzero(alice_next_receive_header_key, sizeof(alice_next_receive_header_key));
		sodium_memzero(bob_root_key, sizeof(bob_root_key));
		sodium_memzero(bob_send_chain_key, sizeof(bob_send_chain_key));
		sodium_memzero(bob_receive_chain_key, sizeof(bob_receive_chain_key));
		sodium_memzero(bob_send_header_key, sizeof(bob_send_header_key));
		sodium_memzero(bob_receive_header_key, sizeof(bob_receive_header_key));
		sodium_memzero(bob_next_send_header_key, sizeof(bob_next_send_header_key));
		sodium_memzero(bob_next_receive_header_key, sizeof(bob_next_receive_header_key));
		return status;
	}

	//print Bob's initial root and chain key
	printf("Bob's initial root key (%zi Bytes):\n", sizeof(bob_root_key));
	print_hex(bob_root_key, sizeof(bob_root_key), 30);
	putchar('\n');
	printf("Bob's initial send chain key (%zi Bytes):\n", sizeof(bob_send_chain_key));
	print_hex(bob_send_chain_key, sizeof(bob_send_chain_key), 30);
	putchar('\n');
	printf("Bob's initial receive chain key (%zi Bytes):\n", sizeof(bob_receive_chain_key));
	print_hex(bob_receive_chain_key, sizeof(bob_receive_chain_key), 30);
	putchar('\n');
	printf("Bob's initial send header key (%zi Bytes):\n", sizeof(bob_send_header_key));
	print_hex(bob_send_header_key, sizeof(bob_send_header_key), 30);
	putchar('\n');
	printf("Bob's initial receive header key (%zi Bytes):\n", sizeof(bob_receive_header_key));
	print_hex(bob_receive_header_key, sizeof(bob_receive_header_key), 30);
	printf("Bob's initial next send header key (%zi Bytes):\n", sizeof(bob_next_send_header_key));
	print_hex(bob_next_send_header_key, sizeof(bob_next_send_header_key), 30);
	putchar('\n');
	printf("Bob's initial next receive header key (%zi Bytes):\n", sizeof(bob_next_receive_header_key));
	print_hex(bob_next_receive_header_key, sizeof(bob_next_receive_header_key), 30);
	putchar('\n');

	//compare Alice's and Bob's initial root key
	if (sodium_memcmp(alice_root_key, bob_root_key, sizeof(alice_root_key)) != 0) {
		fprintf(stderr, "ERROR: Alice's and Bob's initial root keys don't match.\n");
		sodium_memzero(alice_root_key, sizeof(alice_root_key));
		sodium_memzero(alice_send_chain_key, sizeof(alice_send_chain_key));
		sodium_memzero(alice_receive_chain_key, sizeof(alice_receive_chain_key));
		sodium_memzero(alice_send_header_key, sizeof(alice_send_header_key));
		sodium_memzero(alice_receive_header_key, sizeof(alice_receive_header_key));
		sodium_memzero(alice_next_send_header_key, sizeof(alice_next_send_header_key));
		sodium_memzero(alice_next_receive_header_key, sizeof(alice_next_receive_header_key));
		sodium_memzero(bob_root_key, sizeof(bob_root_key));
		sodium_memzero(bob_send_chain_key, sizeof(bob_send_chain_key));
		sodium_memzero(bob_receive_chain_key, sizeof(bob_receive_chain_key));
		sodium_memzero(bob_send_header_key, sizeof(bob_send_header_key));
		sodium_memzero(bob_receive_header_key, sizeof(bob_receive_header_key));
		sodium_memzero(bob_next_send_header_key, sizeof(bob_next_send_header_key));
		sodium_memzero(bob_next_receive_header_key, sizeof(bob_next_receive_header_key));
		return -10;
	}
	printf("Alice's and Bob's initial root keys match.\n");

	sodium_memzero(alice_root_key, sizeof(alice_root_key));
	sodium_memzero(bob_root_key, sizeof(bob_root_key));

	//compare Alice's and Bob's initial chain keys
	if (sodium_memcmp(alice_send_chain_key, bob_receive_chain_key, sizeof(alice_send_chain_key)) != 0) {
		fprintf(stderr, "ERROR: Alice's and Bob's initial chain keys don't match.\n");
		sodium_memzero(alice_send_chain_key, sizeof(alice_send_chain_key));
		sodium_memzero(alice_receive_chain_key, sizeof(alice_receive_chain_key));
		sodium_memzero(alice_send_header_key, sizeof(alice_send_header_key));
		sodium_memzero(alice_receive_header_key, sizeof(alice_receive_header_key));
		sodium_memzero(alice_next_send_header_key, sizeof(alice_next_send_header_key));
		sodium_memzero(alice_next_receive_header_key, sizeof(alice_next_receive_header_key));
		sodium_memzero(bob_send_chain_key, sizeof(bob_send_chain_key));
		sodium_memzero(bob_receive_chain_key, sizeof(bob_receive_chain_key));
		sodium_memzero(bob_send_header_key, sizeof(bob_send_header_key));
		sodium_memzero(bob_receive_header_key, sizeof(bob_receive_header_key));
		sodium_memzero(bob_next_send_header_key, sizeof(bob_next_send_header_key));
		sodium_memzero(bob_next_receive_header_key, sizeof(bob_next_receive_header_key));
		return -10;
	}
	printf("Alice's and Bob's initial chain keys match.\n");

	sodium_memzero(alice_send_chain_key, sizeof(alice_send_chain_key));
	sodium_memzero(bob_receive_chain_key, sizeof(bob_receive_chain_key));

	if (sodium_memcmp(alice_receive_chain_key, bob_send_chain_key, sizeof(alice_receive_chain_key)) != 0) {
		fprintf(stderr, "ERROR: Alice's and Bob's initial chain keys don't match.\n");
		sodium_memzero(alice_receive_chain_key, sizeof(alice_receive_chain_key));
		sodium_memzero(alice_send_header_key, sizeof(alice_send_header_key));
		sodium_memzero(alice_receive_header_key, sizeof(alice_receive_header_key));
		sodium_memzero(alice_next_send_header_key, sizeof(alice_next_send_header_key));
		sodium_memzero(alice_next_receive_header_key, sizeof(alice_next_receive_header_key));
		sodium_memzero(bob_send_chain_key, sizeof(bob_send_chain_key));
		sodium_memzero(bob_send_header_key, sizeof(bob_send_header_key));
		sodium_memzero(bob_receive_header_key, sizeof(bob_receive_header_key));
		sodium_memzero(bob_next_send_header_key, sizeof(bob_next_send_header_key));
		sodium_memzero(bob_next_receive_header_key, sizeof(bob_next_receive_header_key));
		return -10;
	}
	printf("Alice's and Bob's initial chain keys match.\n");

	//compare Alice's and Bob's initial header keys 1/2
	if (sodium_memcmp(alice_send_header_key, bob_receive_header_key, sizeof(alice_send_header_key)) != 0) {
		fprintf(stderr, "ERROR: Alice's initial send and Bob's initial receive header keys don't match.\n");
		sodium_memzero(alice_send_header_key, sizeof(alice_send_header_key));
		sodium_memzero(alice_receive_header_key, sizeof(alice_receive_header_key));
		sodium_memzero(alice_next_send_header_key, sizeof(alice_next_send_header_key));
		sodium_memzero(alice_next_receive_header_key, sizeof(alice_next_receive_header_key));
		sodium_memzero(bob_send_header_key, sizeof(bob_send_header_key));
		sodium_memzero(bob_receive_header_key, sizeof(bob_receive_header_key));
		sodium_memzero(bob_next_send_header_key, sizeof(bob_next_send_header_key));
		sodium_memzero(bob_next_receive_header_key, sizeof(bob_next_receive_header_key));
		return -10;
	}
	printf("Alice's initial send and Bob's initial receive header keys match.\n");

	sodium_memzero(alice_send_header_key, sizeof(alice_send_header_key));
	sodium_memzero(bob_receive_header_key, sizeof(bob_receive_header_key));

	//compare Alice's and Bob's initial header keys 2/2
	if (sodium_memcmp(alice_receive_header_key, bob_send_header_key, sizeof(alice_receive_header_key)) != 0) {
		fprintf(stderr, "ERROR: Alice's initial receive and Bob's initial send header keys don't match.\n");
		sodium_memzero(alice_receive_header_key, sizeof(alice_receive_header_key));
		sodium_memzero(alice_next_receive_header_key, sizeof(alice_next_receive_header_key));
		sodium_memzero(alice_next_send_header_key, sizeof(alice_next_send_header_key));
		sodium_memzero(bob_send_header_key, sizeof(bob_send_header_key));
		sodium_memzero(bob_next_send_header_key, sizeof(bob_next_send_header_key));
		sodium_memzero(bob_next_receive_header_key, sizeof(bob_next_receive_header_key));
		return -10;
	}
	printf("Alice's initial receive and Bob's initial send header keys match.\n");

	sodium_memzero(alice_receive_header_key, sizeof(alice_receive_header_key));
	sodium_memzero(bob_send_header_key, sizeof(bob_send_header_key));

	//compare Alice's and Bob's initial next header keys 1/2
	if (sodium_memcmp(alice_next_send_header_key, bob_next_receive_header_key, sizeof(alice_next_send_header_key)) != 0) {
		fprintf(stderr, "ERROR: Alice's initial next send and Bob's initial next receive header keys don't match.\n");
		sodium_memzero(alice_next_receive_header_key, sizeof(alice_next_receive_header_key));
		sodium_memzero(alice_next_send_header_key, sizeof(alice_next_send_header_key));
		sodium_memzero(bob_next_send_header_key, sizeof(bob_next_send_header_key));
		sodium_memzero(bob_next_receive_header_key, sizeof(bob_next_receive_header_key));
		return -10;
	}
	printf("Alice's initial next send and Bob's initial next receive header keys match.\n");
	sodium_memzero(alice_next_send_header_key, sizeof(alice_next_send_header_key));
	sodium_memzero(bob_next_receive_header_key, sizeof(bob_next_receive_header_key));

	//compare Alice's and Bob's initial next header keys 2/2
	if (sodium_memcmp(alice_next_receive_header_key, bob_next_send_header_key, sizeof(alice_next_receive_header_key)) != 0) {
		fprintf(stderr, "ERROR: Alice's initial next receive and Bob's initial next send header keys don't match.\n");
		sodium_memzero(alice_next_receive_header_key, sizeof(alice_next_receive_header_key));
		sodium_memzero(bob_next_send_header_key, sizeof(bob_next_send_header_key));
		return -10;
	}
	printf("Alice's initial next receive and Bob's initial next send header keys match.\n");

	sodium_memzero(alice_next_receive_header_key, sizeof(alice_next_receive_header_key));
	sodium_memzero(bob_next_send_header_key, sizeof(bob_next_send_header_key));

	return EXIT_SUCCESS;
}
