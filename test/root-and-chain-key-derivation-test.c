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

	//create Alice's keypair
	unsigned char alice_public_ephemeral[crypto_box_PUBLICKEYBYTES];
	unsigned char alice_private_ephemeral[crypto_box_SECRETKEYBYTES];
	status = generate_and_print_keypair(
			alice_public_ephemeral,
			alice_private_ephemeral,
			"Alice",
			"ephemeral");
	if (status != 0) {
		sodium_memzero(alice_private_ephemeral, sizeof(alice_private_ephemeral));
		return status;
	}

	//create Bob's keypair
	unsigned char bob_public_ephemeral[crypto_box_PUBLICKEYBYTES];
	unsigned char bob_private_ephemeral[crypto_box_SECRETKEYBYTES];
	status = generate_and_print_keypair(
			bob_public_ephemeral,
			bob_private_ephemeral,
			"Bob",
			"ephemeral");
	if (status != 0) {
		sodium_memzero(alice_private_ephemeral, sizeof(alice_private_ephemeral));
		sodium_memzero(bob_private_ephemeral, sizeof(bob_private_ephemeral));
		return status;
	}

	//create previous root key
	unsigned char previous_root_key[crypto_secretbox_KEYBYTES];
	randombytes_buf(previous_root_key, sizeof(previous_root_key));

	//print previous root key
	printf("Previous root key (%zi Bytes):\n", sizeof(previous_root_key));
	print_hex(previous_root_key, sizeof(previous_root_key), 30);
	putchar('\n');

	//derive root and chain key for Alice
	unsigned char alice_root_key[crypto_secretbox_KEYBYTES];
	unsigned char alice_chain_key[crypto_secretbox_KEYBYTES];
	status = derive_root_and_chain_key(
			alice_root_key,
			alice_chain_key,
			alice_private_ephemeral,
			alice_public_ephemeral,
			bob_public_ephemeral,
			previous_root_key,
			true);
	sodium_memzero(alice_private_ephemeral, sizeof(alice_private_ephemeral));
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to derive root and chain key for Alice. (%i)\n", status);
		sodium_memzero(alice_root_key, sizeof(alice_root_key));
		sodium_memzero(alice_chain_key, sizeof(alice_chain_key));
		sodium_memzero(bob_private_ephemeral, sizeof(bob_private_ephemeral));
		sodium_memzero(previous_root_key, sizeof(previous_root_key));
		return status;
	}

	//print Alice's root and chain key
	printf("Alice's root key (%zi Bytes):\n", sizeof(alice_root_key));
	print_hex(alice_root_key, sizeof(alice_root_key), 30);
	printf("Alice's chain key (%zi Bytes):\n", sizeof(alice_chain_key));
	print_hex(alice_chain_key, sizeof(alice_chain_key), 30);
	putchar('\n');

	//derive root and chain key for Bob
	unsigned char bob_root_key[crypto_secretbox_KEYBYTES];
	unsigned char bob_chain_key[crypto_secretbox_KEYBYTES];
	status = derive_root_and_chain_key(
			bob_root_key,
			bob_chain_key,
			bob_private_ephemeral,
			bob_public_ephemeral,
			alice_public_ephemeral,
			previous_root_key,
			false);
	sodium_memzero(bob_private_ephemeral, sizeof(bob_private_ephemeral));
	sodium_memzero(previous_root_key, sizeof(previous_root_key));
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to derive root and chain key for Bob. (%i)\n", status);
		sodium_memzero(alice_root_key, sizeof(alice_root_key));
		sodium_memzero(alice_chain_key, sizeof(alice_chain_key));
		sodium_memzero(bob_root_key, sizeof(bob_root_key));
		sodium_memzero(bob_chain_key, sizeof(bob_chain_key));;
		return status;
	}

	//print Bob's root and chain key
	printf("Bob's root key (%zi Bytes):\n", sizeof(bob_root_key));
	print_hex(bob_root_key, sizeof(bob_root_key), 30);
	printf("Bob's chain key (%zi Bytes):\n", sizeof(bob_chain_key));
	print_hex(bob_chain_key, sizeof(bob_chain_key), 30);
	putchar('\n');

	//compare Alice's and Bob's root keys
	if (sodium_memcmp(alice_root_key, bob_root_key, sizeof(bob_root_key)) == 0) {
		printf("Alice's and Bob's root keys match.\n");
	} else {
		fprintf(stderr, "ERROR: Alice's and Bob's root keys don't match.\n");
		sodium_memzero(alice_root_key, sizeof(alice_root_key));
		sodium_memzero(bob_root_key, sizeof(bob_root_key));
		sodium_memzero(alice_chain_key, sizeof(alice_chain_key));
		sodium_memzero(bob_chain_key, sizeof(bob_chain_key));;
		return -1;
	}
	sodium_memzero(alice_root_key, sizeof(alice_root_key));
	sodium_memzero(bob_root_key, sizeof(bob_root_key));

	//compare Alice's and Bob's chain keys
	if (sodium_memcmp(alice_chain_key, bob_chain_key, sizeof(bob_chain_key)) == 0) {
		printf("Alice's and Bob's chain keys match.\n");
	} else {
		fprintf(stderr, "ERROR: Alice's and Bob's chain keys don't match.\n");
		sodium_memzero(alice_chain_key, sizeof(alice_chain_key));
		sodium_memzero(bob_chain_key, sizeof(bob_chain_key));;
		return -1;
	}

	sodium_memzero(alice_chain_key, sizeof(alice_chain_key));
	sodium_memzero(bob_chain_key, sizeof(bob_chain_key));;

	return EXIT_SUCCESS;
}
