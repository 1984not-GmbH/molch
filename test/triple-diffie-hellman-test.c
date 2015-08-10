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

#include "../lib/diffie-hellman.h"
#include "utils.h"
#include "common.h"

int main(void) {
	sodium_init();

	int status;

	printf("Generate Alice's keys -------------------------------------------------------\n\n");

	//create Alice's identity keypair
	unsigned char alice_public_identity[crypto_box_PUBLICKEYBYTES];
	unsigned char alice_private_identity[crypto_box_SECRETKEYBYTES];
	status = generate_and_print_keypair(
			alice_public_identity,
			alice_private_identity,
			"Alice",
			"identity");
	if (status != 0) {
		sodium_memzero(alice_private_identity, crypto_box_SECRETKEYBYTES);
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
		sodium_memzero(alice_private_ephemeral, crypto_box_SECRETKEYBYTES);
		sodium_memzero(alice_private_identity, crypto_box_SECRETKEYBYTES);
		return status;
	}

	printf("Generate Bob's keys ---------------------------------------------------------\n\n");

	//create Bob's identity keypair
	unsigned char bob_public_identity[crypto_box_PUBLICKEYBYTES];
	unsigned char bob_private_identity[crypto_box_SECRETKEYBYTES];
	status = generate_and_print_keypair(
			bob_public_identity,
			bob_private_identity,
			"Bob",
			"identity");
	if (status != 0) {
		sodium_memzero(alice_private_identity, crypto_box_SECRETKEYBYTES);
		sodium_memzero(alice_private_ephemeral, crypto_box_SECRETKEYBYTES);
		sodium_memzero(bob_private_identity, crypto_box_SECRETKEYBYTES);
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
		sodium_memzero(alice_private_identity, crypto_box_SECRETKEYBYTES);
		sodium_memzero(alice_private_ephemeral, crypto_box_SECRETKEYBYTES);
		sodium_memzero(bob_private_identity, crypto_box_SECRETKEYBYTES);
		sodium_memzero(bob_private_ephemeral, crypto_box_SECRETKEYBYTES);
		return status;
	}

	printf("Calculate shared secret via Triple Diffie Hellman ---------------------------\n\n");

	//Triple Diffie Hellman on Alice's side
	unsigned char alice_shared_secret[crypto_generichash_BYTES];
	status = triple_diffie_hellman(
			alice_shared_secret,
			alice_private_identity,
			alice_public_identity,
			alice_private_ephemeral,
			alice_public_ephemeral,
			bob_public_identity,
			bob_public_ephemeral,
			true);
	sodium_memzero(alice_private_identity, crypto_box_SECRETKEYBYTES);
	sodium_memzero(alice_private_ephemeral, crypto_box_SECRETKEYBYTES);
	if (status != 0) {
		fprintf(stderr, "ERROR: Triple Diffie Hellman for Alice failed. (%i)\n", status);
		sodium_memzero(alice_shared_secret, crypto_generichash_BYTES);
		sodium_memzero(bob_private_identity, crypto_box_SECRETKEYBYTES);
		sodium_memzero(bob_private_ephemeral, crypto_box_SECRETKEYBYTES);
		return status;
	}
	//print Alice's shared secret
	printf("Alice's shared secret H(DH(A_priv,B0_pub)||DH(A0_priv,B_pub)||DH(A0_priv,B0_pub)):\n");
	print_hex(alice_shared_secret, crypto_generichash_BYTES, 30);
	putchar('\n');

	//Triple Diffie Hellman on Bob's side
	unsigned char bob_shared_secret[crypto_generichash_BYTES];
	status = triple_diffie_hellman(
			bob_shared_secret,
			bob_private_identity,
			bob_public_identity,
			bob_private_ephemeral,
			bob_public_ephemeral,
			alice_public_identity,
			alice_public_ephemeral,
			false);
	sodium_memzero(bob_private_identity, crypto_box_SECRETKEYBYTES);
	sodium_memzero(bob_private_ephemeral, crypto_box_SECRETKEYBYTES);
	if (status != 0) {
		fprintf(stderr, "ERROR: Triple Diffie Hellman for Bob failed. (%i)\n", status);
		sodium_memzero(bob_shared_secret, crypto_generichash_BYTES);
	}
	//print Bob's shared secret
	printf("Bob's shared secret H(DH(B0_priv, A_pub)||DH(B_priv, A0_pub)||DH(B0_priv, A0_pub)):\n");
	print_hex(bob_shared_secret, crypto_generichash_BYTES, 30);
	putchar('\n');

	//compare both shared secrets
	status = sodium_memcmp(alice_shared_secret, bob_shared_secret, crypto_generichash_BYTES);
	sodium_memzero(alice_shared_secret, crypto_generichash_BYTES);
	sodium_memzero(bob_shared_secret, crypto_generichash_BYTES);
	if (status != 0) {
		fprintf(stderr, "ERROR: Triple Diffie Hellman didn't produce the same shared secret. (%i)\n", status);
		return status;
	}

	printf("Both shared secrets match!\n");

	return EXIT_SUCCESS;
}
