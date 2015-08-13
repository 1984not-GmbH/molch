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

#include "../lib/ratchet.h"
#include "utils.h"
#include "common.h"

int main(void) {
	sodium_init();

	int status;

	//creating Alice's identity keypair
	unsigned char alice_private_identity[crypto_box_SECRETKEYBYTES];
	unsigned char alice_public_identity[crypto_box_PUBLICKEYBYTES];
	status = generate_and_print_keypair(
			alice_public_identity,
			alice_private_identity,
			"Alice",
			"identity");
	if (status != 0) {
		sodium_memzero(alice_private_identity, sizeof(alice_private_identity));
		return status;
	}

	//creating Alice's ephemeral keypair
	unsigned char alice_private_ephemeral[crypto_box_SECRETKEYBYTES];
	unsigned char alice_public_ephemeral[crypto_box_PUBLICKEYBYTES];
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

	//creating Bob's identity keypair
	unsigned char bob_private_identity[crypto_box_SECRETKEYBYTES];
	unsigned char bob_public_identity[crypto_box_PUBLICKEYBYTES];
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

	//creating Bob's ephemeral keypair
	unsigned char bob_private_ephemeral[crypto_box_SECRETKEYBYTES];
	unsigned char bob_public_ephemeral[crypto_box_PUBLICKEYBYTES];
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

	//start new ratchet for alice
	printf("Creating new ratchet for Alice ...\n");
	ratchet_state *alice_state = ratchet_create(
			alice_private_identity,
			alice_public_identity,
			bob_public_identity,
			alice_private_ephemeral,
			alice_public_ephemeral,
			bob_public_ephemeral,
			true);
	if (alice_state == NULL) {
		sodium_memzero(alice_private_identity, sizeof(alice_private_identity));
		sodium_memzero(alice_private_ephemeral, sizeof(alice_private_ephemeral));
		sodium_memzero(bob_private_identity, sizeof(bob_private_identity));
		sodium_memzero(bob_private_ephemeral, sizeof(bob_private_ephemeral));
		return EXIT_FAILURE;
	}

	//destroy the ratchet again
	printf("Destroying Alice's ratchet ...\n");
	ratchet_destroy(alice_state);

	//TODO test everything else

	sodium_memzero(alice_private_identity, sizeof(alice_private_identity));
	sodium_memzero(alice_private_ephemeral, sizeof(alice_private_ephemeral));
	sodium_memzero(bob_private_identity, sizeof(bob_private_identity));
	sodium_memzero(bob_private_ephemeral, sizeof(bob_private_ephemeral));

	return EXIT_SUCCESS;
}
