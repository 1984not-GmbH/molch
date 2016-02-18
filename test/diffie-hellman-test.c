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
#include "tracing.h"

int main(void) {
	if (sodium_init() == -1) {
		return -1;
	}

	int status;

	//create buffers
	buffer_t *alice_public_key = buffer_create_on_heap(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	buffer_t *alice_private_key = buffer_create_on_heap(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	buffer_t *alice_shared_secret = buffer_create_on_heap(crypto_generichash_BYTES, crypto_generichash_BYTES);
	buffer_t *bob_public_key = buffer_create_on_heap(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	buffer_t *bob_private_key = buffer_create_on_heap(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	buffer_t *bob_shared_secret = buffer_create_on_heap(crypto_generichash_BYTES, crypto_generichash_BYTES);

	//create Alice's keypair
	buffer_create_from_string(alice_string, "Alice");
	buffer_create_from_string(empty_string, "");
	status = generate_and_print_keypair(
			alice_public_key,
			alice_private_key,
			alice_string,
			empty_string);
	if (status != 0) {
		goto cleanup;
	}

	//create Bob's keypair
	buffer_create_from_string(bob_string, "Bob");
	status = generate_and_print_keypair(
			bob_public_key,
			bob_private_key,
			bob_string,
			empty_string);
	if (status != 0) {
		goto cleanup;
	}

	//Diffie Hellman on Alice's side
	status = diffie_hellman(
			alice_shared_secret,
			alice_private_key,
			alice_public_key,
			bob_public_key,
			true);
	buffer_clear(alice_private_key);
	if (status != 0) {
		fprintf(stderr, "ERROR: Diffie Hellman with Alice's private key failed. (%i)\n", status);
		goto cleanup;
	}

	//print Alice's shared secret
	printf("Alice's shared secret ECDH(A_priv, B_pub) (%zu Bytes):\n", alice_shared_secret->content_length);
	print_hex(alice_shared_secret);
	putchar('\n');

	//Diffie Hellman on Bob's side
	status = diffie_hellman(
			bob_shared_secret,
			bob_private_key,
			bob_public_key,
			alice_public_key,
			false);
	buffer_clear(bob_private_key);
	if (status != 0) {
		fprintf(stderr, "ERROR: Diffie Hellman with Bob's private key failed. (%i)\n", status);
		goto cleanup;
	}

	//print Bob's shared secret
	printf("Bob's shared secret ECDH(B_priv, A_pub) (%zu Bytes):\n", bob_shared_secret->content_length);
	print_hex(bob_shared_secret);
	putchar('\n');

	//compare both shared secrets
	status = buffer_compare(alice_shared_secret, bob_shared_secret);
	buffer_clear(alice_shared_secret);
	buffer_clear(bob_shared_secret);
	if (status != 0) {
		fprintf(stderr, "ERROR: Diffie Hellman didn't produce the same shared secret. (%i)\n", status);
		goto cleanup;
	}

	printf("Both shared secrets match!\n");

cleanup:
	buffer_destroy_from_heap(alice_public_key);
	buffer_destroy_from_heap(alice_private_key);
	buffer_destroy_from_heap(alice_shared_secret);
	buffer_destroy_from_heap(bob_public_key);
	buffer_destroy_from_heap(bob_private_key);
	buffer_destroy_from_heap(bob_shared_secret);

	return status;
}
