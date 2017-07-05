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

#include "../lib/diffie-hellman.h"
#include "utils.h"
#include "common.h"

int main(void) {
	if (sodium_init() == -1) {
		return -1;
	}

	return_status status = return_status_init();

	//create buffers
	//alice keys
	buffer_t * const alice_public_identity = buffer_create_on_heap(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	buffer_t * const alice_private_identity = buffer_create_on_heap(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	buffer_t * const alice_public_ephemeral = buffer_create_on_heap(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	buffer_t * const alice_private_ephemeral = buffer_create_on_heap(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	buffer_t * const alice_shared_secret = buffer_create_on_heap(crypto_generichash_BYTES, crypto_generichash_BYTES);
	//bobs keys
	buffer_t * const bob_public_identity = buffer_create_on_heap(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	buffer_t * const bob_private_identity = buffer_create_on_heap(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	buffer_t * const bob_public_ephemeral = buffer_create_on_heap(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	buffer_t * const bob_private_ephemeral = buffer_create_on_heap(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	buffer_t * const bob_shared_secret = buffer_create_on_heap(crypto_generichash_BYTES, crypto_generichash_BYTES);

	printf("Generate Alice's keys -------------------------------------------------------\n\n");

	int status_int = 0;
	//create Alice's identity keypair
	buffer_create_from_string(alice_string, "Alice");
	buffer_create_from_string(identity_string, "identity");
	status = generate_and_print_keypair(
			alice_public_identity,
			alice_private_identity,
			alice_string,
			identity_string);
	throw_on_error(KEYGENERATION_FAILED, "Failed to generate and print Alice' identity keypair.");

	//create Alice's ephemeral keypair
	buffer_create_from_string(ephemeral_string, "ephemeral");
	status = generate_and_print_keypair(
			alice_public_ephemeral,
			alice_private_ephemeral,
			alice_string,
			ephemeral_string);
	throw_on_error(KEYGENERATION_FAILED, "Failed to generate and print Alice' ephemeral keypair.");

	printf("Generate Bob's keys ---------------------------------------------------------\n\n");

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

	printf("Calculate shared secret via Triple Diffie Hellman ---------------------------\n\n");

	//Triple Diffie Hellman on Alice's side
	status = triple_diffie_hellman(
			alice_shared_secret,
			alice_private_identity,
			alice_public_identity,
			alice_private_ephemeral,
			alice_public_ephemeral,
			bob_public_identity,
			bob_public_ephemeral,
			true);
	buffer_clear(alice_private_identity);
	buffer_clear(alice_private_ephemeral);
	throw_on_error(KEYGENERATION_FAILED, "Triple Diffie Hellman for Alice failed.");
	//print Alice's shared secret
	printf("Alice's shared secret H(DH(A_priv,B0_pub)||DH(A0_priv,B_pub)||DH(A0_priv,B0_pub)):\n");
	print_hex(alice_shared_secret);
	putchar('\n');

	//Triple Diffie Hellman on Bob's side
	status = triple_diffie_hellman(
			bob_shared_secret,
			bob_private_identity,
			bob_public_identity,
			bob_private_ephemeral,
			bob_public_ephemeral,
			alice_public_identity,
			alice_public_ephemeral,
			false);
	buffer_clear(bob_private_identity);
	buffer_clear(bob_private_ephemeral);
	throw_on_error(KEYGENERATION_FAILED, "Triple Diffie Hellnan for Bob failed.");
	//print Bob's shared secret
	printf("Bob's shared secret H(DH(B0_priv, A_pub)||DH(B_priv, A0_pub)||DH(B0_priv, A0_pub)):\n");
	print_hex(bob_shared_secret);
	putchar('\n');

	//compare both shared secrets
	status_int = buffer_compare(alice_shared_secret, bob_shared_secret);
	buffer_clear(alice_shared_secret);
	buffer_clear(bob_shared_secret);
	if (status_int != 0) {
		throw(INCORRECT_DATA, "Triple Diffie Hellman didn't produce the same shared secret.");
	}

	printf("Both shared secrets match!\n");

cleanup:
	//alice keys
	buffer_destroy_from_heap(alice_public_identity);
	buffer_destroy_from_heap(alice_private_identity);
	buffer_destroy_from_heap(alice_public_ephemeral);
	buffer_destroy_from_heap(alice_private_ephemeral);
	buffer_destroy_from_heap(alice_shared_secret);
	//bobs keys
	buffer_destroy_from_heap(bob_public_identity);
	buffer_destroy_from_heap(bob_private_identity);
	buffer_destroy_from_heap(bob_public_ephemeral);
	buffer_destroy_from_heap(bob_private_ephemeral);
	buffer_destroy_from_heap(bob_shared_secret);

	on_error {
		print_errors(&status);
	}
	return_status_destroy_errors(&status);

	return status.status;
}
