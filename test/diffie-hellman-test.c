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
	buffer_t *alice_public_key = buffer_create_on_heap(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	buffer_t *alice_private_key = buffer_create_on_heap(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	buffer_t *alice_shared_secret = buffer_create_on_heap(crypto_generichash_BYTES, crypto_generichash_BYTES);
	buffer_t *bob_public_key = buffer_create_on_heap(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	buffer_t *bob_private_key = buffer_create_on_heap(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	buffer_t *bob_shared_secret = buffer_create_on_heap(crypto_generichash_BYTES, crypto_generichash_BYTES);

	int status_int = 0;
	//create Alice's keypair
	buffer_create_from_string(alice_string, "Alice");
	buffer_create_from_string(empty_string, "");
	status = generate_and_print_keypair(
			alice_public_key,
			alice_private_key,
			alice_string,
			empty_string);
	throw_on_error(KEYGENERATION_FAILED, "Failed to generate and print Alice's keypair.");

	//create Bob's keypair
	buffer_create_from_string(bob_string, "Bob");
	status = generate_and_print_keypair(
			bob_public_key,
			bob_private_key,
			bob_string,
			empty_string);
	throw_on_error(KEYGENERATION_FAILED, "Failed to generate and print Bob's keypair.");

	//Diffie Hellman on Alice's side
	status = diffie_hellman(
			alice_shared_secret,
			alice_private_key,
			alice_public_key,
			bob_public_key,
			true);
	buffer_clear(alice_private_key);
	throw_on_error(KEYGENERATION_FAILED, "Diffie Hellman with Alice's private key failed.");

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
	throw_on_error(KEYGENERATION_FAILED, "Diffie Hellman with Bob's private key failed.");

	//print Bob's shared secret
	printf("Bob's shared secret ECDH(B_priv, A_pub) (%zu Bytes):\n", bob_shared_secret->content_length);
	print_hex(bob_shared_secret);
	putchar('\n');

	//compare both shared secrets
	status_int = buffer_compare(alice_shared_secret, bob_shared_secret);
	buffer_clear(alice_shared_secret);
	buffer_clear(bob_shared_secret);
	if (status_int != 0) {
		throw(INCORRECT_DATA, "Diffie Hellman didn't produce the same shared secret.");
	}

	printf("Both shared secrets match!\n");

cleanup:
	buffer_destroy_from_heap_and_null_if_valid(alice_public_key);
	buffer_destroy_from_heap_and_null_if_valid(alice_private_key);
	buffer_destroy_from_heap_and_null_if_valid(alice_shared_secret);
	buffer_destroy_from_heap_and_null_if_valid(bob_public_key);
	buffer_destroy_from_heap_and_null_if_valid(bob_private_key);
	buffer_destroy_from_heap_and_null_if_valid(bob_shared_secret);

	on_error {
		print_errors(&status);
	}
	return_status_destroy_errors(&status);

	return status.status;
}
