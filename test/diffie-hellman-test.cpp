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
#include <cstdio>
#include <cstdlib>
#include <sodium.h>
#include <exception>
#include <iostream>

#include "../lib/diffie-hellman.hpp"
#include "utils.hpp"
#include "common.hpp"
#include "../lib/molch-exception.hpp"

int main(void) noexcept {
	try {
		if (sodium_init() == -1) {
			throw MolchException(INIT_ERROR, "Failed to initialize libsodium.");
		}

		int status_int = 0;

		//create Alice's keypair
		Buffer alice_public_key(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
		Buffer alice_private_key(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
		exception_on_invalid_buffer(alice_public_key);
		exception_on_invalid_buffer(alice_private_key);
		generate_and_print_keypair(
			alice_public_key,
			alice_private_key,
			"Alice",
			"");

		//create Bob's keypair
		Buffer bob_public_key(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
		Buffer bob_private_key(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
		exception_on_invalid_buffer(bob_public_key);
		exception_on_invalid_buffer(bob_private_key);
		generate_and_print_keypair(
			bob_public_key,
			bob_private_key,
			"Bob",
			"");

		//Diffie Hellman on Alice's side
		Buffer alice_shared_secret(crypto_generichash_BYTES, crypto_generichash_BYTES);
		exception_on_invalid_buffer(alice_shared_secret);
		diffie_hellman(
			alice_shared_secret,
			alice_private_key,
			alice_public_key,
			bob_public_key,
			true);
		alice_private_key.clear();

		//print Alice's shared secret
		printf("Alice's shared secret ECDH(A_priv, B_pub) (%zu Bytes):\n", alice_shared_secret.content_length);
		std::cout << alice_shared_secret.toHex();
		putchar('\n');

		//Diffie Hellman on Bob's side
		Buffer bob_shared_secret(crypto_generichash_BYTES, crypto_generichash_BYTES);
		exception_on_invalid_buffer(bob_shared_secret);
		diffie_hellman(
			bob_shared_secret,
			bob_private_key,
			bob_public_key,
			alice_public_key,
			false);
		bob_private_key.clear();

		//print Bob's shared secret
		printf("Bob's shared secret ECDH(B_priv, A_pub) (%zu Bytes):\n", bob_shared_secret.content_length);
		std::cout << bob_shared_secret.toHex();
		putchar('\n');

		//compare both shared secrets
		status_int = alice_shared_secret.compare(&bob_shared_secret);
		alice_shared_secret.clear();
		bob_shared_secret.clear();
		if (status_int != 0) {
			throw MolchException(INCORRECT_DATA, "Diffie Hellman didn't produce the same shared secret.");
		}

		printf("Both shared secrets match!\n");
	} catch (const MolchException& exception) {
		exception.print(std::cerr) << std::endl;
		return EXIT_FAILURE;
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
