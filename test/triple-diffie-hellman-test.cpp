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
#include "../lib/molch-exception.hpp"
#include "utils.hpp"
#include "common.hpp"

int main(void) noexcept {
	try {
		if (sodium_init() == -1) {
			return -1;
		}

		printf("Generate Alice's keys -------------------------------------------------------\n\n");

		//create Alice's identity keypair
		Buffer alice_public_identity(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
		Buffer alice_private_identity(PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
		exception_on_invalid_buffer(alice_public_identity);
		exception_on_invalid_buffer(alice_private_identity);
		generate_and_print_keypair(
			alice_public_identity,
			alice_private_identity,
			"Alice",
			"identity");

		//create Alice's ephemeral keypair
		Buffer alice_public_ephemeral(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
		Buffer alice_private_ephemeral(PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
		exception_on_invalid_buffer(alice_public_ephemeral);
		exception_on_invalid_buffer(alice_private_ephemeral);
		generate_and_print_keypair(
			alice_public_ephemeral,
			alice_private_ephemeral,
			"Alice",
			"ephemeral");

		printf("Generate Bob's keys ---------------------------------------------------------\n\n");

		//create Bob's identity keypair
		Buffer bob_public_identity(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
		Buffer bob_private_identity(PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
		exception_on_invalid_buffer(bob_public_identity);
		exception_on_invalid_buffer(bob_private_identity);
		generate_and_print_keypair(
			bob_public_identity,
			bob_private_identity,
			"Bob",
			"identity");

		//create Bob's ephemeral keypair
		Buffer bob_public_ephemeral(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
		Buffer bob_private_ephemeral(PRIVATE_KEY_SIZE, PRIVATE_KEY_SIZE);
		exception_on_invalid_buffer(bob_public_ephemeral);
		exception_on_invalid_buffer(bob_private_ephemeral);
		generate_and_print_keypair(
			bob_public_ephemeral,
			bob_private_ephemeral,
			"Bob",
			"ephemeral");

		printf("Calculate shared secret via Triple Diffie Hellman ---------------------------\n\n");

		//Triple Diffie Hellman on Alice's side
		Buffer alice_shared_secret(crypto_generichash_BYTES, crypto_generichash_BYTES);
		exception_on_invalid_buffer(alice_shared_secret);
		triple_diffie_hellman(
			alice_shared_secret,
			alice_private_identity,
			alice_public_identity,
			alice_private_ephemeral,
			alice_public_ephemeral,
			bob_public_identity,
			bob_public_ephemeral,
			true);

		//print Alice's shared secret
		printf("Alice's shared secret H(DH(A_priv,B0_pub)||DH(A0_priv,B_pub)||DH(A0_priv,B0_pub)):\n");
		std::cout << alice_shared_secret.toHex();
		putchar('\n');

		//Triple Diffie Hellman on Bob's side
		Buffer bob_shared_secret(crypto_generichash_BYTES, crypto_generichash_BYTES);
		exception_on_invalid_buffer(bob_shared_secret);
		triple_diffie_hellman(
			bob_shared_secret,
			bob_private_identity,
			bob_public_identity,
			bob_private_ephemeral,
			bob_public_ephemeral,
			alice_public_identity,
			alice_public_ephemeral,
			false);

		//print Bob's shared secret
		printf("Bob's shared secret H(DH(B0_priv, A_pub)||DH(B_priv, A0_pub)||DH(B0_priv, A0_pub)):\n");
		std::cout << bob_shared_secret.toHex();
		putchar('\n');

		//compare both shared secrets
		if (alice_shared_secret != bob_shared_secret) {
			throw MolchException(INCORRECT_DATA, "Triple Diffie Hellman didn't produce the same shared secret.");
		}

		printf("Both shared secrets match!\n");
	} catch (const MolchException& exception) {
		exception.print(std::cout) << std::endl;
		return EXIT_FAILURE;
	} catch (const std::exception& exception) {
		std::cout << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
