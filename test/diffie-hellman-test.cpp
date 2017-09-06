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

using namespace Molch;

int main(void) noexcept {
	try {
		Molch::sodium_init();

		//create Alice's keypair
		PublicKey alice_public_key;
		PrivateKey alice_private_key;
		generate_and_print_keypair(
			alice_public_key,
			alice_private_key,
			"Alice",
			"");

		//create Bob's keypair
		PublicKey bob_public_key;
		PrivateKey bob_private_key;
		generate_and_print_keypair(
			bob_public_key,
			bob_private_key,
			"Bob",
			"");

		//Diffie Hellman on Alice's side
		Molch::Key<DIFFIE_HELLMAN_SIZE,Molch::KeyType::Key> alice_shared_secret;
		diffie_hellman(
			alice_shared_secret,
			alice_private_key,
			alice_public_key,
			bob_public_key,
			Ratchet::Role::ALICE);
		alice_private_key.clear();

		//print Alice's shared secret
		printf("Alice's shared secret ECDH(A_priv, B_pub) (%zu Bytes):\n", alice_shared_secret.size());
		alice_shared_secret.printHex(std::cout) << std::endl;

		//Diffie Hellman on Bob's side
		Molch::Key<DIFFIE_HELLMAN_SIZE,Molch::KeyType::Key> bob_shared_secret;
		diffie_hellman(
			bob_shared_secret,
			bob_private_key,
			bob_public_key,
			alice_public_key,
			Ratchet::Role::BOB);
		bob_private_key.clear();

		//print Bob's shared secret
		printf("Bob's shared secret ECDH(B_priv, A_pub) (%zu Bytes):\n", bob_shared_secret.size());
		bob_shared_secret.printHex(std::cout) << std::endl;

		//compare both shared secrets
		if (alice_shared_secret != bob_shared_secret) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Diffie Hellman didn't produce the same shared secret."};
		}

		printf("Both shared secrets match!\n");
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
