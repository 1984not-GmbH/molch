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
#include "exception.hpp"

using namespace Molch;

int main() {
	try {
		TRY_VOID(Molch::sodium_init());

		std::cout << "Generate Alice's keys -------------------------------------------------------\n\n";

		//create Alice's identity keypair
		PublicKey alice_public_identity;
		PrivateKey alice_private_identity;
		generate_and_print_keypair(
			alice_public_identity,
			alice_private_identity,
			"Alice",
			"identity");

		//create Alice's ephemeral keypair
		PublicKey alice_public_ephemeral;
		PrivateKey alice_private_ephemeral;
		generate_and_print_keypair(
			alice_public_ephemeral,
			alice_private_ephemeral,
			"Alice",
			"ephemeral");

		std::cout << "Generate Bob's keys ---------------------------------------------------------\n\n";

		//create Bob's identity keypair
		PublicKey bob_public_identity;
		PrivateKey bob_private_identity;
		generate_and_print_keypair(
			bob_public_identity,
			bob_private_identity,
			"Bob",
			"identity");

		//create Bob's ephemeral keypair
		PublicKey bob_public_ephemeral;
		PrivateKey bob_private_ephemeral;
		generate_and_print_keypair(
			bob_public_ephemeral,
			bob_private_ephemeral,
			"Bob",
			"ephemeral");

		std::cout << "Calculate shared secret via Triple Diffie Hellman ---------------------------\n\n";

		//Triple Diffie Hellman on Alice's side
		TRY_WITH_RESULT(alice_shared_secret_result, triple_diffie_hellman(
			alice_private_identity,
			alice_public_identity,
			alice_private_ephemeral,
			alice_public_ephemeral,
			bob_public_identity,
			bob_public_ephemeral,
			Ratchet::Role::ALICE));
		const auto& alice_shared_secret{alice_shared_secret_result.value()};

		//print Alice's shared secret
		std::cout << "Alice's shared secret H(DH(A_priv,B0_pub)||DH(A0_priv,B_pub)||DH(A0_priv,B0_pub)):\n";
		std::cout << alice_shared_secret << std::endl;

		//Triple Diffie Hellman on Bob's side
		TRY_WITH_RESULT(bob_shared_secret_result, triple_diffie_hellman(
			bob_private_identity,
			bob_public_identity,
			bob_private_ephemeral,
			bob_public_ephemeral,
			alice_public_identity,
			alice_public_ephemeral,
			Ratchet::Role::BOB));
		const auto& bob_shared_secret{bob_shared_secret_result.value()};

		//print Bob's shared secret
		std::cout << "Bob's shared secret H(DH(B0_priv, A_pub)||DH(B_priv, A0_pub)||DH(B0_priv, A0_pub)):\n";
		std::cout << bob_shared_secret << std::endl;

		//compare both shared secrets
		if (alice_shared_secret != bob_shared_secret) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Triple Diffie Hellman didn't produce the same shared secret."};
		}

		std::cout << "Both shared secrets match!\n";
	} catch (const std::exception& exception) {
		std::cout << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
