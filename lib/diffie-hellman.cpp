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
#include <sodium.h>

#include "constants.h"
#include "diffie-hellman.hpp"
#include "molch-exception.hpp"
#include "autozero.hpp"

void diffie_hellman(
		Buffer& derived_key, //needs to be DIFFIE_HELLMAN_SIZE long
		const Buffer& our_private_key, //needs to be PRIVATE_KEY_SIZE long
		const Buffer& our_public_key, //needs to be PUBLIC_KEY_SIZE long
		const Buffer& their_public_key, //needs to be PUBLIC_KEY_SIZE long
		const Ratchet::Role role) {
	//make sure that the assumptions are correct
	static_assert(PUBLIC_KEY_SIZE == crypto_scalarmult_SCALARBYTES, "crypto_scalarmult_SCALARBYTES is not PUBLIC_KEY_SIZE");
	static_assert(PRIVATE_KEY_SIZE == crypto_scalarmult_SCALARBYTES, "crypto_scalarmult_SCALARBYTES is not PRIVATE_KEY_BYTES");
	static_assert(DIFFIE_HELLMAN_SIZE == crypto_generichash_BYTES, "crypto_generichash_bytes is not DIFFIE_HELLMAN_SIZE");

	//set size of output to 0 (can prevent use on failure)
	derived_key.size = 0;

	//check buffer sizes
	if (!derived_key.fits(DIFFIE_HELLMAN_SIZE)
			|| !our_private_key.contains(PRIVATE_KEY_SIZE)
			|| !our_public_key.contains(PUBLIC_KEY_SIZE)
			|| !their_public_key.contains(PUBLIC_KEY_SIZE)) {
		throw MolchException(INVALID_INPUT, "Invalid input to diffie_hellman.");
	}

	//buffer for diffie hellman shared secret
	Buffer dh_secret(crypto_scalarmult_SCALARBYTES, crypto_scalarmult_SCALARBYTES);

	//do the diffie hellman key exchange
	if (crypto_scalarmult(dh_secret.content, our_private_key.content, their_public_key.content) != 0) {
		throw MolchException(KEYDERIVATION_FAILED, "Failed to do crypto_scalarmult.");
	}

	//initialize hashing
	autozero<crypto_generichash_state> hash_state;
	int status_int = crypto_generichash_init(
			hash_state.pointer(),
			nullptr, //key
			0, //key_length
			DIFFIE_HELLMAN_SIZE); //output length
	if (status_int != 0) {
		throw MolchException(GENERIC_ERROR, "Failed to initialize hash.");
	}

	//start input to hash with diffie hellman secret
	if (crypto_generichash_update(hash_state.pointer(), dh_secret.content, dh_secret.size) != 0) {
		throw MolchException(GENERIC_ERROR, "Failed to add the diffie hellman secret to the hash input.");
	}

	//add public keys to the input of the hash
	switch (role) {
		case Ratchet::Role::ALICE: //Alice (our_public_key|their_public_key)
			//add our_public_key to the input of the hash
			if (crypto_generichash_update(hash_state.pointer(), our_public_key.content, our_public_key.size) != 0) {
				throw MolchException(GENERIC_ERROR, "Failed to add Alice' public key to the hash input.");
			}

			//add their_public_key to the input of the hash
			if (crypto_generichash_update(hash_state.pointer(), their_public_key.content, their_public_key.size) != 0) {
				throw MolchException(GENERIC_ERROR, "Failed to add Bob's public key to the hash input.");
			}
			break;

		case Ratchet::Role::BOB: //Bob (their_public_key|our_public_key)
			//add their_public_key to the input of the hash
			if (crypto_generichash_update(hash_state.pointer(), their_public_key.content, their_public_key.size) != 0) {
				throw MolchException(GENERIC_ERROR, "Failed to add Alice's public key to the hash input.");
			}

			//add our_public_key to the input of the hash
			if (crypto_generichash_update(hash_state.pointer(), our_public_key.content, our_public_key.size) != 0) {
				throw MolchException(GENERIC_ERROR, "Failed to add Bob's public key to the hash input.");
			}
			break;

		default:
			break;
	}

	//finally write the hash to derived_key
	if (crypto_generichash_final(hash_state.pointer(), derived_key.content, DIFFIE_HELLMAN_SIZE) != 0) {
		throw MolchException(GENERIC_ERROR, "Failed to finalize hash.");
	}
	derived_key.size = DIFFIE_HELLMAN_SIZE;
}

void triple_diffie_hellman(
		Buffer& derived_key,
		const Buffer& our_private_identity,
		const Buffer& our_public_identity,
		const Buffer& our_private_ephemeral,
		const Buffer& our_public_ephemeral,
		const Buffer& their_public_identity,
		const Buffer& their_public_ephemeral,
		const Ratchet::Role role) {
	//set content length of output to 0 (can prevent use on failure)
	derived_key.size = 0;

	//check buffer sizes
	if (!derived_key.fits(DIFFIE_HELLMAN_SIZE)
			|| !our_private_identity.contains(PRIVATE_KEY_SIZE)
			|| !our_public_identity.contains(PUBLIC_KEY_SIZE)
			|| !their_public_identity.contains(PUBLIC_KEY_SIZE)
			|| !our_private_ephemeral.contains(PRIVATE_KEY_SIZE)
			|| !our_public_ephemeral.contains(PUBLIC_KEY_SIZE)
			|| !their_public_ephemeral.contains(PUBLIC_KEY_SIZE)) {
		throw MolchException(INVALID_INPUT, "Invalid input to triple_diffie_hellman.");
	}

	//buffers for all 3 Diffie Hellman exchanges
	Buffer dh1(DIFFIE_HELLMAN_SIZE, DIFFIE_HELLMAN_SIZE);
	Buffer dh2(DIFFIE_HELLMAN_SIZE, DIFFIE_HELLMAN_SIZE);
	Buffer dh3(DIFFIE_HELLMAN_SIZE, DIFFIE_HELLMAN_SIZE);
	switch (role) {
		case Ratchet::Role::ALICE:
			//DH(our_identity, their_ephemeral)
			diffie_hellman(
				dh1,
				our_private_identity,
				our_public_identity,
				their_public_ephemeral,
				role);

			//DH(our_ephemeral, their_identity)
			diffie_hellman(
				dh2,
				our_private_ephemeral,
				our_public_ephemeral,
				their_public_identity,
				role);
			break;

		case Ratchet::Role::BOB:
			//DH(our_ephemeral, their_identity)
			diffie_hellman(
				dh1,
				our_private_ephemeral,
				our_public_ephemeral,
				their_public_identity,
				role);

			//DH(our_identity, their_ephemeral)
			diffie_hellman(
				dh2,
				our_private_identity,
				our_public_identity,
				their_public_ephemeral,
				role);
			break;

		default:
			break;
	}

	//DH(our_ephemeral, their_ephemeral)
	//this is identical for both Alice and Bob
	diffie_hellman(
		dh3,
		our_private_ephemeral,
		our_public_ephemeral,
		their_public_ephemeral,
		role);

	//now calculate HASH(DH(A,B0) || DH(A0,B) || DH(A0,B0))
	//( HASH(dh1|| dh2 || dh3) )

	//initialize hashing
	autozero<crypto_generichash_state> hash_state;
	int status_int = crypto_generichash_init(
			hash_state.pointer(),
			nullptr, //key
			0, //key_length
			DIFFIE_HELLMAN_SIZE); //output_length
	if (status_int != 0) {
		throw MolchException(GENERIC_ERROR, "Failed to initialize hash.");
	}

	//add dh1 to hash input
	if (crypto_generichash_update(hash_state.pointer(), dh1.content, DIFFIE_HELLMAN_SIZE) != 0) {
		throw MolchException(GENERIC_ERROR, "Failed to add dh1 to the hash input.");
	}

	//add dh2 to hash input
	if (crypto_generichash_update(hash_state.pointer(), dh2.content, DIFFIE_HELLMAN_SIZE) != 0) {
		throw MolchException(GENERIC_ERROR, "Failed to add dh2 to the hash input.");
	}

	//add dh3 to hash input
	if (crypto_generichash_update(hash_state.pointer(), dh3.content, DIFFIE_HELLMAN_SIZE) != 0) {
		throw MolchException(GENERIC_ERROR, "Failed to add dh3 to the hash input.");
	}

	//write final hash to output (derived_key)
	if (crypto_generichash_final(hash_state.pointer(), derived_key.content, DIFFIE_HELLMAN_SIZE) != 0) {
		throw MolchException(GENERIC_ERROR, "Failed to finalize hash");
	}
	derived_key.size = DIFFIE_HELLMAN_SIZE;
}
