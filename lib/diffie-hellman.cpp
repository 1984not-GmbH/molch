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
#include "gsl.hpp"

namespace Molch {
	void diffie_hellman(
			Key<DIFFIE_HELLMAN_SIZE,KeyType::Key>& derived_key, //needs to be DIFFIE_HELLMAN_SIZE long
			const PrivateKey& our_private_key, //needs to be PRIVATE_KEY_SIZE long
			const PublicKey& our_public_key, //needs to be PUBLIC_KEY_SIZE long
			const PublicKey& their_public_key, //needs to be PUBLIC_KEY_SIZE long
			const Ratchet::Role role) {
		Expects(!our_private_key.empty
				&& !our_public_key.empty
				&& !their_public_key.empty);

		//make sure that the assumptions are correct
		static_assert(PUBLIC_KEY_SIZE == crypto_scalarmult_SCALARBYTES, "crypto_scalarmult_SCALARBYTES is not PUBLIC_KEY_SIZE");
		static_assert(PRIVATE_KEY_SIZE == crypto_scalarmult_SCALARBYTES, "crypto_scalarmult_SCALARBYTES is not PRIVATE_KEY_BYTES");
		static_assert(DIFFIE_HELLMAN_SIZE == crypto_generichash_BYTES, "crypto_generichash_bytes is not DIFFIE_HELLMAN_SIZE");

		//buffer for diffie hellman shared secret
		Key<crypto_scalarmult_SCALARBYTES,KeyType::Key> dh_secret;

		//do the diffie hellman key exchange
		auto status{crypto_scalarmult(
				byte_to_uchar(dh_secret.data()),
				byte_to_uchar(our_private_key.data()),
				byte_to_uchar(their_public_key.data()))};
		if (status != 0) {
			throw Exception{status_type::KEYDERIVATION_FAILED, "Failed to do crypto_scalarmult."};
		}
		dh_secret.empty = false;

		//initialize hashing
		autozero<crypto_generichash_state> hash_state;
		status = crypto_generichash_init(
				hash_state.pointer(),
				nullptr, //key
				0, //key_length
				DIFFIE_HELLMAN_SIZE); //output length
		if (status != 0) {
			throw Exception{status_type::GENERIC_ERROR, "Failed to initialize hash."};
		}

		//start input to hash with diffie hellman secret
		status = crypto_generichash_update(
				hash_state.pointer(),
				byte_to_uchar(dh_secret.data()),
				dh_secret.size());
		if (status != 0) {
			throw Exception{status_type::GENERIC_ERROR, "Failed to add the diffie hellman secret to the hash input."};
		}

		//add public keys to the input of the hash
		switch (role) {
			case Ratchet::Role::ALICE: //Alice (our_public_key|their_public_key)
				//add our_public_key to the input of the hash
				status = crypto_generichash_update(
						hash_state.pointer(),
						byte_to_uchar(our_public_key.data()),
						our_public_key.size());
				if (status != 0) {
					throw Exception{status_type::GENERIC_ERROR, "Failed to add Alice' public key to the hash input."};
				}

				//add their_public_key to the input of the hash
				status = crypto_generichash_update(
						hash_state.pointer(),
						byte_to_uchar(their_public_key.data()),
						their_public_key.size());
				if (status != 0) {
					throw Exception{status_type::GENERIC_ERROR, "Failed to add Bob's public key to the hash input."};
				}
				break;

			case Ratchet::Role::BOB: //Bob (their_public_key|our_public_key)
				//add their_public_key to the input of the hash
				status = crypto_generichash_update(
						hash_state.pointer(),
						byte_to_uchar(their_public_key.data()),
						their_public_key.size());
				if (status != 0) {
					throw Exception{status_type::GENERIC_ERROR, "Failed to add Alice's public key to the hash input."};
				}

				//add our_public_key to the input of the hash
				status = crypto_generichash_update(
						hash_state.pointer(),
						byte_to_uchar(our_public_key.data()),
						our_public_key.size());
				if (status != 0) {
					throw Exception{status_type::GENERIC_ERROR, "Failed to add Bob's public key to the hash input."};
				}
				break;

			default:
				break;
		}

		//finally write the hash to derived_key
		status = crypto_generichash_final(
				hash_state.pointer(),
				byte_to_uchar(derived_key.data()),
				derived_key.size());
		if (status != 0) {
			throw Exception{status_type::GENERIC_ERROR, "Failed to finalize hash."};
		}
		derived_key.empty = false;
	}

	void triple_diffie_hellman(
			Key<DIFFIE_HELLMAN_SIZE,KeyType::Key>& derived_key,
			const PrivateKey& our_private_identity,
			const PublicKey& our_public_identity,
			const PrivateKey& our_private_ephemeral,
			const PublicKey& our_public_ephemeral,
			const PublicKey& their_public_identity,
			const PublicKey& their_public_ephemeral,
			const Ratchet::Role role) {
		Expects(!our_private_identity.empty
				&& !our_public_identity.empty
				&& !their_public_identity.empty
				&& !our_private_ephemeral.empty
				&& !our_public_ephemeral.empty
				&& !their_public_ephemeral.empty);

		//buffers for all 3 Diffie Hellman exchanges
		Key<DIFFIE_HELLMAN_SIZE,KeyType::Key> dh1;
		Key<DIFFIE_HELLMAN_SIZE,KeyType::Key> dh2;
		Key<DIFFIE_HELLMAN_SIZE,KeyType::Key> dh3;
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
		auto status{crypto_generichash_init(
				hash_state.pointer(),
				nullptr, //key
				0, //key_length
				DIFFIE_HELLMAN_SIZE)}; //output_length
		if (status != 0) {
			throw Exception{status_type::GENERIC_ERROR, "Failed to initialize hash."};
		}

		//add dh1 to hash input
		status = crypto_generichash_update(
				hash_state.pointer(),
				byte_to_uchar(dh1.data()),
				dh1.size());
		if (status != 0) {
			throw Exception{status_type::GENERIC_ERROR, "Failed to add dh1 to the hash input."};
		}

		//add dh2 to hash input
		status = crypto_generichash_update(
				hash_state.pointer(),
				byte_to_uchar(dh2.data()),
				dh2.size());
		if (status != 0) {
			throw Exception{status_type::GENERIC_ERROR, "Failed to add dh2 to the hash input."};
		}

		//add dh3 to hash input
		status = crypto_generichash_update(
				hash_state.pointer(),
				byte_to_uchar(dh3.data()),
				dh3.size());
		if (status != 0) {
			throw Exception{status_type::GENERIC_ERROR, "Failed to add dh3 to the hash input."};
		}

		//write final hash to output (derived_key)
		status = crypto_generichash_final(
				hash_state.pointer(),
				byte_to_uchar(derived_key.data()),
				derived_key.size());
		if (status != 0) {
			throw Exception{status_type::GENERIC_ERROR, "Failed to finalize hash"};
		}
		derived_key.empty = false;
	}
}
