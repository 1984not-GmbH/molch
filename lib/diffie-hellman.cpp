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
#include "exception.hpp"
#include "gsl.hpp"

namespace Molch {
	result<Key<DIFFIE_HELLMAN_SIZE,KeyType::Key>> diffie_hellman(
			const PrivateKey& our_private_key, //needs to be PRIVATE_KEY_SIZE long
			const PublicKey& our_public_key, //needs to be PUBLIC_KEY_SIZE long
			const PublicKey& their_public_key, //needs to be PUBLIC_KEY_SIZE long
			const Ratchet::Role role) {
		//make sure that the assumptions are correct
		static_assert(PUBLIC_KEY_SIZE == crypto_scalarmult_SCALARBYTES, "crypto_scalarmult_SCALARBYTES is not PUBLIC_KEY_SIZE");
		static_assert(PRIVATE_KEY_SIZE == crypto_scalarmult_SCALARBYTES, "crypto_scalarmult_SCALARBYTES is not PRIVATE_KEY_BYTES");
		static_assert(DIFFIE_HELLMAN_SIZE == crypto_generichash_BYTES, "crypto_generichash_bytes is not DIFFIE_HELLMAN_SIZE");

		//buffer for diffie hellman shared secret
		Key<crypto_scalarmult_SCALARBYTES,KeyType::Key> dh_secret(uninitialized_t::uninitialized);

		//do the diffie hellman key exchange
		OUTCOME_TRY(crypto_scalarmult(dh_secret, our_private_key, their_public_key));

		//initialize hashing
		OUTCOME_TRY(hash, CryptoGenerichash::construct({nullptr, static_cast<size_t>(0)}, DIFFIE_HELLMAN_SIZE));
		OUTCOME_TRY(hash.update(dh_secret));

		//add public keys to the input of the hash
		switch (role) {
			case Ratchet::Role::ALICE: { //Alice (our_public_key|their_public_key)
				OUTCOME_TRY(hash.update(our_public_key));
				OUTCOME_TRY(hash.update(their_public_key));
				break;
			}

			case Ratchet::Role::BOB: { //Bob (their_public_key|our_public_key)
				OUTCOME_TRY(hash.update(their_public_key));
				OUTCOME_TRY(hash.update(our_public_key));
				break;
			}

			default:
				break;
		}

		//finally write the hash to derived_key
		Key<DIFFIE_HELLMAN_SIZE,KeyType::Key> derived_key;
		OUTCOME_TRY(hash.final(derived_key));

		return derived_key;
	}

	result<EmptyableKey<DIFFIE_HELLMAN_SIZE,KeyType::Key>> triple_diffie_hellman(
			const PrivateKey& our_private_identity,
			const PublicKey& our_public_identity,
			const PrivateKey& our_private_ephemeral,
			const PublicKey& our_public_ephemeral,
			const PublicKey& their_public_identity,
			const PublicKey& their_public_ephemeral,
			const Ratchet::Role role) {
		//buffers for all 3 Diffie Hellman exchanges
		Key<DIFFIE_HELLMAN_SIZE,KeyType::Key> dh1;
		Key<DIFFIE_HELLMAN_SIZE,KeyType::Key> dh2;
		switch (role) {
			case Ratchet::Role::ALICE: {
				//DH(our_identity, their_ephemeral)
				OUTCOME_TRY(dh1_result, diffie_hellman(
						our_private_identity,
						our_public_identity,
						their_public_ephemeral,
						role));
				dh1 = dh1_result;

				//DH(our_ephemeral, their_identity)
				OUTCOME_TRY(dh2_result, diffie_hellman(
						our_private_ephemeral,
						our_public_ephemeral,
						their_public_identity,
						role));
				dh2 = dh2_result;
				break;
			}

			case Ratchet::Role::BOB: {
				//DH(our_ephemeral, their_identity)
				OUTCOME_TRY(dh1_result, diffie_hellman(
						our_private_ephemeral,
						our_public_ephemeral,
						their_public_identity,
						role));
				dh1 = dh1_result;

				//DH(our_identity, their_ephemeral)
				OUTCOME_TRY(dh2_result, diffie_hellman(
						our_private_identity,
						our_public_identity,
						their_public_ephemeral,
						role));
				dh2 = dh2_result;
				break;
			}

			default:
				break;
		}

		//DH(our_ephemeral, their_ephemeral)
		//this is identical for both Alice and Bob
		OUTCOME_TRY(dh3_result, diffie_hellman(
			our_private_ephemeral,
			our_public_ephemeral,
			their_public_ephemeral,
			role));
		const auto& dh3{dh3_result};

		//now calculate HASH(DH(A,B0) || DH(A0,B) || DH(A0,B0))
		//( HASH(dh1|| dh2 || dh3) )
		OUTCOME_TRY(hash, CryptoGenerichash::construct({nullptr, static_cast<size_t>(0)}, DIFFIE_HELLMAN_SIZE));
		OUTCOME_TRY(hash.update(dh1));
		OUTCOME_TRY(hash.update(dh2));
		OUTCOME_TRY(hash.update(dh3));
		EmptyableKey<DIFFIE_HELLMAN_SIZE,KeyType::Key> derived_key;
		OUTCOME_TRY(hash.final(derived_key));
		derived_key.empty = false;
		return derived_key;
	}
}
