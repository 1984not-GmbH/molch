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
	void diffie_hellman(
			EmptyableKey<DIFFIE_HELLMAN_SIZE,KeyType::Key>& derived_key, //needs to be DIFFIE_HELLMAN_SIZE long
			const PrivateKey& our_private_key, //needs to be PRIVATE_KEY_SIZE long
			const PublicKey& our_public_key, //needs to be PUBLIC_KEY_SIZE long
			const PublicKey& their_public_key, //needs to be PUBLIC_KEY_SIZE long
			const Ratchet::Role role) {
		//make sure that the assumptions are correct
		static_assert(PUBLIC_KEY_SIZE == crypto_scalarmult_SCALARBYTES, "crypto_scalarmult_SCALARBYTES is not PUBLIC_KEY_SIZE");
		static_assert(PRIVATE_KEY_SIZE == crypto_scalarmult_SCALARBYTES, "crypto_scalarmult_SCALARBYTES is not PRIVATE_KEY_BYTES");
		static_assert(DIFFIE_HELLMAN_SIZE == crypto_generichash_BYTES, "crypto_generichash_bytes is not DIFFIE_HELLMAN_SIZE");

		//buffer for diffie hellman shared secret
		EmptyableKey<crypto_scalarmult_SCALARBYTES,KeyType::Key> dh_secret;

		//do the diffie hellman key exchange
		TRY_VOID(crypto_scalarmult(dh_secret, our_private_key, their_public_key));
		dh_secret.empty = false;

		//initialize hashing
		TRY_WITH_RESULT(result, CryptoGenerichash::construct({nullptr, static_cast<size_t>(0)}, DIFFIE_HELLMAN_SIZE));
		auto hash{result.value()};
		TRY_VOID(hash.update(dh_secret));

		//add public keys to the input of the hash
		switch (role) {
			case Ratchet::Role::ALICE: //Alice (our_public_key|their_public_key)
				TRY_VOID(hash.update(our_public_key));
				TRY_VOID(hash.update(their_public_key));
				break;

			case Ratchet::Role::BOB: //Bob (their_public_key|our_public_key)
				TRY_VOID(hash.update(their_public_key));
				TRY_VOID(hash.update(our_public_key));
				break;

			default:
				break;
		}

		//finally write the hash to derived_key
		TRY_VOID(hash.final(derived_key));
		derived_key.empty = false;
	}

	void triple_diffie_hellman(
			EmptyableKey<DIFFIE_HELLMAN_SIZE,KeyType::Key>& derived_key,
			const PrivateKey& our_private_identity,
			const EmptyablePublicKey& our_public_identity,
			const PrivateKey& our_private_ephemeral,
			const EmptyablePublicKey& our_public_ephemeral,
			const EmptyablePublicKey& their_public_identity,
			const EmptyablePublicKey& their_public_ephemeral,
			const Ratchet::Role role) {
		Expects(!our_public_identity.empty
				&& !their_public_identity.empty
				&& !our_public_ephemeral.empty
				&& !their_public_ephemeral.empty);

		//buffers for all 3 Diffie Hellman exchanges
		EmptyableKey<DIFFIE_HELLMAN_SIZE,KeyType::Key> dh1;
		EmptyableKey<DIFFIE_HELLMAN_SIZE,KeyType::Key> dh2;
		EmptyableKey<DIFFIE_HELLMAN_SIZE,KeyType::Key> dh3;
		switch (role) {
			case Ratchet::Role::ALICE:
				//DH(our_identity, their_ephemeral)
				diffie_hellman(
					dh1,
					our_private_identity,
					our_public_identity.toKey().value(),
					their_public_ephemeral.toKey().value(),
					role);

				//DH(our_ephemeral, their_identity)
				diffie_hellman(
					dh2,
					our_private_ephemeral,
					our_public_ephemeral.toKey().value(),
					their_public_identity.toKey().value(),
					role);
				break;

			case Ratchet::Role::BOB:
				//DH(our_ephemeral, their_identity)
				diffie_hellman(
					dh1,
					our_private_ephemeral,
					our_public_ephemeral.toKey().value(),
					their_public_identity.toKey().value(),
					role);

				//DH(our_identity, their_ephemeral)
				diffie_hellman(
					dh2,
					our_private_identity,
					our_public_identity.toKey().value(),
					their_public_ephemeral.toKey().value(),
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
			our_public_ephemeral.toKey().value(),
			their_public_ephemeral.toKey().value(),
			role);

		//now calculate HASH(DH(A,B0) || DH(A0,B) || DH(A0,B0))
		//( HASH(dh1|| dh2 || dh3) )
		TRY_WITH_RESULT(result, CryptoGenerichash::construct({nullptr, static_cast<size_t>(0)}, DIFFIE_HELLMAN_SIZE));
		auto hash{result.value()};
		TRY_VOID(hash.update(dh1));
		TRY_VOID(hash.update(dh2));
		TRY_VOID(hash.update(dh3));
		TRY_VOID(hash.final(derived_key));
		derived_key.empty = false;
	}
}
