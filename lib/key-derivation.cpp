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
#include <exception>

#include "constants.h"
#include "key-derivation.hpp"
#include "diffie-hellman.hpp"

namespace Molch {
	/*
	 * Derive a root, next header and initial chain key for a new ratchet.
	 *
	 * RK, NHKs, CKs = KDF(HMAC-HASH(RK, DH(DHRr, DHRs)))
	 * and
	 * RK, NHKp, CKp = KDF(HMAC-HASH(RK, DH(DHRp, DHRs)))
	 */
	result<DerivedRootNextHeadAndChainKey> derive_root_next_header_and_chain_keys(
			const PrivateKey& our_private_ephemeral,
			const EmptyablePublicKey& our_public_ephemeral,
			const EmptyablePublicKey& their_public_ephemeral,
			const EmptyableRootKey& previous_root_key,
			const Ratchet::Role role) {
		FulfillOrFail(!our_public_ephemeral.empty
				&& !their_public_ephemeral.empty
				&& !previous_root_key.empty);

		//create buffers
		EmptyableKey<crypto_generichash_BYTES,KeyType::Key> derivation_key;

		//DH(DHRs, DHRr) or DH(DHRp, DHRs)
		OUTCOME_TRY(diffie_hellman_secret, diffie_hellman(
			our_private_ephemeral,
			our_public_ephemeral.toKey().value(),
			their_public_ephemeral.toKey().value(),
			role));

		//key to derive from
		//HMAC-HASH(RK, DH(..., ...))
		OUTCOME_TRY(crypto_generichash(
				derivation_key,
				diffie_hellman_secret,
				previous_root_key));
		derivation_key.empty = false;

		DerivedRootNextHeadAndChainKey output;

		//now derive the different keys from the derivation key
		//root key
		OUTCOME_TRY(root_key, derivation_key.deriveSubkeyWithIndex<EmptyableRootKey>(0));
		output.root_key = root_key.toKey().value();

		//next header key
		OUTCOME_TRY(next_header_key, derivation_key.deriveSubkeyWithIndex<EmptyableHeaderKey>(1));
		output.next_header_key = next_header_key.toKey().value();

		//chain key
		OUTCOME_TRY(chain_key, derivation_key.deriveSubkeyWithIndex<ChainKey>(2));
		output.chain_key = chain_key;

		return output;
	}

	/*
	 * Derive initial root, chain and header keys.
	 *
	 * RK, CKs/r, HKs/r, NHKs/r = KDF(HASH(DH(A,B0) || DH(A0,B) || DH(A0,B0)))
	 */
	result<DerivedInitialRootChainAndHeaderKeys> derive_initial_root_chain_and_header_keys(
			const PrivateKey& our_private_identity,
			const EmptyablePublicKey& our_public_identity,
			const EmptyablePublicKey& their_public_identity,
			const PrivateKey& our_private_ephemeral,
			const EmptyablePublicKey& our_public_ephemeral,
			const EmptyablePublicKey& their_public_ephemeral,
			const Ratchet::Role role) {
		FulfillOrFail(!our_public_identity.empty
				&& !their_public_identity.empty
				&& !our_public_ephemeral.empty
				&& !their_public_ephemeral.empty);

		//derive master_key to later derive the initial root key,
		//header keys and chain keys from
		//master_key = HASH( DH(A,B0) || DH(A0,B) || DH(A0,B0) )
		static_assert(crypto_secretbox_KEYBYTES == crypto_auth_BYTES, "crypto_auth_BYTES is not crypto_secretbox_KEYBYTES");
		OUTCOME_TRY(master_key, triple_diffie_hellman(
			our_private_identity,
			our_public_identity.toKey().value(),
			our_private_ephemeral,
			our_public_ephemeral.toKey().value(),
			their_public_identity.toKey().value(),
			their_public_ephemeral.toKey().value(),
			role));

		DerivedInitialRootChainAndHeaderKeys output;
		//derive root key
		//RK = KDF(master_key, 0x00)
		OUTCOME_TRY(root_key, master_key.deriveSubkeyWithIndex<EmptyableRootKey>(0));
		output.root_key = root_key.toKey().value();

		//derive chain keys and header keys
		switch (role) {
			case Ratchet::Role::ALICE:
				{
					//HKs=<none>, HKr=KDF
					//HKs=<none>
					output.send_header_key.reset();
					//HKr = KDF(master_key, 0x01)
					OUTCOME_TRY(receive_header_key, master_key.deriveSubkeyWithIndex<EmptyableHeaderKey>(1));
					output.receive_header_key.emplace(receive_header_key.toKey().value());

					//NHKs, NHKr
					//NHKs = KDF(master_key, 0x02)
					OUTCOME_TRY(next_send_header_key, master_key.deriveSubkeyWithIndex<EmptyableHeaderKey>(2));
					output.next_send_header_key = next_send_header_key.toKey().value();

					//NHKr = KDF(master_key, 0x03)
					OUTCOME_TRY(next_receive_header_key, master_key.deriveSubkeyWithIndex<EmptyableHeaderKey>(3));
					output.next_receive_header_key = next_receive_header_key.toKey().value();

					//CKs=<none>, CKr=KDF
					//CKs=<none>
					output.send_chain_key.reset();
					//CKr = KDF(master_key, 0x04)
					OUTCOME_TRY(receive_chain_key, master_key.deriveSubkeyWithIndex<ChainKey>(4));
					output.receive_chain_key.emplace(receive_chain_key);
				}
				break;

			case Ratchet::Role::BOB:
				{
					//HKs=HKDF, HKr=<none>
					//HKr = <none>
					output.receive_header_key.reset();
					//HKs = KDF(master_key, 0x01)
					OUTCOME_TRY(send_header_key, master_key.deriveSubkeyWithIndex<EmptyableHeaderKey>(1));
					output.send_header_key.emplace(send_header_key.toKey().value());

					//NHKr, NHKs
					//NHKr = KDF(master_key, 0x02)
					OUTCOME_TRY(next_receive_header_key, master_key.deriveSubkeyWithIndex<EmptyableHeaderKey>(2));
					output.next_receive_header_key = next_receive_header_key.toKey().value();
					//NHKs = KDF(master_key, 0x03)
					OUTCOME_TRY(next_send_header_key, master_key.deriveSubkeyWithIndex<EmptyableHeaderKey>(3));
					output.next_send_header_key = next_send_header_key.toKey().value();

					//CKs=KDF, CKr=<none>
					//CKr = <none>
					output.receive_chain_key.reset();
					//CKs = KDF(master_key, 0x04)
					OUTCOME_TRY(send_chain_key, master_key.deriveSubkeyWithIndex<ChainKey>(4));
					output.send_chain_key.emplace(send_chain_key);
				}
				break;

			default:
				break;
		}

		return output;
	}
}
