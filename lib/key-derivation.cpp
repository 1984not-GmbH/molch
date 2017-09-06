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
#include "molch-exception.hpp"

namespace Molch {
	/*
	 * Derive a root, next header and initial chain key for a new ratchet.
	 *
	 * RK, NHKs, CKs = KDF(HMAC-HASH(RK, DH(DHRr, DHRs)))
	 * and
	 * RK, NHKp, CKp = KDF(HMAC-HASH(RK, DH(DHRp, DHRs)))
	 */
	void derive_root_next_header_and_chain_keys(
			RootKey& root_key, //ROOT_KEY_SIZE
			HeaderKey& next_header_key, //HEADER_KEY_SIZE
			ChainKey& chain_key, //CHAIN_KEY_SIZE
			const PrivateKey& our_private_ephemeral,
			const PublicKey& our_public_ephemeral,
			const PublicKey& their_public_ephemeral,
			const RootKey& previous_root_key,
			const Ratchet::Role role) {
		Expects(!our_private_ephemeral.empty
				&& !our_public_ephemeral.empty
				&& !their_public_ephemeral.empty
				&& !previous_root_key.empty);

		//create buffers
		Key<DIFFIE_HELLMAN_SIZE,KeyType::Key> diffie_hellman_secret;
		Key<crypto_generichash_BYTES,KeyType::Key> derivation_key;

		//DH(DHRs, DHRr) or DH(DHRp, DHRs)
		diffie_hellman(
			diffie_hellman_secret,
			our_private_ephemeral,
			our_public_ephemeral,
			their_public_ephemeral,
			role);

		//key to derive from
		//HMAC-HASH(RK, DH(..., ...))
		crypto_generichash(
				derivation_key,
				diffie_hellman_secret,
				previous_root_key);
		derivation_key.empty = false;

		//now derive the different keys from the derivation key
		//root key
		derivation_key.deriveTo(root_key, 0);

		//next header key
		derivation_key.deriveTo(next_header_key, 1);

		//chain key
		derivation_key.deriveTo(chain_key, 2);
	}

	/*
	 * Derive initial root, chain and header keys.
	 *
	 * RK, CKs/r, HKs/r, NHKs/r = KDF(HASH(DH(A,B0) || DH(A0,B) || DH(A0,B0)))
	 */
	void derive_initial_root_chain_and_header_keys(
			RootKey& root_key, //ROOT_KEY_SIZE
			ChainKey& send_chain_key, //CHAIN_KEY_SIZE
			ChainKey& receive_chain_key, //CHAIN_KEY_SIZE
			HeaderKey& send_header_key, //HEADER_KEY_SIZE
			HeaderKey& receive_header_key, //HEADER_KEY_SIZE
			HeaderKey& next_send_header_key, //HEADER_KEY_SIZE
			HeaderKey& next_receive_header_key, //HEADER_KEY_SIZE
			const PrivateKey& our_private_identity,
			const PublicKey& our_public_identity,
			const PublicKey& their_public_identity,
			const PrivateKey& our_private_ephemeral,
			const PublicKey& our_public_ephemeral,
			const PublicKey& their_public_ephemeral,
			const Ratchet::Role role) {
		Expects(!our_private_identity.empty
				&& !our_public_identity.empty
				&& !their_public_identity.empty
				&& !our_private_ephemeral.empty
				&& !our_public_ephemeral.empty
				&& !their_public_ephemeral.empty);

		Key<crypto_secretbox_KEYBYTES,KeyType::Key> master_key;

		//derive master_key to later derive the initial root key,
		//header keys and chain keys from
		//master_key = HASH( DH(A,B0) || DH(A0,B) || DH(A0,B0) )
		static_assert(crypto_secretbox_KEYBYTES == crypto_auth_BYTES, "crypto_auth_BYTES is not crypto_secretbox_KEYBYTES");
		triple_diffie_hellman(
			master_key,
			our_private_identity,
			our_public_identity,
			our_private_ephemeral,
			our_public_ephemeral,
			their_public_identity,
			their_public_ephemeral,
			role);

		//derive root key
		//RK = KDF(master_key, 0x00)
		master_key.deriveTo(root_key, 0);

		//derive chain keys and header keys
		switch (role) {
			case Ratchet::Role::ALICE:
				//HKs=<none>, HKr=KDF
				//HKs=<none>
				send_header_key.clear();
				//HKr = KDF(master_key, 0x01)
				master_key.deriveTo(receive_header_key, 1);

				//NHKs, NHKr
				//NHKs = KDF(master_key, 0x02)
				master_key.deriveTo(next_send_header_key, 2);

				//NHKr = KDF(master_key, 0x03)
				master_key.deriveTo(next_receive_header_key, 3);

				//CKs=<none>, CKr=KDF
				//CKs=<none>
				send_chain_key.clear();
				//CKr = KDF(master_key, 0x04)
				master_key.deriveTo(receive_chain_key, 4);
				break;

			case Ratchet::Role::BOB:
				//HKs=HKDF, HKr=<none>
				//HKr = <none>
				receive_header_key.clear();
				//HKs = KDF(master_key, 0x01)
				master_key.deriveTo(send_header_key, 1);

				//NHKr, NHKs
				//NHKr = KDF(master_key, 0x02)
				master_key.deriveTo(next_receive_header_key, 2);
				//NHKs = KDF(master_key, 0x03)
				master_key.deriveTo(next_send_header_key, 3);

				//CKs=KDF, CKr=<none>
				//CKr = <none>
				receive_chain_key.clear();
				//CKs = KDF(master_key, 0x04)
				master_key.deriveTo(send_chain_key, 4);
				break;

			default:
				break;
		}
	}
}
