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

#ifndef LIB_KEY_DERIVATION_H
#define LIB_KEY_DERIVATION_H

#include "buffer.hpp"
#include "ratchet.hpp"
#include "return-status.hpp"

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
			const Ratchet::Role role);

	/*
	 * Derive initial root, chain and header keys.
	 *
	 * RK, CKs/r, HKs/r = KDF(HASH(DH(A,B0) || DH(A0,B) || DH(A0,B0)))
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
			const Ratchet::Role role);
}

#endif
