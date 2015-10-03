/*  Molch, an implementation of the axolotl ratchet based on libsodium
 *  Copyright (C) 2015  Max Bruckner (FSMaxB)
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <stdbool.h>

#include "buffer.h"

#ifndef LIB_KEY_DERIVATION_H
#define LIB_KEY_DERIVATION_H

/*
 * Derive the next chain key in a message chain.
 *
 * The chain keys have to be crypto_auth_BYTES long.
 *
 * CK_new = HMAC-Hash(CK_prev, 0x01)
 * (previous chain key as key, 0x01 as message)
 */
int derive_chain_key(
		buffer_t * const new_chain_key,
		const buffer_t * const previous_chain_key) __attribute__((warn_unused_result));

/*
 * Derive a message key from a chain key.
 *
 * The chain and message keys have to be crypto_auth_BYTES long.
 *
 * MK = HMAC-Hash(CK, 0x00)
 * (chain_key as key, 0x00 as message)
 */
int derive_message_key(
		buffer_t * const message_key,
		const buffer_t * const chain_key) __attribute__((warn_unused_result));

/*
 * Derive a root, header and initial chain key for a new ratchet.
 *
 * RK, CK, HK = HKDF( RK, DH(DHRr, DHRs) )
 */
int derive_root_chain_and_header_keys(
		buffer_t * const root_key, //crypto_secretbox_KEYBYTES
		buffer_t * const chain_key, //crypto_secretbox_KEYBYTES
		buffer_t * const header_key, //crypto_aead_chacha20poly1305_KEYBYTES
		const buffer_t * const our_private_ephemeral,
		const buffer_t * const our_public_ephemeral,
		const buffer_t * const their_public_ephemeral,
		const buffer_t * const previous_root_key,
		bool am_i_alice) __attribute__((warn_unused_result));

/*
 * Derive initial root, chain and header keys.
 *
 * RK, CKs/r, HKs/r = HKDF(HASH(DH(A,B0) || DH(A0,B) || DH(A0,B0)))
 */
int derive_initial_root_chain_and_header_keys(
		buffer_t * const root_key, //crypto_secretbox_KEYBYTES
		buffer_t * const send_chain_key, //crypto_secretbox_KEYBYTES
		buffer_t * const receive_chain_key, //crypto_secretbox_KEYBYTES
		buffer_t * const send_header_key, //crypto_aead_chacha20poly1305_KEYBYTES
		buffer_t * const receive_header_key, //crypto_aead_chacha20poly1305_KEYBYTES
		buffer_t * const next_send_header_key, //crypto_aead_chacha20poly1305_KEYBYTES
		buffer_t * const next_receive_header_key, //crypto_aead_chacha20poly1305_KEYBYTES
		const buffer_t * const our_private_identity,
		const buffer_t * const our_public_identity,
		const buffer_t * const their_public_identity,
		const buffer_t * const our_private_ephemeral,
		const buffer_t * const our_public_ephemeral,
		const buffer_t * const their_public_ephemeral,
		bool am_i_alice) __attribute__((warn_unused_result));

#endif
