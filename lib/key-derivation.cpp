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
#include "endianness.hpp"
#include "molch-exception.hpp"

namespace Molch {
	/*
	 * Derive a key of length between crypto_generichash_blake2b_BYTES_MIN (16 Bytes)
	 * and crypto_generichash_blake2b_BYTES_MAX (64 Bytes).
	 *
	 * The input key needs to be between crypto_generichash_blake2b_KEYBYTES_MIN (16 Bytes)
	 * and crypto_generichash_blake2b_KEYBYTES_MAX (64 Bytes).
	 */
	void derive_key(
			Buffer& derived_key,
			const size_t derived_size,
			const Buffer& input_key,
			const uint32_t subkey_counter) { //number of the current subkey, used to derive multiple keys from the same input key
		//check if inputs are valid
		if ((derived_size > crypto_generichash_blake2b_BYTES_MAX)
				|| (derived_size < crypto_generichash_blake2b_BYTES_MIN)
				|| !derived_key.fits(derived_size)
				|| (input_key.size > crypto_generichash_blake2b_KEYBYTES_MAX)
				|| (input_key.size < crypto_generichash_blake2b_KEYBYTES_MIN)) {
			throw MolchException(INVALID_INPUT, "Invalid input to derive_key.");
		}

		//create a salt that contains the number of the subkey
		Buffer salt(crypto_generichash_blake2b_SALTBYTES, crypto_generichash_blake2b_SALTBYTES);
		salt.clear(); //fill with zeroes
		salt.size = crypto_generichash_blake2b_SALTBYTES;

		//fill the salt with a big endian representation of the subkey counter
		Buffer big_endian_subkey_counter(salt.content + salt.size - sizeof(uint32_t), sizeof(uint32_t));
		to_big_endian(subkey_counter, big_endian_subkey_counter);

		const char personal_string[] = "molch_cryptolib";
		Buffer personal(personal_string);
		static_assert(sizeof(personal_string) == crypto_generichash_blake2b_PERSONALBYTES, "personal string is not crypto_generichash_blake2b_PERSONALBYTES long");

		//set length of output
		derived_key.size = derived_size;
		int status_int = crypto_generichash_blake2b_salt_personal(
				derived_key.content,
				derived_key.size,
				nullptr, //input
				0, //input length
				input_key.content,
				input_key.size,
				salt.content,
				personal.content);
		if (status_int != 0) {
			throw MolchException(KEYDERIVATION_FAILED, "Failed to derive key via crypto_generichash_blake2b_salt_personal");
		}
	}

	/*
	 * Derive the next chain key in a message chain.
	 *
	 * The chain keys have to be crypto_auth_BYTES long.
	 *
	 * CK_new = HMAC-Hash(CK_prev, 0x01)
	 * (previous chain key as key, 0x01 as message)
	 */
	void derive_chain_key(
			Buffer& new_chain_key,
			const Buffer& previous_chain_key) {
		return derive_key(
				new_chain_key,
				CHAIN_KEY_SIZE,
				previous_chain_key,
				1);
	}

	/*
	 * Derive a message key from a chain key.
	 *
	 * The chain and message keys have to be crypto_auth_BYTES long.
	 *
	 * MK = HMAC-Hash(CK, 0x00)
	 * (chain_key as key, 0x00 as message)
	 */
	void derive_message_key(
			Buffer& message_key,
			const Buffer& chain_key) {
		return derive_key(
				message_key,
				MESSAGE_KEY_SIZE,
				chain_key,
				0);
	}

	/*
	 * Derive a root, next header and initial chain key for a new ratchet.
	 *
	 * RK, NHKs, CKs = KDF(HMAC-HASH(RK, DH(DHRr, DHRs)))
	 * and
	 * RK, NHKp, CKp = KDF(HMAC-HASH(RK, DH(DHRp, DHRs)))
	 */
	void derive_root_next_header_and_chain_keys(
			Buffer& root_key, //ROOT_KEY_SIZE
			Buffer& next_header_key, //HEADER_KEY_SIZE
			Buffer& chain_key, //CHAIN_KEY_SIZE
			const Buffer& our_private_ephemeral,
			const Buffer& our_public_ephemeral,
			const Buffer& their_public_ephemeral,
			const Buffer& previous_root_key,
			const Ratchet::Role role) {

		//check input
		if (!root_key.fits(ROOT_KEY_SIZE)
				|| !next_header_key.fits(HEADER_KEY_SIZE)
				|| !chain_key.fits(CHAIN_KEY_SIZE)
				|| !our_private_ephemeral.contains(PRIVATE_KEY_SIZE)
				|| !our_public_ephemeral.contains(PUBLIC_KEY_SIZE)
				|| !their_public_ephemeral.contains(PUBLIC_KEY_SIZE)
				|| !previous_root_key.contains(ROOT_KEY_SIZE)) {
			throw MolchException(INVALID_INPUT, "Invalid input to derive_root_next_header_and_chain_keys.");
		}

		//create buffers
		Buffer diffie_hellman_secret(DIFFIE_HELLMAN_SIZE, 0);
		Buffer derivation_key(crypto_generichash_BYTES, crypto_generichash_BYTES);

		//DH(DHRs, DHRr) or DH(DHRp, DHRs)
		diffie_hellman(
			diffie_hellman_secret,
			our_private_ephemeral,
			our_public_ephemeral,
			their_public_ephemeral,
			role);

		//key to derive from
		//HMAC-HASH(RK, DH(..., ...))
		int status_int = crypto_generichash(
				derivation_key.content,
				derivation_key.size,
				diffie_hellman_secret.content,
				diffie_hellman_secret.size,
				previous_root_key.content,
				previous_root_key.size);
		if (status_int != 0) {
			throw MolchException(GENERIC_ERROR, "Failed to hash diffie hellman and previous root key.");
		}

		//now derive the different keys from the derivation key
		//root key
		derive_key(root_key, ROOT_KEY_SIZE, derivation_key, 0);

		//next header key
		derive_key(next_header_key, HEADER_KEY_SIZE, derivation_key, 1);

		//chain key
		derive_key(chain_key, CHAIN_KEY_SIZE, derivation_key, 2);
	}

	/*
	 * Derive initial root, chain and header keys.
	 *
	 * RK, CKs/r, HKs/r, NHKs/r = KDF(HASH(DH(A,B0) || DH(A0,B) || DH(A0,B0)))
	 */
	void derive_initial_root_chain_and_header_keys(
			Buffer& root_key, //ROOT_KEY_SIZE
			Buffer& send_chain_key, //CHAIN_KEY_SIZE
			Buffer& receive_chain_key, //CHAIN_KEY_SIZE
			Buffer& send_header_key, //HEADER_KEY_SIZE
			Buffer& receive_header_key, //HEADER_KEY_SIZE
			Buffer& next_send_header_key, //HEADER_KEY_SIZE
			Buffer& next_receive_header_key, //HEADER_KEY_SIZE
			const Buffer& our_private_identity,
			const Buffer& our_public_identity,
			const Buffer& their_public_identity,
			const Buffer& our_private_ephemeral,
			const Buffer& our_public_ephemeral,
			const Buffer& their_public_ephemeral,
			const Ratchet::Role role) {
		//check buffer sizes
		if (!root_key.fits(ROOT_KEY_SIZE)
				|| !send_chain_key.fits(CHAIN_KEY_SIZE)
				|| !receive_chain_key.fits(CHAIN_KEY_SIZE)
				|| !send_header_key.fits(HEADER_KEY_SIZE)
				|| !receive_header_key.fits(HEADER_KEY_SIZE)
				|| !next_send_header_key.fits(HEADER_KEY_SIZE)
				|| !next_receive_header_key.fits(HEADER_KEY_SIZE)
				|| !our_private_identity.contains(PRIVATE_KEY_SIZE)
				|| !our_public_identity.contains(PUBLIC_KEY_SIZE)
				|| !their_public_identity.contains(PUBLIC_KEY_SIZE)
				|| !our_private_ephemeral.contains(PRIVATE_KEY_SIZE)
				|| !our_public_ephemeral.contains(PUBLIC_KEY_SIZE)
				|| !their_public_ephemeral.contains(PUBLIC_KEY_SIZE)) {
			throw MolchException(INVALID_INPUT, "Invalid input to derive_initial_root_chain_and_header_keys.");
		}

		Buffer master_key(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);

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
		derive_key(root_key, ROOT_KEY_SIZE, master_key, 0);

		//derive chain keys and header keys
		switch (role) {
			case Ratchet::Role::ALICE:
				//HKs=<none>, HKr=KDF
				//HKs=<none>
				send_header_key.clear();
				send_header_key.size = HEADER_KEY_SIZE;
				//HKr = KDF(master_key, 0x01)
				derive_key(receive_header_key, HEADER_KEY_SIZE, master_key, 1);

				//NHKs, NHKr
				//NHKs = KDF(master_key, 0x02)
				derive_key(next_send_header_key, HEADER_KEY_SIZE, master_key, 2);

				//NHKr = KDF(master_key, 0x03)
				derive_key(next_receive_header_key, HEADER_KEY_SIZE, master_key, 3);

				//CKs=<none>, CKr=KDF
				//CKs=<none>
				send_chain_key.clear();
				send_chain_key.size = CHAIN_KEY_SIZE;
				//CKr = KDF(master_key, 0x04)
				derive_key(receive_chain_key, CHAIN_KEY_SIZE, master_key, 4);
				break;

			case Ratchet::Role::BOB:
				//HKs=HKDF, HKr=<none>
				//HKr = <none>
				receive_header_key.clear();
				receive_header_key.size = HEADER_KEY_SIZE;
				//HKs = KDF(master_key, 0x01)
				derive_key(send_header_key, HEADER_KEY_SIZE, master_key, 1);

				//NHKr, NHKs
				//NHKr = KDF(master_key, 0x02)
				derive_key(next_receive_header_key, HEADER_KEY_SIZE, master_key, 2);
				//NHKs = KDF(master_key, 0x03)
				derive_key(next_send_header_key, HEADER_KEY_SIZE, master_key, 3);

				//CKs=KDF, CKr=<none>
				//CKr = <none>
				receive_chain_key.clear();
				receive_chain_key.size = CHAIN_KEY_SIZE;
				//CKs = KDF(master_key, 0x04)
				derive_key(send_chain_key, CHAIN_KEY_SIZE, master_key, 4);
				break;

			default:
				break;
		}
	}
}
