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
#include <assert.h>
#include <string.h>

#include "constants.h"
#include "key-derivation.h"
#include "diffie-hellman.h"
#include "endianness.h"

/*
 * Derive a key of length between crypto_generichash_blake2b_BYTES_MIN (16 Bytes)
 * and crypto_generichash_blake2b_BYTES_MAX (64 Bytes).
 *
 * The input key needs to be between crypto_generichash_blake2b_KEYBYTES_MIN (16 Bytes)
 * and crypto_generichash_blake2b_KEYBYTES_MAX (64 Bytes).
 */
return_status derive_key(
		buffer_t * const derived_key,
		size_t derived_size,
		const buffer_t * const input_key,
		uint32_t subkey_counter) { //number of the current subkey, used to derive multiple keys from the same input key
	return_status status = return_status_init();

	//create a salt that contains the number of the subkey
	buffer_t * salt = buffer_create_on_heap(crypto_generichash_blake2b_SALTBYTES, crypto_generichash_blake2b_SALTBYTES);
	buffer_clear(salt); //fill with zeroes
	salt->content_length = crypto_generichash_blake2b_SALTBYTES;

	//check if inputs are valid
	if ((derived_size > crypto_generichash_blake2b_BYTES_MAX)
			|| (derived_size < crypto_generichash_blake2b_BYTES_MIN)
			|| (derived_key == NULL) || (derived_key->buffer_length < derived_size)
			|| (input_key == NULL)
			|| (input_key->content_length > crypto_generichash_blake2b_KEYBYTES_MAX)
			|| (input_key->content_length < crypto_generichash_blake2b_KEYBYTES_MIN)) {
		throw(INVALID_INPUT, "Invalid input to derive_key.");
	}

	//set length of output
	derived_key->content_length = derived_size;

	buffer_create_from_string(personal, "molch cryptolib"); //string that's unique to molch
	assert(personal->content_length == crypto_generichash_blake2b_PERSONALBYTES);

	//fill the salt with a big endian representation of the subkey counter
	buffer_create_with_existing_array(big_endian_subkey_counter, salt->content + salt->content_length - sizeof(uint32_t), sizeof(uint32_t));
	status = endianness_uint32_to_big_endian(subkey_counter, big_endian_subkey_counter);
	throw_on_error(CONVERSION_ERROR, "Failed to convert subkey counter to big endian.");

	int status_int = 0;
	status_int = crypto_generichash_blake2b_salt_personal(
			derived_key->content,
			derived_key->content_length,
			NULL, //input
			0, //input length
			input_key->content,
			input_key->content_length,
			salt->content,
			personal->content);
	if (status_int != 0) {
		throw(KEYDERIVATION_FAILED, "Failed to derive key via crypto_generichash_blake2b_salt_personal");
	}

cleanup:
	on_error(
		if (derived_key != NULL) {
			derived_key->content_length = 0;
		}
	);
	buffer_destroy_from_heap_and_null(salt);

	return status;
}

/*
 * Derive the next chain key in a message chain.
 *
 * The chain keys have to be crypto_auth_BYTES long.
 *
 * CK_new = HMAC-Hash(CK_prev, 0x01)
 * (previous chain key as key, 0x01 as message)
 */
return_status derive_chain_key(
		buffer_t * const new_chain_key,
		const buffer_t * const previous_chain_key) {
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
return_status derive_message_key(
		buffer_t * const message_key,
		const buffer_t * const chain_key) {
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
return_status derive_root_next_header_and_chain_keys(
		buffer_t * const root_key, //ROOT_KEY_SIZE
		buffer_t * const next_header_key, //HEADER_KEY_SIZE
		buffer_t * const chain_key, //CHAIN_KEY_SIZE
		const buffer_t * const our_private_ephemeral,
		const buffer_t * const our_public_ephemeral,
		const buffer_t * const their_public_ephemeral,
		const buffer_t * const previous_root_key,
		bool am_i_alice) {
	return_status status = return_status_init();

	//create buffers
	buffer_t *diffie_hellman_secret = buffer_create_on_heap(DIFFIE_HELLMAN_SIZE, 0);
	buffer_t *derivation_key = buffer_create_on_heap(crypto_generichash_BYTES, crypto_generichash_BYTES);

	//check input
	if ((root_key == NULL) || (root_key->buffer_length < ROOT_KEY_SIZE)
			|| (next_header_key == NULL) || (next_header_key->buffer_length < HEADER_KEY_SIZE)
			|| (chain_key == NULL) || (chain_key->buffer_length < CHAIN_KEY_SIZE)
			|| (our_private_ephemeral == NULL) || (our_private_ephemeral->content_length != PRIVATE_KEY_SIZE)
			|| (our_public_ephemeral == NULL) || (our_public_ephemeral->content_length != PUBLIC_KEY_SIZE)
			|| (their_public_ephemeral == NULL) || (their_public_ephemeral->content_length != PUBLIC_KEY_SIZE)
			|| (previous_root_key == NULL) || (previous_root_key->content_length != ROOT_KEY_SIZE)) {
		throw(INVALID_INPUT, "Invalid input to derive_root_next_header_and_chain_keys.");
	}

	int status_int = 0;
	//DH(DHRs, DHRr) or DH(DHRp, DHRs)
	status = diffie_hellman(
			diffie_hellman_secret,
			our_private_ephemeral,
			our_public_ephemeral,
			their_public_ephemeral,
			am_i_alice);
	throw_on_error(KEYDERIVATION_FAILED, "Failed to perform diffie hellman.");

	//key to derive from
	//HMAC-HASH(RK, DH(..., ...))
	status_int = crypto_generichash(
			derivation_key->content,
			derivation_key->content_length,
			diffie_hellman_secret->content,
			diffie_hellman_secret->content_length,
			previous_root_key->content,
			previous_root_key->content_length);
	if (status_int != 0) {
		throw(GENERIC_ERROR, "Failed to hash diffie hellman and previous root key.");
	}

	//now derive the different keys from the derivation key
	//root key
	status = derive_key(
			root_key,
			ROOT_KEY_SIZE,
			derivation_key,
			0);
	throw_on_error(KEYDERIVATION_FAILED, "Failed to derive root key from derivation key.");

	//next header key
	status = derive_key(
			next_header_key,
			HEADER_KEY_SIZE,
			derivation_key,
			1);
	throw_on_error(KEYDERIVATION_FAILED, "Failed to derive next header key from derivation key.");

	//chain key
	status = derive_key(
			chain_key,
			CHAIN_KEY_SIZE,
			derivation_key,
			2);
	throw_on_error(KEYDERIVATION_FAILED, "Failed to derive chain key from derivation key.");

cleanup:
	on_error(
		if (root_key != NULL) {
			buffer_clear(root_key);
			root_key->content_length = 0;
		}
		if (next_header_key != NULL) {
			buffer_clear(next_header_key);
			next_header_key->content_length = 0;
		}
		if (chain_key != NULL) {
			buffer_clear(chain_key);
			chain_key->content_length = 0;
		}
	);

	buffer_destroy_from_heap_and_null(diffie_hellman_secret);
	buffer_destroy_from_heap_and_null(derivation_key);

	return status;
}

/*
 * Derive initial root, chain and header keys.
 *
 * RK, CKs/r, HKs/r, NHKs/r = KDF(HASH(DH(A,B0) || DH(A0,B) || DH(A0,B0)))
 */
return_status derive_initial_root_chain_and_header_keys(
		buffer_t * const root_key, //ROOT_KEY_SIZE
		buffer_t * const send_chain_key, //CHAIN_KEY_SIZE
		buffer_t * const receive_chain_key, //CHAIN_KEY_SIZE
		buffer_t * const send_header_key, //HEADER_KEY_SIZE
		buffer_t * const receive_header_key, //HEADER_KEY_SIZE
		buffer_t * const next_send_header_key, //HEADER_KEY_SIZE
		buffer_t * const next_receive_header_key, //HEADER_KEY_SIZE
		const buffer_t * const our_private_identity,
		const buffer_t * const our_public_identity,
		const buffer_t * const their_public_identity,
		const buffer_t * const our_private_ephemeral,
		const buffer_t * const our_public_ephemeral,
		const buffer_t * const their_public_ephemeral,
		bool am_i_alice) {
	return_status status = return_status_init();

	buffer_t *master_key = buffer_create_on_heap(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);

	//check buffer sizes
	if ((root_key->buffer_length < ROOT_KEY_SIZE)
			|| (send_chain_key->buffer_length < CHAIN_KEY_SIZE)
			|| (receive_chain_key->buffer_length < CHAIN_KEY_SIZE)
			|| (send_header_key->buffer_length < HEADER_KEY_SIZE)
			|| (receive_header_key->buffer_length < HEADER_KEY_SIZE)
			|| (next_send_header_key->buffer_length < HEADER_KEY_SIZE)
			|| (next_receive_header_key->buffer_length < HEADER_KEY_SIZE)
			|| (our_private_identity->content_length != PRIVATE_KEY_SIZE)
			|| (our_public_identity->content_length != PUBLIC_KEY_SIZE)
			|| (their_public_identity->content_length != PUBLIC_KEY_SIZE)
			|| (our_private_ephemeral->content_length != PRIVATE_KEY_SIZE)
			|| (our_public_ephemeral->content_length != PUBLIC_KEY_SIZE)
			|| (their_public_ephemeral->content_length != PUBLIC_KEY_SIZE)) {
		throw(INVALID_INPUT, "Invalid input to derive_initial_root_chain_and_header_keys.");
	}

	//derive master_key to later derive the initial root key,
	//header keys and chain keys from
	//master_key = HASH( DH(A,B0) || DH(A0,B) || DH(A0,B0) )
	assert(crypto_secretbox_KEYBYTES == crypto_auth_BYTES);
	status = triple_diffie_hellman(
			master_key,
			our_private_identity,
			our_public_identity,
			our_private_ephemeral,
			our_public_ephemeral,
			their_public_identity,
			their_public_ephemeral,
			am_i_alice);
	throw_on_error(KEYDERIVATION_FAILED, "Failed to perform triple diffie hellman.");

	//derive root key
	//RK = KDF(master_key, 0x00)
	status = derive_key(
			root_key,
			ROOT_KEY_SIZE,
			master_key,
			0);
	throw_on_error(KEYDERIVATION_FAILED, "Failed to derive root key from master key.");

	//derive chain keys and header keys
	if (am_i_alice) {
		//HKs=<none>, HKr=KDF
		//HKs=<none>
		buffer_clear(send_header_key);
		send_header_key->content_length = HEADER_KEY_SIZE;
		//HKr = KDF(master_key, 0x01)
		status = derive_key(
				receive_header_key,
				HEADER_KEY_SIZE,
				master_key,
				1);
		throw_on_error(KEYDERIVATION_FAILED, "Failed to derive receive header key from master key.");

		//NHKs, NHKr
		//NHKs = KDF(master_key, 0x02)
		status = derive_key(
				next_send_header_key,
				HEADER_KEY_SIZE,
				master_key,
				2);
		throw_on_error(KEYDERIVATION_FAILED, "Failed to derive next send header key from master key.");

		//NHKr = KDF(master_key, 0x03)
		status = derive_key(
				next_receive_header_key,
				HEADER_KEY_SIZE,
				master_key,
				3);
		throw_on_error(KEYDERIVATION_FAILED, "Failed to derive next receive header key from master key.");

		//CKs=<none>, CKr=KDF
		//CKs=<none>
		buffer_clear(send_chain_key);
		send_chain_key->content_length = CHAIN_KEY_SIZE;
		//CKr = KDF(master_key, 0x04)
		status = derive_key(
				receive_chain_key,
				CHAIN_KEY_SIZE,
				master_key,
				4);
		throw_on_error(KEYDERIVATION_FAILED, "Failed to derive receive chain key from master key.");

	} else {
		//HKs=HKDF, HKr=<none>
		//HKr = <none>
		buffer_clear(receive_header_key);
		receive_header_key->content_length = HEADER_KEY_SIZE;
		//HKs = KDF(master_key, 0x01)
		status = derive_key(
				send_header_key,
				HEADER_KEY_SIZE,
				master_key,
				1);
		throw_on_error(KEYDERIVATION_FAILED, "Failed to derive send header key from master key.");

		//NHKr, NHKs
		//NHKr = KDF(master_key, 0x02)
		status = derive_key(
				next_receive_header_key,
				HEADER_KEY_SIZE,
				master_key,
				2);
		throw_on_error(KEYDERIVATION_FAILED, "Failed to derive next receive header key from master key.");
		//NHKs = KDF(master_key, 0x03)
		status = derive_key(
				next_send_header_key,
				HEADER_KEY_SIZE,
				master_key,
				3);
		throw_on_error(KEYDERIVATION_FAILED, "Failed to derive next send header key from master key.");

		//CKs=KDF, CKr=<none>
		//CKr = <none>
		buffer_clear(receive_chain_key);
		receive_chain_key->content_length = CHAIN_KEY_SIZE;
		//CKs = KDF(master_key, 0x04)
		status = derive_key(
				send_chain_key,
				CHAIN_KEY_SIZE,
				master_key,
				4);
		throw_on_error(KEYDERIVATION_FAILED, "Failed to derive send chain key from master key.");
	}

cleanup:
	on_error(
		//clear all keys to prevent misuse
		buffer_clear(root_key);
		root_key->content_length = 0;
		buffer_clear(send_chain_key);
		send_chain_key->content_length = 0;
		buffer_clear(receive_chain_key);
		receive_chain_key->content_length = 0;
		buffer_clear(send_header_key);
		send_header_key->content_length = 0;
		buffer_clear(receive_header_key);
		receive_header_key->content_length = 0;
		buffer_clear(next_send_header_key);
		next_send_header_key->content_length = 0;
		buffer_clear(next_receive_header_key);
		next_receive_header_key->content_length = 0;
	);

	buffer_destroy_from_heap_and_null(master_key);

	return status;
}
