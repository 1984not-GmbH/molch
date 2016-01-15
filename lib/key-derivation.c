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
#include <sodium.h>
#include <assert.h>
#include <string.h>

#include "key-derivation.h"
#include "diffie-hellman.h"

/*
 * Derive a key of length between crypto_generichash_blake2b_BYTES_MIN (16 Bytes)
 * and crypto_generichash_blake2b_BYTES_MAX (64 Bytes).
 *
 * The input key needs to be between crypto_generichash_blake2b_KEYBYTES_MIN (16 Bytes)
 * and crypto_generichash_blake2b_KEYBYTES_MAX (64 Bytes).
 */
int derive_key(
		buffer_t * const derived_key,
		size_t derived_size,
		const buffer_t * const input_key,
		unsigned int subkey_counter) { //number of the current subkey, used to derive multiple keys from the same input key
	//check if inputs are valid
	if ((derived_size > crypto_generichash_blake2b_BYTES_MAX)
			|| (derived_size < crypto_generichash_blake2b_BYTES_MIN)
			|| (derived_key == NULL) || (derived_key->buffer_length < derived_size)
			|| (input_key == NULL)
			|| (input_key->content_length > crypto_generichash_blake2b_KEYBYTES_MAX)
			|| (input_key->content_length < crypto_generichash_blake2b_KEYBYTES_MIN)) {
		return -10;
	}

	//set length of output
	derived_key->content_length = derived_size;

	buffer_create_from_string(personal, "molch cryptolib"); //string that's unique to molch
	assert(personal->content_length == crypto_generichash_blake2b_PERSONALBYTES);

	//create a salt that contains the number of the subkey
	buffer_t * salt = buffer_create_on_heap(crypto_generichash_blake2b_SALTBYTES, crypto_generichash_blake2b_SALTBYTES);
	buffer_clear(salt); //fill with zeroes
	//FIXME: This is a really unefficient solution
	for (; subkey_counter > 0; subkey_counter--) {
		sodium_increment(salt->content, salt->content_length);
	}

	int status = crypto_generichash_blake2b_salt_personal(
			derived_key->content,
			derived_key->content_length,
			NULL, //input
			0, //input length
			input_key->content,
			input_key->content_length,
			salt->content,
			personal->content);
	if (status != 0) {
		derived_key->content_length = 0;
		goto cleanup;
	}

cleanup:
	buffer_destroy_from_heap(salt);

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
int derive_chain_key(
		buffer_t * const new_chain_key,
		const buffer_t * const previous_chain_key) {
	return derive_key(
			new_chain_key,
			crypto_secretbox_KEYBYTES,
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
int derive_message_key(
		buffer_t * const message_key,
		const buffer_t * const chain_key) {
	return derive_key(
			message_key,
			crypto_secretbox_KEYBYTES,
			chain_key,
			0);
}

/*
 * Derive a root and initial chain key for a new ratchet.
 *
 * The chain and root key have to be crypto_secretbox_KEYBYTES long.
 *
 * RK, CK, HK = KDF( RK, DH(DHRr, DHRs) )
 */
int derive_root_chain_and_header_keys(
		buffer_t * const root_key, //crypto_secretbox_KEYBYTES
		buffer_t * const chain_key, //crypto_secretbox_KEYBYTES
		buffer_t * const header_key, //crypto_aead_chacha20poly1305_KEYBYTES
		const buffer_t * const our_private_ephemeral,
		const buffer_t * const our_public_ephemeral,
		const buffer_t * const their_public_ephemeral,
		const buffer_t * const previous_root_key,
		bool am_i_alice) {
	assert(crypto_secretbox_KEYBYTES == crypto_auth_KEYBYTES);
	//check size of the buffers
	if ((root_key->buffer_length < crypto_secretbox_KEYBYTES)
			|| (chain_key->buffer_length < crypto_secretbox_KEYBYTES)
			|| (header_key->buffer_length < crypto_aead_chacha20poly1305_KEYBYTES)
			|| (our_private_ephemeral->content_length != crypto_box_SECRETKEYBYTES)
			|| (our_public_ephemeral->content_length != crypto_box_PUBLICKEYBYTES)
			|| (their_public_ephemeral->content_length != crypto_box_PUBLICKEYBYTES)
			|| (previous_root_key->content_length != crypto_secretbox_KEYBYTES)) {
		return -6;
	}

	int status;
	//input key for KDF (root key and chain key derivation)
	//input_key = DH(our_private_ephemeral, their_public_ephemeral)
	buffer_t *input_key = buffer_create_on_heap(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	status = diffie_hellman(
			input_key,
			our_private_ephemeral,
			our_public_ephemeral,
			their_public_ephemeral,
			am_i_alice);
	if (status != 0) {
		goto fail;
	}

	//derive root key
	status = derive_key(
			root_key,
			crypto_secretbox_KEYBYTES,
			input_key,
			0);
	if (status != 0) {
		goto fail;
	}

	//derive chain key
	status = derive_key(
			chain_key,
			crypto_secretbox_KEYBYTES,
			input_key,
			1);
	if (status != 0) {
		goto fail;
	}

	//derive header key
	status = derive_key(
			header_key,
			crypto_aead_chacha20poly1305_KEYBYTES,
			input_key,
			2);
	if (status != 0) {
		goto fail;
	}

	goto cleanup;

fail:
	buffer_clear(root_key);
	root_key->content_length = 0;
	buffer_clear(chain_key);
	chain_key->content_length = 0;
	buffer_clear(header_key);
	header_key->content_length = 0;

cleanup:
	buffer_destroy_from_heap(input_key);

	return status;
}

/*
 * Derive initial root, chain and header keys.
 *
 * RK, CKs/r, HKs/r, NHKs/r = KDF(HASH(DH(A,B0) || DH(A0,B) || DH(A0,B0)))
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
		bool am_i_alice) {
	//check buffer sizes
	if ((root_key->buffer_length < crypto_secretbox_KEYBYTES)
			|| (send_chain_key->buffer_length < crypto_secretbox_KEYBYTES)
			|| (receive_chain_key->buffer_length < crypto_secretbox_KEYBYTES)
			|| (send_header_key->buffer_length < crypto_aead_chacha20poly1305_KEYBYTES)
			|| (receive_header_key->buffer_length < crypto_aead_chacha20poly1305_KEYBYTES)
			|| (next_send_header_key->buffer_length < crypto_aead_chacha20poly1305_KEYBYTES)
			|| (next_receive_header_key->buffer_length < crypto_aead_chacha20poly1305_KEYBYTES)
			|| (our_private_identity->content_length != crypto_box_SECRETKEYBYTES)
			|| (our_public_identity->content_length != crypto_box_PUBLICKEYBYTES)
			|| (their_public_identity->content_length != crypto_box_PUBLICKEYBYTES)
			|| (our_private_ephemeral->content_length != crypto_box_SECRETKEYBYTES)
			|| (our_public_ephemeral->content_length != crypto_box_PUBLICKEYBYTES)
			|| (their_public_ephemeral->content_length != crypto_box_PUBLICKEYBYTES)) {
		return -6;
	}

	int status;
	//derive master_key to later derive the initial root key,
	//header keys and chain keys from
	//master_key = HASH( DH(A,B0) || DH(A0,B) || DH(A0,B0) )
	assert(crypto_secretbox_KEYBYTES == crypto_auth_BYTES);
	buffer_t *master_key = buffer_create_on_heap(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	status = triple_diffie_hellman(
			master_key,
			our_private_identity,
			our_public_identity,
			our_private_ephemeral,
			our_public_ephemeral,
			their_public_identity,
			their_public_ephemeral,
			am_i_alice);
	if (status != 0) {
		goto fail;
	}

	//derive root key
	//RK = KDF(master_key, 0x00)
	status = derive_key(
			root_key,
			crypto_secretbox_KEYBYTES,
			master_key,
			0);
	if (status != 0) {
		goto fail;
	}

	//derive chain keys and header keys
	if (am_i_alice) {
		//Alice: CKs=<none>, CKr=KDF
		//CKs=<none>
		buffer_clear(send_chain_key);
		send_chain_key->content_length = crypto_secretbox_KEYBYTES;
		//CKr = KDF(master_key, 0x01)
		status = derive_key(
				receive_chain_key,
				crypto_secretbox_KEYBYTES,
				master_key,
				1);
		if (status != 0) {
			goto fail;
		}

		//HKs=<none>, HKr=KDF
		//HKs=<none>
		buffer_clear(send_header_key);
		send_header_key->content_length = crypto_aead_chacha20poly1305_KEYBYTES;
		//HKr = KDF(master_key, 0x02)
		status = derive_key(
				receive_header_key,
				crypto_aead_chacha20poly1305_KEYBYTES,
				master_key,
				2);
		if (status != 0) {
			goto fail;
		}

		//NHKs, NHKr
		//NHKs = KDF(master_key, 0x03)
		status = derive_key(
				next_send_header_key,
				crypto_aead_chacha20poly1305_KEYBYTES,
				master_key,
				3);
		if (status != 0) {
			goto fail;
		}
		//NHKr = KDF(master_key, 0x04)
		status = derive_key(
				next_receive_header_key,
				crypto_aead_chacha20poly1305_KEYBYTES,
				master_key,
				4);
		if (status != 0) {
			goto fail;
		}
	} else {
		//Bob: CKs=KDF, CKr=<none>
		//CKr = <none>
		buffer_clear(receive_chain_key);
		receive_chain_key->content_length = crypto_secretbox_KEYBYTES;
		//CKs = KDF(master_key, 0x01)
		status = derive_key(
				send_chain_key,
				crypto_secretbox_KEYBYTES,
				master_key,
				1);
		if (status != 0) {
			goto fail;
		}

		//HKs=HKDF, HKr=<none>
		//HKr = <none>
		buffer_clear(receive_header_key);
		receive_header_key->content_length = crypto_aead_chacha20poly1305_KEYBYTES;
		//HKs = KDF(master_key, 0x02)
		status = derive_key(
				send_header_key,
				crypto_aead_chacha20poly1305_KEYBYTES,
				master_key,
				2);
		if (status != 0) {
			goto fail;
		}

		//NHKr, NHKs
		//NHKr = KDF(master_key, 0x03)
		status = derive_key(
				next_receive_header_key,
				crypto_aead_chacha20poly1305_KEYBYTES,
				master_key,
				3);
		if (status != 0) {
			goto fail;
		}
		//NHKs = KDF(master_key, 0x04)
		status = derive_key(
				next_send_header_key,
				crypto_aead_chacha20poly1305_KEYBYTES,
				master_key,
				4);
		if (status != 0) {
			goto fail;
		}
	}

	goto cleanup;

fail:
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

cleanup:
	buffer_destroy_from_heap(master_key);

	return status;
}
