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
#include "hkdf.h"

//TODO maybe use another info string?
#define INFO (unsigned char*) "molch"

/*
 * Derive the next chain key in a message chain.
 *
 * The chain keys have to be crypto_auth_BYTES long.
 *
 * CK_new = HMAC-Hash(CK_prev, 0x01)
 * (previous chain key as key, 0x01 as message)
 */
int derive_chain_key(
		unsigned char * const new_chain_key,
		const unsigned char * const previous_chain_key) {
	//make sure assumptions about length are correct
	assert(crypto_auth_BYTES == crypto_auth_KEYBYTES);

	const unsigned char input_message = 0x01;

	//new_chain_key = HMAC-Hash(previous_chain_key, 0x01)
	//and return status
	return crypto_auth(new_chain_key, &input_message, 1, previous_chain_key);
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
		unsigned char * const message_key,
		const unsigned char * const chain_key) {
	//make sure assumptions about length are correct
	assert(crypto_auth_BYTES == crypto_auth_KEYBYTES);

	const unsigned char input_message = 0x00;

	//message_key = HMAC-Hash(chain_key, 0x00)
	//and return status
	return crypto_auth(message_key, &input_message, 1, chain_key);
}

/*
 * Derive a root and initial chain key for a new ratchet.
 *
 * The chain and root key have to be crypto_secretbox_KEYBYTES long.
 *
 * RK, CK, HK = HKDF( RK, DH(DHRr, DHRs) )
 */
int derive_root_chain_and_header_keys(
		unsigned char * const root_key, //crypto_secretbox_KEYBYTES
		unsigned char * const chain_key, //crypto_secretbox_KEYBYTES
		unsigned char * const header_key, //crypto_aead_chacha20poly1305_KEYBYTES
		const unsigned char * const our_private_ephemeral,
		const unsigned char * const our_public_ephemeral,
		const unsigned char * const their_public_ephemeral,
		const unsigned char * const previous_root_key,
		bool am_i_alice) {
	assert(crypto_secretbox_KEYBYTES == crypto_auth_KEYBYTES);

	//input key for HKDF (root key and chain key derivation)
	//input_key = DH(our_private_ephemeral, their_public_ephemeral)
	buffer_t *input_key = buffer_create(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	int status = diffie_hellman(
			input_key->content,
			our_private_ephemeral,
			our_public_ephemeral,
			their_public_ephemeral,
			am_i_alice);
	if (status != 0) {
		buffer_clear(input_key);
		return status;
	}

	//FIXME remove this once the entire library is moved over to buffer_t
	//Copy previous root key into a new buffer
	buffer_t *previous_root_key_buffer = buffer_create(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	buffer_clone_from_raw(previous_root_key_buffer, previous_root_key, crypto_secretbox_KEYBYTES);

	//now create root and chain key in temporary buffer
	//RK, CK = HKDF(previous_root_key, input_key)
	buffer_t *info = buffer_create_from_string(INFO);
	buffer_t *hkdf_buffer = buffer_create(2 * crypto_secretbox_KEYBYTES + crypto_aead_chacha20poly1305_KEYBYTES, 2 * crypto_secretbox_KEYBYTES + crypto_aead_chacha20poly1305_KEYBYTES);
	status = hkdf(
			hkdf_buffer,
			hkdf_buffer->content_length,
			previous_root_key_buffer, //salt
			input_key,
			info);
	buffer_clear(input_key);
	if (status != 0) {
		buffer_clear(hkdf_buffer);
		return status;
	}

	//copy keys from hkdf buffer
	memcpy(root_key, hkdf_buffer->content, crypto_secretbox_KEYBYTES);
	memcpy(chain_key, hkdf_buffer->content + crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	memcpy(header_key, hkdf_buffer->content + 2 * crypto_secretbox_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);

	buffer_clear(hkdf_buffer);
	return 0;
}

/*
 * Derive initial root, chain and header keys.
 *
 * RK, CKs/r, HKs/r, NHKs/r = HKDF(HASH(DH(A,B0) || DH(A0,B) || DH(A0,B0)))
 */
int derive_initial_root_chain_and_header_keys(
		unsigned char * const root_key, //crypto_secretbox_KEYBYTES
		unsigned char * const send_chain_key, //crypto_secretbox_KEYBYTES
		unsigned char * const receive_chain_key, //crypto_secretbox_KEYBYTES
		unsigned char * const send_header_key, //crypto_aead_chacha20poly1305_KEYBYTES
		unsigned char * const receive_header_key, //crypto_aead_chacha20poly1305_KEYBYTES
		unsigned char * const next_send_header_key, //crypto_aead_chacha20poly1305_KEYBYTES
		unsigned char * const next_receive_header_key, //crypto_aead_chacha20poly1305_KEYBYTES
		const unsigned char * const our_private_identity,
		const unsigned char * const our_public_identity,
		const unsigned char * const their_public_identity,
		const unsigned char * const our_private_ephemeral,
		const unsigned char * const our_public_ephemeral,
		const unsigned char * const their_public_ephemeral,
		bool am_i_alice) {
	//derive pre_root_key to later derive the initial root key,
	//header keys and chain keys from
	//pre_root_key = HASH( DH(A,B0) || DH(A0,B) || DH(A0,B0) )
	assert(crypto_secretbox_KEYBYTES == crypto_auth_BYTES);
	buffer_t *pre_root_key = buffer_create(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	int status = triple_diffie_hellman(
			pre_root_key->content,
			our_private_identity,
			our_public_identity,
			our_private_ephemeral,
			our_public_ephemeral,
			their_public_identity,
			their_public_ephemeral,
			am_i_alice);
	if (status != 0) {
		buffer_clear(pre_root_key);
		return status;
	}

	//derive chain, root and header keys from pre_root_key via HKDF
	//RK, CK, HK, NHK1, NHK2 = HKDF(salt, pre_root_key)
	buffer_t *hkdf_buffer = buffer_create(2 * crypto_secretbox_KEYBYTES + 3 * crypto_aead_chacha20poly1305_KEYBYTES, 2 * crypto_secretbox_KEYBYTES + 3 * crypto_aead_chacha20poly1305_KEYBYTES);
	buffer_t *salt = buffer_create_from_string("molch--libsodium-crypto-library");
	assert(salt->content_length == crypto_auth_KEYBYTES);
	buffer_t *info = buffer_create_from_string(INFO);
	status = hkdf(
			hkdf_buffer,
			hkdf_buffer->content_length,
			salt,
			pre_root_key,
			info);
	buffer_clear(pre_root_key);
	if (status != 0) {
		buffer_clear(hkdf_buffer);
		return status;
	}

	//now copy the keys
	//root key:
	memcpy(root_key, hkdf_buffer->content, crypto_secretbox_KEYBYTES);
	//chain keys and header keys
	if (am_i_alice) {
		//Alice: CKs=<none>, CKr=HKDF
		memset(send_chain_key, 0, crypto_secretbox_KEYBYTES);
		memcpy(receive_chain_key, hkdf_buffer->content + crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
		//HKs=<none>, HKr=HKDF
		memset(send_header_key, 0, crypto_secretbox_KEYBYTES);
		memcpy(receive_header_key, hkdf_buffer->content + 2 * crypto_secretbox_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);

		//NHKs, NHKr
		memcpy(next_send_header_key, hkdf_buffer->content + 2 * crypto_secretbox_KEYBYTES + crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
		memcpy(next_receive_header_key, hkdf_buffer->content + 2 * crypto_secretbox_KEYBYTES + 2 * crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
	} else {
		//Bob: CKs=HKDF, CKr=<none>
		memset(receive_chain_key, 0, crypto_secretbox_KEYBYTES);
		memcpy(send_chain_key, hkdf_buffer->content + crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
		//HKs=HKDF, HKr=<none>
		memset(receive_header_key, 0, crypto_secretbox_KEYBYTES);
		memcpy(send_header_key, hkdf_buffer->content + 2 * crypto_secretbox_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);

		//NHKr, NHKs
		memcpy(next_receive_header_key, hkdf_buffer->content + 2 * crypto_secretbox_KEYBYTES + crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
		memcpy(next_send_header_key, hkdf_buffer->content + 2 * crypto_secretbox_KEYBYTES + 2 * crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
	}
	buffer_clear(hkdf_buffer);

	return 0;
}
