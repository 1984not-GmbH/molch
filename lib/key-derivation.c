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
 * RK, CK = HKDF( RK, DH(DHRr, DHRs) )
 */
int derive_root_and_chain_key(
		unsigned char * const root_key,
		unsigned char * const chain_key,
		const unsigned char * const our_private_ephemeral,
		const unsigned char * const our_public_ephemeral,
		const unsigned char * const their_public_ephemeral,
		const unsigned char * const previous_root_key,
		bool am_i_alice) {
	assert(crypto_secretbox_KEYBYTES == crypto_auth_KEYBYTES);

	//input key for HKDF (root key and chain key derivation)
	//input_key = DH(our_private_ephemeral, their_public_ephemeral)
	unsigned char input_key[crypto_secretbox_KEYBYTES];
	int status = diffie_hellman(
			input_key,
			our_private_ephemeral,
			our_public_ephemeral,
			their_public_ephemeral,
			am_i_alice);
	if (status != 0) {
		sodium_memzero(input_key, sizeof(input_key));
		return status;
	}

	//now create root and chain key in temporary buffer
	//RK, CK = HKDF(previous_root_key, input_key)
	const unsigned char info[] = "molch"; //TODO is this the final info string?
	unsigned char hkdf_buffer[2 * crypto_secretbox_KEYBYTES];
	status = hkdf(
			hkdf_buffer,
			sizeof(hkdf_buffer),
			previous_root_key, //salt
			input_key,
			sizeof(input_key),
			info,
			sizeof(info));
	sodium_memzero(input_key, sizeof(input_key));
	if (status != 0) {
		sodium_memzero(hkdf_buffer, sizeof(hkdf_buffer));
		return status;
	}

	//copy keys from hkdf buffer
	memcpy(root_key, hkdf_buffer, crypto_secretbox_KEYBYTES);
	memcpy(chain_key, hkdf_buffer + crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);

	sodium_memzero(hkdf_buffer, sizeof(hkdf_buffer));
	return 0;
}
