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

#include "key-derivation.h"

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
	if (crypto_auth_BYTES != crypto_auth_KEYBYTES) {
		return -10;
	}

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
	if (crypto_auth_BYTES != crypto_auth_KEYBYTES) {
		return -10;
	}

	const unsigned char input_message = 0x00;

	//message_key = HMAC-Hash(chain_key, 0x00)
	//and return status
	return crypto_auth(message_key, &input_message, 1, chain_key);
}
