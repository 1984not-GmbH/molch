/*  Molch, an implementation of the axolotl ratched based on libsodium
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

#include "diffie-hellman.h"

/*
 * Diffie Hellman key exchange using our private key and the
 * other's public key. Our public key is used to derive a Hash
 * from the actual output of the diffie hellman exchange (see
 * documentation of libsodium).
 *
 * i_am_alice specifies if I am Alice or Bob. This determines in
 * what order the public key get hashed.
 *
 * OUTPUT:
 * Alice: H(ECDH(our_private_key,their_public_key)|our_public_key|their_public_key)
 * Bob:   H(ECDH(our_private_key,their_public_key)|their_public_key|our_public_key)
 */
int diffie_hellman(
		unsigned char* derived_key, //needs to be crypto_generichash_BYTES long
		unsigned char* our_private_key, //needs to be crypto_box_SECRETKEYBYTES long
		unsigned char* our_public_key, //needs to be crypto_box_PUBLICKEYBYTES long
		unsigned char* their_public_key, //needs to be crypto_box_PUBLICKEYBYTES long
		bool i_am_alice) {
	//make sure that the assumptions are correct
	if ((crypto_box_PUBLICKEYBYTES != crypto_scalarmult_SCALARBYTES) || (crypto_box_SECRETKEYBYTES != crypto_scalarmult_SCALARBYTES)) {
		return -10;
	}

	//buffer for diffie hellman shared secret
	unsigned char dh_secret[crypto_scalarmult_BYTES];

	//do the diffie hellman key exchange
	int status;
	status = crypto_scalarmult(dh_secret, our_private_key, their_public_key);
	if (status != 0) {
		sodium_memzero(dh_secret, crypto_scalarmult_BYTES);
		return status;
	}

	//initialize hashing
	crypto_generichash_state hash_state;
	status = crypto_generichash_init(
			&hash_state,
			NULL, //key
			0, //key_length
			crypto_generichash_BYTES);
	if (status != 0) {
		sodium_memzero(dh_secret, crypto_scalarmult_BYTES);
		return status;
	}

	//start input to hash with diffie hellman secret
	status = crypto_generichash_update(&hash_state, dh_secret, crypto_scalarmult_BYTES);
	sodium_memzero(dh_secret, crypto_scalarmult_BYTES);
	if (status != 0) {
		return status;
	}

	//add public keys to the input of the hash
	if (i_am_alice) { //Alice (our_public_key|their_public_key)
		//add our_public_key to the input of the hash
		status = crypto_generichash_update(&hash_state, our_public_key, crypto_box_PUBLICKEYBYTES);
		if (status != 0) {
			return status;
		}

		//add their_public_key to the input of the hash
		status = crypto_generichash_update(&hash_state, their_public_key, crypto_box_PUBLICKEYBYTES);
		if (status != 0) {
			return status;
		}
	} else { //Bob (their_public_key|our_public_key)
		//add their_public_key to the input of the hash
		status = crypto_generichash_update(&hash_state, their_public_key, crypto_box_PUBLICKEYBYTES);
		if (status != 0) {
			return status;
		}

		//add our_public_key to the input of the hash
		status = crypto_generichash_update(&hash_state, our_public_key, crypto_box_PUBLICKEYBYTES);
		if (status != 0) {
			return status;
		}
	}

	//finally write the hash to derived_key
	status = crypto_generichash_final(&hash_state, derived_key, crypto_generichash_BYTES);

	//generate hash over diffie hellman secret and public keys
	sodium_memzero(dh_secret, crypto_scalarmult_BYTES);
	return 0;
}
