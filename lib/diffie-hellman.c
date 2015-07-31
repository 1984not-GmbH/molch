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

#include "diffie-hellman.h"

/*
 * Diffie Hellman key exchange using our private key and the
 * other's public key. Our public key is used to derive a Hash
 * from the actual output of the diffie hellman exchange (see
 * documentation of libsodium).
 *
 * am_i_alice specifies if I am Alice or Bob. This determines in
 * what order the public keys get hashed.
 *
 * OUTPUT:
 * Alice: H(ECDH(our_private_key,their_public_key)|our_public_key|their_public_key)
 * Bob:   H(ECDH(our_private_key,their_public_key)|their_public_key|our_public_key)
 */
int diffie_hellman(
		unsigned char * const derived_key, //needs to be crypto_generichash_BYTES long
		const unsigned char * const our_private_key, //needs to be crypto_box_SECRETKEYBYTES long
		const unsigned char * const our_public_key, //needs to be crypto_box_PUBLICKEYBYTES long
		const unsigned char * const their_public_key, //needs to be crypto_box_PUBLICKEYBYTES long
		const bool am_i_alice) {
	//make sure that the assumptions are correct
	assert(crypto_box_PUBLICKEYBYTES == crypto_scalarmult_SCALARBYTES);
	assert(crypto_box_SECRETKEYBYTES == crypto_scalarmult_SCALARBYTES);

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
	if (am_i_alice) { //Alice (our_public_key|their_public_key)
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
	sodium_memzero(dh_secret, crypto_scalarmult_BYTES);
	return status;
}

/*
 * Triple Diffie Hellman with two keys.
 *
 * am_i_alice specifies if I am Alice or Bob. This determines in
 * what order the public keys get hashed.
 *
 * OUTPUT:
 * HASH(DH(A,B0) || DH(A0,B) || DH(A0,B0))
 * Where:
 * A: Alice's identity
 * A0: Alice's ephemeral
 * B: Bob's identity
 * B0: Bob's ephemeral
 * -->Alice: HASH(DH(our_identity, their_ephemeral)||DH(our_ephemeral, their_identity)||DH(our_ephemeral, their_ephemeral))
 * -->Bob: HASH(DH(their_identity, our_ephemeral)||DH(our_identity, their_ephemeral)||DH(our_ephemeral, their_ephemeral))
 */
int triple_diffie_hellman(
		unsigned char * const derived_key,
		const unsigned char * const our_private_identity,
		const unsigned char * const our_public_identity,
		const unsigned char * const our_private_ephemeral,
		const unsigned char * const our_public_ephemeral,
		const unsigned char * const their_public_identity,
		const unsigned char * const their_public_ephemeral,
		const bool am_i_alice) {
	//buffers for all 3 Diffie Hellman exchanges
	unsigned char dh1[crypto_generichash_BYTES];
	unsigned char dh2[crypto_generichash_BYTES];
	unsigned char dh3[crypto_generichash_BYTES];

	int status;

	if (am_i_alice) {
		//DH(our_identity, their_ephemeral)
		status = diffie_hellman(
				dh1,
				our_private_identity,
				our_public_identity,
				their_public_ephemeral,
				am_i_alice);
		if (status != 0) {
			sodium_memzero(dh1, crypto_generichash_BYTES);
			return status;
		}

		//DH(our_ephemeral, their_identity)
		status = diffie_hellman(
				dh2,
				our_private_ephemeral,
				our_public_ephemeral,
				their_public_identity,
				am_i_alice);
		if (status != 0) {
			sodium_memzero(dh2, crypto_generichash_BYTES);
			sodium_memzero(dh1, crypto_generichash_BYTES);
			return status;
		}
	} else {
		//DH(our_ephemeral, their_identity)
		status = diffie_hellman(
				dh1,
				our_private_ephemeral,
				our_public_ephemeral,
				their_public_identity,
				am_i_alice);
		if (status != 0) {
			sodium_memzero(dh1, crypto_generichash_BYTES);
			return status;
		}

		//DH(our_identity, their_ephemeral)
		status = diffie_hellman(
				dh2,
				our_private_identity,
				our_public_identity,
				their_public_ephemeral,
				am_i_alice);
		if (status != 0) {
			sodium_memzero(dh2, crypto_generichash_BYTES);
			sodium_memzero(dh1, crypto_generichash_BYTES);
			return status;
		}
	}

	//DH(our_ephemeral, their_ephemeral)
	//this is identical for both Alice and Bob
	status = diffie_hellman(
			dh3,
			our_private_ephemeral,
			our_public_ephemeral,
			their_public_ephemeral,
			am_i_alice);
	if (status != 0) {
		sodium_memzero(dh3, crypto_generichash_BYTES);
		sodium_memzero(dh2, crypto_generichash_BYTES);
		sodium_memzero(dh1, crypto_generichash_BYTES);
		return status;
	}

	//now calculate HASH(DH(A,B0) || DH(A0,B) || DH(A0,B0))
	//( HASH(dh1|| dh2 || dh3) )

	//initialize hashing
	crypto_generichash_state hash_state;
	status = crypto_generichash_init(
			&hash_state,
			NULL, //key
			0, //key_length
			crypto_generichash_BYTES); //output_length
	if (status != 0) {
		sodium_memzero(dh1, crypto_generichash_BYTES);
		sodium_memzero(dh2, crypto_generichash_BYTES);
		sodium_memzero(dh3, crypto_generichash_BYTES);
		return status;
	}

	//add dh1 to hash input
	status = crypto_generichash_update(&hash_state, dh1, crypto_generichash_BYTES);
	sodium_memzero(dh1, crypto_generichash_BYTES);
	if (status != 0) {
		sodium_memzero(dh2, crypto_generichash_BYTES);
		sodium_memzero(dh3, crypto_generichash_BYTES);
		return status;
	}

	//add dh2 to hash input
	status = crypto_generichash_update(&hash_state, dh2, crypto_generichash_BYTES);
	sodium_memzero(dh2, crypto_generichash_BYTES);
	if (status != 0) {
		sodium_memzero(dh3, crypto_generichash_BYTES);
		return status;
	}

	//add dh3 to hash input
	status = crypto_generichash_update(&hash_state, dh3, crypto_generichash_BYTES);
	sodium_memzero(dh3, crypto_generichash_BYTES);
	if (status != 0) {
		return status;
	}

	//write final hash to output (derived_key)
	status = crypto_generichash_final(&hash_state, derived_key, crypto_generichash_BYTES);
	return status;
}
