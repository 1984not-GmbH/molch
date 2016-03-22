/*  Molch, an implementation of the axolotl ratchet based on libsodium
 *  Copyright (C) 2015-2016 1984not Security GmbH
 *  Author: Max Bruckner (FSMaxB)
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

#include "constants.h"
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
		buffer_t * const derived_key, //needs to be DIFFIE_HELLMAN_SIZE long
		const buffer_t * const our_private_key, //needs to be PRIVATE_KEY_SIZE long
		const buffer_t * const our_public_key, //needs to be PUBLIC_KEY_SIZE long
		const buffer_t * const their_public_key, //needs to be PUBLIC_KEY_SIZE long
		const bool am_i_alice) {
	//make sure that the assumptions are correct
	assert(PUBLIC_KEY_SIZE == crypto_scalarmult_SCALARBYTES);
	assert(PRIVATE_KEY_SIZE == crypto_scalarmult_SCALARBYTES);
	assert(DIFFIE_HELLMAN_SIZE == crypto_generichash_BYTES);

	//set content length of output to 0 (can prevent use on failure)
	derived_key->content_length = 0;

	//check buffer sizes
	if ((derived_key->buffer_length < DIFFIE_HELLMAN_SIZE)
			|| (our_private_key->content_length != PRIVATE_KEY_SIZE)
			|| (our_public_key->content_length != PUBLIC_KEY_SIZE)
			|| (their_public_key->content_length != PUBLIC_KEY_SIZE)
			|| (our_private_key->buffer_length < PRIVATE_KEY_SIZE)
			|| (our_public_key->buffer_length < PUBLIC_KEY_SIZE)
			|| (their_public_key->buffer_length < PUBLIC_KEY_SIZE)) {
		return -6;
	}

	//buffer for diffie hellman shared secret
	buffer_t *dh_secret = buffer_create_on_heap(crypto_scalarmult_SCALARBYTES, crypto_scalarmult_SCALARBYTES);

	//do the diffie hellman key exchange
	int status;
	status = crypto_scalarmult(dh_secret->content, our_private_key->content, their_public_key->content);
	if (status != 0) {
		buffer_destroy_from_heap(dh_secret);
		return status;
	}

	//initialize hashing
	crypto_generichash_state hash_state[1];
	status = crypto_generichash_init(
			hash_state,
			NULL, //key
			0, //key_length
			DIFFIE_HELLMAN_SIZE); //output length
	if (status != 0) {
		buffer_destroy_from_heap(dh_secret);
		sodium_memzero(hash_state, sizeof(crypto_generichash_state));
		return status;
	}

	//start input to hash with diffie hellman secret
	status = crypto_generichash_update(hash_state, dh_secret->content, dh_secret->content_length);
	buffer_destroy_from_heap(dh_secret);
	if (status != 0) {
		sodium_memzero(hash_state, sizeof(crypto_generichash_state));
		return status;
	}

	//add public keys to the input of the hash
	if (am_i_alice) { //Alice (our_public_key|their_public_key)
		//add our_public_key to the input of the hash
		status = crypto_generichash_update(hash_state, our_public_key->content, our_public_key->content_length);
		if (status != 0) {
			sodium_memzero(hash_state, sizeof(crypto_generichash_state));
			return status;
		}

		//add their_public_key to the input of the hash
		status = crypto_generichash_update(hash_state, their_public_key->content, their_public_key->content_length);
		if (status != 0) {
			sodium_memzero(hash_state, sizeof(crypto_generichash_state));
			return status;
		}
	} else { //Bob (their_public_key|our_public_key)
		//add their_public_key to the input of the hash
		status = crypto_generichash_update(hash_state, their_public_key->content, their_public_key->content_length);
		if (status != 0) {
			sodium_memzero(hash_state, sizeof(crypto_generichash_state));
			return status;
		}

		//add our_public_key to the input of the hash
		status = crypto_generichash_update(hash_state, our_public_key->content, our_public_key->content_length);
		if (status != 0) {
			sodium_memzero(hash_state, sizeof(crypto_generichash_state));
			return status;
		}
	}

	//finally write the hash to derived_key
	status = crypto_generichash_final(hash_state, derived_key->content, DIFFIE_HELLMAN_SIZE);
	if (status != 0) {
		sodium_memzero(hash_state, sizeof(crypto_generichash_state));
		return status;
	}
	derived_key->content_length = DIFFIE_HELLMAN_SIZE;
	sodium_memzero(hash_state, sizeof(crypto_generichash_state));
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
		buffer_t * const derived_key,
		const buffer_t * const our_private_identity,
		const buffer_t * const our_public_identity,
		const buffer_t * const our_private_ephemeral,
		const buffer_t * const our_public_ephemeral,
		const buffer_t * const their_public_identity,
		const buffer_t * const their_public_ephemeral,
		const bool am_i_alice) {
	//set content length of output to 0 (can prevent use on failure)
	derived_key->content_length = 0;

	//check buffer sizes
	if ((derived_key->buffer_length < DIFFIE_HELLMAN_SIZE)
			|| (our_private_identity->content_length != PRIVATE_KEY_SIZE)
			|| (our_public_identity->content_length != PUBLIC_KEY_SIZE)
			|| (their_public_identity->content_length != PUBLIC_KEY_SIZE)
			|| (our_private_ephemeral->content_length != PRIVATE_KEY_SIZE)
			|| (our_public_ephemeral->content_length != PUBLIC_KEY_SIZE)
			|| (their_public_ephemeral->content_length != PUBLIC_KEY_SIZE)
			|| (our_private_identity->buffer_length < PRIVATE_KEY_SIZE)
			|| (our_public_identity->buffer_length < PUBLIC_KEY_SIZE)
			|| (their_public_identity->buffer_length < PUBLIC_KEY_SIZE)
			|| (our_private_ephemeral->buffer_length < PRIVATE_KEY_SIZE)
			|| (our_public_ephemeral->buffer_length < PUBLIC_KEY_SIZE)
			|| (their_public_ephemeral->buffer_length < PUBLIC_KEY_SIZE)) {
		return -6;
	}

	int status;
	//buffers for all 3 Diffie Hellman exchanges
	buffer_t *dh1 = buffer_create_on_heap(DIFFIE_HELLMAN_SIZE, DIFFIE_HELLMAN_SIZE);
	buffer_t *dh2 = buffer_create_on_heap(DIFFIE_HELLMAN_SIZE, DIFFIE_HELLMAN_SIZE);
	buffer_t *dh3 = buffer_create_on_heap(DIFFIE_HELLMAN_SIZE, DIFFIE_HELLMAN_SIZE);

	if (am_i_alice) {
		//DH(our_identity, their_ephemeral)
		status = diffie_hellman(
				dh1,
				our_private_identity,
				our_public_identity,
				their_public_ephemeral,
				am_i_alice);
		if (status != 0) {
			goto cleanup;
		}

		//DH(our_ephemeral, their_identity)
		status = diffie_hellman(
				dh2,
				our_private_ephemeral,
				our_public_ephemeral,
				their_public_identity,
				am_i_alice);
		if (status != 0) {
			goto cleanup;
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
			goto cleanup;
		}

		//DH(our_identity, their_ephemeral)
		status = diffie_hellman(
				dh2,
				our_private_identity,
				our_public_identity,
				their_public_ephemeral,
				am_i_alice);
		if (status != 0) {
			goto cleanup;
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
		goto cleanup;
	}

	//now calculate HASH(DH(A,B0) || DH(A0,B) || DH(A0,B0))
	//( HASH(dh1|| dh2 || dh3) )

	//initialize hashing
	crypto_generichash_state hash_state[1];
	status = crypto_generichash_init(
			hash_state,
			NULL, //key
			0, //key_length
			DIFFIE_HELLMAN_SIZE); //output_length
	if (status != 0) {
		goto cleanup;
	}

	//add dh1 to hash input
	status = crypto_generichash_update(hash_state, dh1->content, DIFFIE_HELLMAN_SIZE);
	if (status != 0) {
		goto cleanup;
	}

	//add dh2 to hash input
	status = crypto_generichash_update(hash_state, dh2->content, DIFFIE_HELLMAN_SIZE);
	if (status != 0) {
		goto cleanup;
	}

	//add dh3 to hash input
	status = crypto_generichash_update(hash_state, dh3->content, DIFFIE_HELLMAN_SIZE);
	if (status != 0) {
		goto cleanup;
	}

	//write final hash to output (derived_key)
	status = crypto_generichash_final(hash_state, derived_key->content, DIFFIE_HELLMAN_SIZE);
	if (status != 0) {
		sodium_memzero(hash_state, sizeof(crypto_generichash_state));
		goto cleanup;
	}
	derived_key->content_length = DIFFIE_HELLMAN_SIZE;
	sodium_memzero(hash_state, sizeof(crypto_generichash_state));

cleanup:
	buffer_destroy_from_heap(dh1);
	buffer_destroy_from_heap(dh2);
	buffer_destroy_from_heap(dh3);
	return status;
}
