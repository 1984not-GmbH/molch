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
return_status diffie_hellman(
		buffer_t * const derived_key, //needs to be DIFFIE_HELLMAN_SIZE long
		const buffer_t * const our_private_key, //needs to be PRIVATE_KEY_SIZE long
		const buffer_t * const our_public_key, //needs to be PUBLIC_KEY_SIZE long
		const buffer_t * const their_public_key, //needs to be PUBLIC_KEY_SIZE long
		const bool am_i_alice) {

	return_status status = return_status_init();

	//make sure that the assumptions are correct
	assert(PUBLIC_KEY_SIZE == crypto_scalarmult_SCALARBYTES);
	assert(PRIVATE_KEY_SIZE == crypto_scalarmult_SCALARBYTES);
	assert(DIFFIE_HELLMAN_SIZE == crypto_generichash_BYTES);

	//set content length of output to 0 (can prevent use on failure)
	derived_key->content_length = 0;

	//buffer for diffie hellman shared secret
	buffer_t *dh_secret = buffer_create_on_heap(crypto_scalarmult_SCALARBYTES, crypto_scalarmult_SCALARBYTES);
	throw_on_failed_alloc(dh_secret);

	crypto_generichash_state hash_state[1];

	//check buffer sizes
	if ((derived_key->buffer_length < DIFFIE_HELLMAN_SIZE)
			|| (our_private_key->content_length != PRIVATE_KEY_SIZE)
			|| (our_public_key->content_length != PUBLIC_KEY_SIZE)
			|| (their_public_key->content_length != PUBLIC_KEY_SIZE)
			|| (our_private_key->buffer_length < PRIVATE_KEY_SIZE)
			|| (our_public_key->buffer_length < PUBLIC_KEY_SIZE)
			|| (their_public_key->buffer_length < PUBLIC_KEY_SIZE)) {
		throw(INVALID_INPUT, "Invalid input to diffie_hellman.");
	}


	//do the diffie hellman key exchange
	int status_int = 0;
	if (crypto_scalarmult(dh_secret->content, our_private_key->content, their_public_key->content) != 0) {
		throw(KEYDERIVATION_FAILED, "Failed to do crypto_scalarmult.");
	}

	//initialize hashing
	status_int = crypto_generichash_init(
			hash_state,
			NULL, //key
			0, //key_length
			DIFFIE_HELLMAN_SIZE); //output length
	if (status_int != 0) {
		throw(GENERIC_ERROR, "Failed to initialize hash.");
	}

	//start input to hash with diffie hellman secret
	if (crypto_generichash_update(hash_state, dh_secret->content, dh_secret->content_length) != 0) {
		throw(GENERIC_ERROR, "Failed to add the diffie hellman secret to the hash input.");
	}

	//add public keys to the input of the hash
	if (am_i_alice) { //Alice (our_public_key|their_public_key)
		//add our_public_key to the input of the hash
		if (crypto_generichash_update(hash_state, our_public_key->content, our_public_key->content_length) != 0) {
			throw(GENERIC_ERROR, "Failed to add Alice' public key to the hash input.");
		}

		//add their_public_key to the input of the hash
		if (crypto_generichash_update(hash_state, their_public_key->content, their_public_key->content_length) != 0) {
			throw(GENERIC_ERROR, "Failed to add Bob's public key to the hash input.");
		}
	} else { //Bob (their_public_key|our_public_key)
		//add their_public_key to the input of the hash
		if (crypto_generichash_update(hash_state, their_public_key->content, their_public_key->content_length) != 0) {
			throw(GENERIC_ERROR, "Failed to add Alice's public key to the hash input.");
		}

		//add our_public_key to the input of the hash
		if (crypto_generichash_update(hash_state, our_public_key->content, our_public_key->content_length) != 0) {
			throw(GENERIC_ERROR, "Failed to add Bob's public key to the hash input.");
		}
	}

	//finally write the hash to derived_key
	if (crypto_generichash_final(hash_state, derived_key->content, DIFFIE_HELLMAN_SIZE) != 0) {
		throw(GENERIC_ERROR, "Failed to finalize hash.");
	}
	derived_key->content_length = DIFFIE_HELLMAN_SIZE;

cleanup:
	buffer_destroy_from_heap_and_null(dh_secret);
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
return_status triple_diffie_hellman(
		buffer_t * const derived_key,
		const buffer_t * const our_private_identity,
		const buffer_t * const our_public_identity,
		const buffer_t * const our_private_ephemeral,
		const buffer_t * const our_public_ephemeral,
		const buffer_t * const their_public_identity,
		const buffer_t * const their_public_ephemeral,
		const bool am_i_alice) {
	return_status status = return_status_init();

	//set content length of output to 0 (can prevent use on failure)
	derived_key->content_length = 0;

	//buffers for all 3 Diffie Hellman exchanges
	buffer_t *dh1 = NULL;
	buffer_t *dh2 = NULL;
	buffer_t *dh3 = NULL;
	dh1 = buffer_create_on_heap(DIFFIE_HELLMAN_SIZE, DIFFIE_HELLMAN_SIZE);
	throw_on_failed_alloc(dh1);
	dh2 = buffer_create_on_heap(DIFFIE_HELLMAN_SIZE, DIFFIE_HELLMAN_SIZE);
	throw_on_failed_alloc(dh2);
	dh3 = buffer_create_on_heap(DIFFIE_HELLMAN_SIZE, DIFFIE_HELLMAN_SIZE);
	throw_on_failed_alloc(dh3);

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
		throw(INVALID_INPUT, "Invalid input to triple_diffie_hellman.");
	}

	int status_int = 0;
	if (am_i_alice) {
		//DH(our_identity, their_ephemeral)
		status = diffie_hellman(
				dh1,
				our_private_identity,
				our_public_identity,
				their_public_ephemeral,
				am_i_alice);
		throw_on_error(KEYDERIVATION_FAILED, "Failed to perform diffie hellman on our identity and their ephemeral.");

		//DH(our_ephemeral, their_identity)
		status = diffie_hellman(
				dh2,
				our_private_ephemeral,
				our_public_ephemeral,
				their_public_identity,
				am_i_alice);
		throw_on_error(KEYDERIVATION_FAILED, "Failed to perform diffie hellman on our ephemeral and their identity.");
	} else {
		//DH(our_ephemeral, their_identity)
		status = diffie_hellman(
				dh1,
				our_private_ephemeral,
				our_public_ephemeral,
				their_public_identity,
				am_i_alice);
		throw_on_error(KEYDERIVATION_FAILED, "Failed to perform diffie hellman on our ephemeral and their identy.");

		//DH(our_identity, their_ephemeral)
		status = diffie_hellman(
				dh2,
				our_private_identity,
				our_public_identity,
				their_public_ephemeral,
				am_i_alice);
		throw_on_error(KEYDERIVATION_FAILED, "Failed to perform diffie hellman on our identity and their ephemeral.");
	}

	//DH(our_ephemeral, their_ephemeral)
	//this is identical for both Alice and Bob
	status = diffie_hellman(
			dh3,
			our_private_ephemeral,
			our_public_ephemeral,
			their_public_ephemeral,
			am_i_alice);
	throw_on_error(KEYDERIVATION_FAILED, "Failed to perform diffie hellman on our ephemeral and their ephemeral.");

	//now calculate HASH(DH(A,B0) || DH(A0,B) || DH(A0,B0))
	//( HASH(dh1|| dh2 || dh3) )

	//initialize hashing
	crypto_generichash_state hash_state[1];
	status_int = crypto_generichash_init(
			hash_state,
			NULL, //key
			0, //key_length
			DIFFIE_HELLMAN_SIZE); //output_length
	if (status_int != 0) {
		throw(GENERIC_ERROR, "Failed to initialize hash.");
	}

	//add dh1 to hash input
	if (crypto_generichash_update(hash_state, dh1->content, DIFFIE_HELLMAN_SIZE) != 0) {
		throw(GENERIC_ERROR, "Failed to add dh1 to the hash input.");
	}

	//add dh2 to hash input
	if (crypto_generichash_update(hash_state, dh2->content, DIFFIE_HELLMAN_SIZE) != 0) {
		throw(GENERIC_ERROR, "Failed to add dh2 to the hash input.");
	}

	//add dh3 to hash input
	if (crypto_generichash_update(hash_state, dh3->content, DIFFIE_HELLMAN_SIZE) != 0) {
		throw(GENERIC_ERROR, "Failed to add dh3 to the hash input.");
	}

	//write final hash to output (derived_key)
	if (crypto_generichash_final(hash_state, derived_key->content, DIFFIE_HELLMAN_SIZE) != 0) {
		sodium_memzero(hash_state, sizeof(crypto_generichash_state));
		throw(GENERIC_ERROR, "Failed to finalize hash");
	}
	derived_key->content_length = DIFFIE_HELLMAN_SIZE;
	sodium_memzero(hash_state, sizeof(crypto_generichash_state));

cleanup:
	buffer_destroy_from_heap_and_null(dh1);
	buffer_destroy_from_heap_and_null(dh2);
	buffer_destroy_from_heap_and_null(dh3);

	return status;
}
