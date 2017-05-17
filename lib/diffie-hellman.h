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

#include <stdbool.h>

#include "buffer.h"
#include "common.h"

#ifndef LIB_DIFFIE_HELLMAN_H
#define LIB_DIFFIE_HELLMAN_H

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
		const bool am_i_alice) __attribute__((warn_unused_result));

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
		const bool am_i_alice) __attribute__((warn_unused_result));
#endif
