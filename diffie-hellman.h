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

#include <stdbool.h>

#ifndef DIFFIE_HELLMAN_H
#define DIFFIE_HELLMAN_H

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
		bool i_am_alice);
#endif
