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

#include "../buffer/buffer.h"

#ifndef LIB_HEADER_H
#define LIB_HEADER_H

typedef struct header_t {
	unsigned char public_ephemeral[crypto_box_PUBLICKEYBYTES];
	uint32_t message_counter;
	uint32_t previous_message_counter;
} header_t;

/*
 * Create a new header.
 *
 * The header looks like follows:
 * header (40) = {
 *   public_ephemeral_key (crypto_box_PUBLICKEYBYTES = 32),
 *   message_counter (4)
 *   previous_message_counter(4)
 * }
 */
int header_construct(
		buffer_t * const header, //crypto_box_PUBLICKEYBYTES + 8, output
		const buffer_t * const our_public_ephemeral, //crypto_box_PUBLICKEYBYTES
		const uint32_t message_counter,
		const uint32_t previous_message_counter) __attribute__((warn_unused_result));

/*
 * Get the content of the header.
 */
int header_extract(
		const buffer_t * const header, //crypto_box_PUBLICKEYBYTES + 8, input
		buffer_t * const their_public_ephemeral, //crypto_box_PUBLICKEYBYTES, output
		uint32_t * const message_counter,
		uint32_t * const previous_message_counter) __attribute__((warn_unused_result));
#endif
