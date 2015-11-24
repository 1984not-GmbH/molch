/* Molch, an implementation of the axolotl ratchet based on libsodium
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
#include <string.h>
#include <assert.h>

#include "header.h"

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
		buffer_t * const header_buffer, //crypto_box_PUBLICKEYBYTES + 8
		const buffer_t * const our_public_ephemeral, //crypto_box_PUBLICKEYBYTES
		const uint32_t message_counter,
		const uint32_t previous_message_counter) { //FIXME: Endianness
	//check buffer sizes
	if ((header_buffer->buffer_length < crypto_box_PUBLICKEYBYTES + 8)
			|| (our_public_ephemeral->content_length != crypto_box_PUBLICKEYBYTES)) {
		header_buffer->content_length = 0;
		return -6;
	}

	//directly access the content of the header buffer via the header_t struct
	header_t * const header = (header_t*)header_buffer->content;

	int status;
	status = buffer_clone_to_raw(header->public_ephemeral, sizeof(header->public_ephemeral), our_public_ephemeral);
	if (status != 0) {
		buffer_clear(header_buffer);
		return status;
	}

	header_buffer->content_length = sizeof(*header);

	header->message_counter = message_counter;
	header->previous_message_counter = previous_message_counter;

	return 0;
}

/*
 * Get the content of the header.
 */
int header_extract(
		const buffer_t * const header_buffer, //crypto_box_PUBLICKEYBYTES + 8, input
		buffer_t * const their_public_ephemeral, //crypto_box_PUBLICKEYBYTES, output
		uint32_t * const message_counter,
		uint32_t * const previous_message_counter) { //FIXME Endianness
	//check buffer sizes
	if ((header_buffer->content_length != sizeof(header_t))
			|| (their_public_ephemeral->buffer_length < crypto_box_PUBLICKEYBYTES)) {
		their_public_ephemeral->content_length = 0;
		return -6;
	}

	//directly access the content of the header buffer via the header_t struct
	const header_t * const header = (header_t*) header_buffer->content;

	int status;
	status = buffer_clone_from_raw(their_public_ephemeral, header->public_ephemeral, sizeof(header->public_ephemeral));
	if (status != 0) {
		buffer_clear(their_public_ephemeral);
		return status;
	}
	*message_counter = header->message_counter;
	*previous_message_counter = header->previous_message_counter;

	return 0;
}
