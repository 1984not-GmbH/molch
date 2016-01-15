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

#include "constants.h"
#include "header.h"

/*
 * Create a new header.
 *
 * The header looks like follows:
 * header (40) = {
 *   public_ephemeral_key (PUBLIC_KEY_SIZE = 32),
 *   message_counter (4)
 *   previous_message_counter(4)
 * }
 */
int header_construct(
		buffer_t * const header, //PUBLIC_KEY_SIZE + 8
		const buffer_t * const our_public_ephemeral, //PUBLIC_KEY_SIZE
		const uint32_t message_counter,
		const uint32_t previous_message_counter) { //FIXME: Endianness
	//check buffer sizes
	if ((header->buffer_length < PUBLIC_KEY_SIZE + 8)
			|| (our_public_ephemeral->content_length != PUBLIC_KEY_SIZE)) {
		header->content_length = 0;
		return -6;
	}
	int status;
	status = buffer_clone(header, our_public_ephemeral);
	if (status != 0) {
		buffer_clear(header);
		return status;
	}
	status = buffer_copy_from_raw(header, PUBLIC_KEY_SIZE, (unsigned char*) &message_counter, 0, sizeof(message_counter));
	if (status != 0) {
		buffer_clear(header);
		return status;
	}
	status = buffer_copy_from_raw(header, PUBLIC_KEY_SIZE + sizeof(message_counter), (unsigned char*) &previous_message_counter, 0, sizeof(previous_message_counter));
	if (status != 0) {
		buffer_clear(header);
		return status;
	}

	return 0;
}

/*
 * Get the content of the header.
 */
int header_extract(
		const buffer_t * const header, //PUBLIC_KEY_SIZE + 8, input
		buffer_t * const their_public_ephemeral, //PUBLIC_KEY_SIZE, output
		uint32_t * const message_counter,
		uint32_t * const previous_message_counter) { //FIXME Endianness
	//check buffer sizes
	if ((header->content_length != PUBLIC_KEY_SIZE + 8)
			|| (their_public_ephemeral->buffer_length < PUBLIC_KEY_SIZE)) {
		their_public_ephemeral->content_length = 0;
		return -6;
	}

	int status;
	status = buffer_copy(their_public_ephemeral, 0, header, 0, PUBLIC_KEY_SIZE);
	if (status != 0) {
		buffer_clear(their_public_ephemeral);
		return status;
	}
	*message_counter = *(uint32_t*) (header->content + PUBLIC_KEY_SIZE);
	*previous_message_counter = *(uint32_t*) (header->content + PUBLIC_KEY_SIZE + sizeof(uint32_t));

	return 0;
}
