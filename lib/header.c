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
#include "endianness.h"

/*
 * Create a new header.
 *
 * The header looks like follows:
 * header (40) = {
 *   public_ephemeral_key (PUBLIC_KEY_SIZE = 32),
 *   message_counter (4)
 *   previous_message_counter(4)
 * }
 *
 * Don't forget to destroy the return status with return_status_destroy_errors()
 * if an error has occurred.
 */
return_status header_construct(
		buffer_t * const header, //PUBLIC_KEY_SIZE + 8
		const buffer_t * const our_public_ephemeral, //PUBLIC_KEY_SIZE
		const uint32_t message_counter,
		const uint32_t previous_message_counter) {
	return_status status = return_status_init();

	//check input
	if ((header == NULL) || (header->buffer_length < PUBLIC_KEY_SIZE + 2 * sizeof(uint32_t))
			|| (our_public_ephemeral == NULL) || (our_public_ephemeral->content_length != PUBLIC_KEY_SIZE)) {
		throw(INVALID_INPUT, "Invalid input to header_construct.");
	}

	int status_int;
	status_int = buffer_clone(header, our_public_ephemeral);
	if (status_int != 0) {
		throw(BUFFER_ERROR, "Failed to copy public ephemeral to header.");
	}

	//message counter as big endian
	buffer_create_with_existing_array(big_endian_message_counter, header->content + PUBLIC_KEY_SIZE, sizeof(uint32_t));
	status_int = endianness_uint32_to_big_endian(message_counter, big_endian_message_counter);
	if (status_int != 0) {
		throw(GENERIC_ERROR, "Failed to convert message counter to big endian.");
	}

	//previous message counter as big endian
	buffer_create_with_existing_array(big_endian_previous_message_counter, header->content + PUBLIC_KEY_SIZE + sizeof(uint32_t), sizeof(uint32_t));
	status_int = endianness_uint32_to_big_endian(previous_message_counter, big_endian_previous_message_counter);
	if (status_int != 0) {
		throw(GENERIC_ERROR, "Failed to convert previous message counter to big endian.");
	}

	header->content_length = PUBLIC_KEY_SIZE + 2 * sizeof(uint32_t);

cleanup:
	if (status.status != SUCCESS) {
		if (header != NULL) {
			buffer_clear(header);
		}
	}

	return status;
}

/*
 * Get the content of the header.
 */
int header_extract(
		const buffer_t * const header, //PUBLIC_KEY_SIZE + 8, input
		buffer_t * const their_public_ephemeral, //PUBLIC_KEY_SIZE, output
		uint32_t * const message_counter,
		uint32_t * const previous_message_counter) {
	//check buffer sizes
	if ((header->content_length != PUBLIC_KEY_SIZE + 8)
			|| (their_public_ephemeral->buffer_length < PUBLIC_KEY_SIZE)) {
		their_public_ephemeral->content_length = 0;
		return -6;
	}

	int status = 0;
	status = buffer_copy(their_public_ephemeral, 0, header, 0, PUBLIC_KEY_SIZE);
	if (status != 0) {
		goto cleanup;
	}

	//message counter from big endian
	buffer_create_with_existing_array(big_endian_message_counter, header->content + PUBLIC_KEY_SIZE, sizeof(uint32_t));
	status = endianness_uint32_from_big_endian(message_counter, big_endian_message_counter);
	if (status != 0) {
		goto cleanup;
	}

	//previous message counter from big endian
	buffer_create_with_existing_array(big_endian_previous_message_counter, header->content + PUBLIC_KEY_SIZE + sizeof(uint32_t), sizeof(uint32_t));
	status = endianness_uint32_from_big_endian(previous_message_counter, big_endian_previous_message_counter);
	if (status != 0) {
		goto cleanup;
	}

cleanup:
	if (status != 0) {
		buffer_clear(their_public_ephemeral);
	}

	return status;
}
