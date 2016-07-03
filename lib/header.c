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
	status = endianness_uint32_to_big_endian(message_counter, big_endian_message_counter);
	throw_on_error(GENERIC_ERROR, "Failed to convert message counter to big endian.");

	//previous message counter as big endian
	buffer_create_with_existing_array(big_endian_previous_message_counter, header->content + PUBLIC_KEY_SIZE + sizeof(uint32_t), sizeof(uint32_t));
	status = endianness_uint32_to_big_endian(previous_message_counter, big_endian_previous_message_counter);
	throw_on_error(GENERIC_ERROR, "Failed to convert previous message counter to big endian.");

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
 *
 * Don't forget to destroy the return status with return_status_destroy_errors()
 * if an error has occurred.
 */
return_status header_extract(
		const buffer_t * const header, //PUBLIC_KEY_SIZE + 8, input
		buffer_t * const their_public_ephemeral, //PUBLIC_KEY_SIZE, output
		uint32_t * const message_counter,
		uint32_t * const previous_message_counter) {
	return_status status = return_status_init();

	//check input
	if ((header == NULL) || (header->content_length != PUBLIC_KEY_SIZE + 8)
			|| (their_public_ephemeral == NULL) || (their_public_ephemeral->buffer_length < PUBLIC_KEY_SIZE)) {
		throw(INVALID_INPUT, "Invalid input to header_extract.");
	}

	int status_int = 0;
	status_int = buffer_copy(their_public_ephemeral, 0, header, 0, PUBLIC_KEY_SIZE);
	if (status_int != 0) {
		throw(BUFFER_ERROR, "Failed to copy public ephemeral from the header.");
	}

	//message counter from big endian
	buffer_create_with_existing_array(big_endian_message_counter, header->content + PUBLIC_KEY_SIZE, sizeof(uint32_t));
	status = endianness_uint32_from_big_endian(message_counter, big_endian_message_counter);
	throw_on_error(GENERIC_ERROR, "Failed to convert message counter back from big endian.");

	//previous message counter from big endian
	buffer_create_with_existing_array(big_endian_previous_message_counter, header->content + PUBLIC_KEY_SIZE + sizeof(uint32_t), sizeof(uint32_t));
	status = endianness_uint32_from_big_endian(previous_message_counter, big_endian_previous_message_counter);
	throw_on_error(GENERIC_ERROR, "Failed to convert previous message counter back from big endian.");

cleanup:
	if (status.status != SUCCESS) {
		if (their_public_ephemeral != NULL) {
			buffer_clear(their_public_ephemeral);
		}
	}

	return status;
}
