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

/*
 * Functions to convert different types of numbers to big endian (networ byte order) for
 * packet creation.
 */

#include "endianness.h"

/*
 * Determine the current endianness at runtime.
 */
bool endianness_is_little_endian() {
	uint16_t number = 0x1;
	unsigned char *number_pointer = (unsigned char*) &number;
	return (number_pointer[0] == 0x1);
}

/*
 * Copy a 32 bit unsigned integer to a buffer in big endian format.
 */
return_status endianness_uint32_to_big_endian(
		uint32_t integer,
		Buffer * const output) {
	return_status status = return_status_init();

	if ((output == nullptr) || (output->getBufferLength() < sizeof(uint32_t))) {
		THROW(INVALID_INPUT, "Invalid input to endianness_uint32_to_big_endian.");
	}

	if (endianness_is_little_endian()) {
		output->content_length = 4;
		unsigned char *pointer = (unsigned char*) &integer;
		output->content[0] = pointer[3];
		output->content[1] = pointer[2];
		output->content[2] = pointer[1];
		output->content[3] = pointer[0];
	} else {
		//if already big endian, just copy
		if (buffer_clone_from_raw(output, (unsigned char*) &integer, sizeof(int32_t)) != 0) {
			THROW(BUFFER_ERROR, "Failed to copy number.");
		}
	}

cleanup:
	return status;
}

/*
 * Get a 32 bit unsigned integer from a buffer in big endian format.
 */
return_status endianness_uint32_from_big_endian(
		uint32_t *integer,
		Buffer * const buffer) {
	return_status status = return_status_init();

	if ((integer == nullptr) || (buffer == nullptr) || (buffer->content_length != sizeof(uint32_t))) {
		THROW(INVALID_INPUT, "Invalid input to endianness_uint32_from_big_endian.");
	}

	if (endianness_is_little_endian()) {
		unsigned char *pointer = (unsigned char*) integer;
		pointer[0] = buffer->content[3];
		pointer[1] = buffer->content[2];
		pointer[2] = buffer->content[1];
		pointer[3] = buffer->content[0];
	} else {
		//if already big endian, just copy
		if (buffer_clone_to_raw((unsigned char*) integer, sizeof(uint32_t), buffer) != 0) {
			THROW(BUFFER_ERROR, "Failed to copy number.");
		}
	}

cleanup:
	return status;
}

/*
 * Copy a 32 bit signed integer to a buffer in big endian format.
 */
return_status endianness_int32_to_big_endian(
		int32_t integer,
		Buffer * const output) {
	return endianness_uint32_to_big_endian(*((uint32_t*)&integer), output);
}

/*
 * Get a 32 bit signed integer from a buffer in big endian format.
 */
return_status endianness_int32_from_big_endian(
		int32_t *integer,
		Buffer * const buffer) {
	return endianness_uint32_from_big_endian((uint32_t*) integer, buffer);
}

/*
 * Copy a 64 bit unsigned integer to a buffer in big endian format.
 */
return_status endianness_uint64_to_big_endian(
		uint64_t integer,
		Buffer * const output) {
	return_status status = return_status_init();

	if ((output == nullptr) || (output->getBufferLength() < sizeof(uint64_t))) {
		THROW(INVALID_INPUT, "Invalid input to endianness_uint64_to_big_endian.");
	}

	if (endianness_is_little_endian()) {
		output->content_length = 8;
		unsigned char *pointer = (unsigned char*) &integer;
		output->content[0] = pointer[7];
		output->content[1] = pointer[6];
		output->content[2] = pointer[5];
		output->content[3] = pointer[4];
		output->content[4] = pointer[3];
		output->content[5] = pointer[2];
		output->content[6] = pointer[1];
		output->content[7] = pointer[0];
	} else {
		//if already big endian, just copy
		if (buffer_clone_from_raw(output, (unsigned char*) &integer, sizeof(uint64_t)) != 0) {
			THROW(BUFFER_ERROR, "Failed to copy number.");
		}
	}

cleanup:
	return status;
}

/*
 * Get a 64 bit unsigned integer from a buffer in big endian format.
 */
return_status endianness_uint64_from_big_endian(
		uint64_t *integer,
		Buffer * const buffer) {
	return_status status = return_status_init();

	if ((integer == nullptr) || (buffer == nullptr) || (buffer->content_length != sizeof(uint64_t))) {
		THROW(INVALID_INPUT, "Invalid input to endianness_uint64_from_big_endian.");
	}

	if (endianness_is_little_endian()) {
		unsigned char *pointer = (unsigned char*) integer;
		pointer[0] = buffer->content[7];
		pointer[1] = buffer->content[6];
		pointer[2] = buffer->content[5];
		pointer[3] = buffer->content[4];
		pointer[4] = buffer->content[3];
		pointer[5] = buffer->content[2];
		pointer[6] = buffer->content[1];
		pointer[7] = buffer->content[0];
	} else {
		//if already big endian, just copy
		if (buffer_clone_to_raw((unsigned char*) integer, sizeof(uint64_t), buffer) != 0) {
			THROW(BUFFER_ERROR, "Failed to copy number.");
		}
	}

cleanup:
	return status;
}

/*
 * Copy a 64 bit unsigned integer to a buffer in big endian format.
 */
return_status endianness_int64_to_big_endian(
		int64_t integer,
		Buffer * const output) {
	return endianness_uint64_to_big_endian(*((uint64_t*)&integer), output);
}

/*
 * Get a 64 bit signed integer from a buffer in big endian format.
 */
return_status endianness_int64_from_big_endian(
		int64_t *integer,
		Buffer * const buffer) {
	return endianness_uint64_from_big_endian((uint64_t*)integer, buffer);
}

/*
 * Copy a time_t value to a 64 bit signed integer in a buffer in big endian format
 */
return_status endianness_time_to_big_endian(
		time_t time,
		Buffer * const output) {

	int64_t timestamp = (int64_t) time;
	return endianness_int64_to_big_endian(timestamp, output);
}

/*
 * Get a time_t from a buffer in big endian format.
 */
return_status endianness_time_from_big_endian(
		time_t *time,
		Buffer * const buffer) {
	return_status status = return_status_init();

	int64_t timestamp = 0;
	status = endianness_int64_from_big_endian(&timestamp, buffer);
	THROW_on_error(CONVERSION_ERROR, "Failed to convert int64 from big endian.");

	*time = (time_t) timestamp;

cleanup:
	return status;
}
