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
int endianness_uint32_to_big_endian(
		uint32_t integer,
		buffer_t * const output) {
	if ((output == NULL) || (output->buffer_length < sizeof(uint32_t))) {
		return -1;
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
		return buffer_clone_from_raw(output, (unsigned char*) &integer, sizeof(int32_t));
	}

	return 0;
}

/*
 * Get a 32 bit unsigned integer from a buffer in big endian format.
 */
int endianness_uint32_from_big_endian(
		uint32_t *integer,
		const buffer_t * const buffer) {
	if ((integer == NULL) || (buffer == NULL) || (buffer->content_length != sizeof(uint32_t))) {
		return -1;
	}

	if (endianness_is_little_endian()) {
		unsigned char *pointer = (unsigned char*) integer;
		pointer[0] = buffer->content[3];
		pointer[1] = buffer->content[2];
		pointer[2] = buffer->content[1];
		pointer[3] = buffer->content[0];
	} else {
		//if already big endian, just copy
		return buffer_clone_to_raw((unsigned char*) integer, sizeof(uint32_t), buffer);
	}

	return 0;
}

/*
 * Copy a 32 bit signed integer to a buffer in big endian format.
 */
int endianness_int32_to_big_endian(
		int32_t integer,
		buffer_t * const output) {
	return endianness_uint32_to_big_endian(*((uint32_t*)&integer), output);
}

/*
 * Get a 32 bit signed integer from a buffer in big endian format.
 */
int endianness_int32_from_big_endian(
		int32_t *integer,
		const buffer_t * const buffer) {
	return endianness_uint32_from_big_endian((uint32_t*) integer, buffer);
}

/*
 * Copy a 64 bit unsigned integer to a buffer in big endian format.
 */
int endianness_uint64_to_big_endian(
		uint64_t integer,
		buffer_t * const output) {
	if ((output == NULL) || (output->buffer_length < sizeof(uint64_t))) {
		return -1;
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
		return buffer_clone_from_raw(output, (unsigned char*) &integer, sizeof(uint64_t));
	}

	return 0;
}

/*
 * Get a 64 bit unsigned integer from a buffer in big endian format.
 */
int endianness_uint64_from_big_endian(
		uint64_t *integer,
		const buffer_t * const buffer) {
	if ((integer == NULL) || (buffer == NULL) || (buffer->content_length != sizeof(uint64_t))) {
		return -1;
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
		return buffer_clone_to_raw((unsigned char*) integer, sizeof(uint64_t), buffer);
	}

	return 0;
}

/*
 * Copy a 64 bit unsigned integer to a buffer in big endian format.
 */
int endianness_int64_to_big_endian(
		int64_t integer,
		buffer_t * const output) {
	return endianness_uint64_to_big_endian(*((uint64_t*)&integer), output);
}

/*
 * Get a 64 bit signed integer from a buffer in big endian format.
 */
int endianness_int64_from_big_endian(
		int64_t *integer,
		const buffer_t * const buffer) {
	return endianness_uint64_from_big_endian((uint64_t*)integer, buffer);
}

/*
 * Copy a time_t value to a 64 bit signed integer in a buffer in big endian format
 */
int endianness_time_to_big_endian(
		time_t time,
		buffer_t * const output) {

	int64_t timestamp = (int64_t) time;
	return endianness_int64_to_big_endian(timestamp, output);
}

/*
 * Get a time_t from a buffer in big endian format.
 */
int endianness_time_from_big_endian(
		time_t *time,
		const buffer_t * const buffer) {
	int64_t timestamp;
	int status = endianness_int64_from_big_endian(&timestamp, buffer);
	if (status != 0) {
		return status;
	}

	*time = (time_t) timestamp;

	return 0;
}
