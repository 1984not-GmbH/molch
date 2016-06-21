/*  Molch, an implementation of the axolotl ratchet based on libsodium
 *  Copyright (C) 2015-2016 1984not Security GmbH
 *  Author: Max Bruckner (FSMaxB)
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

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include "return-status.h"
#include "../buffer/buffer.h"

#ifndef LIB_ENDIANNESS_H
#define LIB_ENDIANNESS_H

/*
 * Determine the current endianness at runtime.
 */
bool endianness_is_little_endian();

/*
 * Copy a 32 bit unsigned integer to a buffer in big endian format.
 */
return_status endianness_uint32_to_big_endian(
		uint32_t integer,
		buffer_t * const output) __attribute__((warn_unused_result));

/*
 * Get a 32 bit unsigned integer from a buffer in big endian format.
 */
return_status endianness_uint32_from_big_endian(
		uint32_t *integer,
		const buffer_t * const buffer) __attribute__((warn_unused_result));

/*
 * Copy a 32 bit signed integer to a buffer in big endian format.
 */
return_status endianness_int32_to_big_endian(
		int32_t integer,
		buffer_t * const output) __attribute__((warn_unused_result));

/*
 * Get a 32 bit signed integer from a buffer in big endian format.
 */
return_status endianness_int32_from_big_endian(
		int32_t *integer,
		const buffer_t * const buffer) __attribute__((warn_unused_result));

/*
 * Copy a 64 bit unsigned integer to a buffer in big endian format.
 */
return_status endianness_uint64_to_big_endian(
		uint64_t integer,
		buffer_t * const output) __attribute__((warn_unused_result));

/*
 * Get a 64 bit unsigned integer from a buffer in big endian format.
 */
return_status endianness_uint64_from_big_endian(
		uint64_t *integer,
		const buffer_t * const buffer) __attribute__((warn_unused_result));

/*
 * Copy a 64 bit unsigned integer to a buffer in big endian format.
 */
return_status endianness_int64_to_big_endian(
		int64_t integer,
		buffer_t * const output) __attribute__((warn_unused_result));

/*
 * Get a 64 bit signed integer from a buffer in big endian format.
 */
return_status endianness_int64_from_big_endian(
		int64_t *integer,
		const buffer_t * const buffer) __attribute__((warn_unused_result));

/*
 * Copy a time_t value to a 64 bit signed integer in a buffer in big endian format
 */
return_status endianness_time_to_big_endian(
		time_t time,
		buffer_t * const output) __attribute__((warn_unused_result));

/*
 * Get a time_t from a buffer in big endian format.
 */
return_status endianness_time_from_big_endian(
		time_t *time,
		const buffer_t * const buffer) __attribute__((warn_unused_result));

#endif
