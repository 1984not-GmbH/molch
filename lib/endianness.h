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
