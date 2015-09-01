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

#include "buffer.h"

/*
 * Initialize a molch buffer with a given length.
 *
 * This is normally not called directly but via
 * the molch_buffer_create macro.
 */
buffer_t* buffer_init(
		buffer_t * const buffer,
		const size_t buffer_length,
		const size_t content_length) {
	buffer->buffer_length = buffer_length;
	buffer->content_length = (content_length > buffer_length)
		? buffer_length
		: content_length;
	buffer->readonly = false;
	buffer->content = (unsigned char*) buffer + sizeof(buffer_t);
	return buffer;
}

/*
 * Clear a buffer.
 *
 * Overwrites the buffer with zeroes and
 * resets the content size.
 */
void buffer_clear(buffer_t *buffer) {
	sodium_memzero(buffer->content, buffer->buffer_length);
	buffer->content_length = 0;
}

/*
 * Concatenate a buffer to the first.
 *
 * Return 0 on success.
 */
int buffer_concat(
		buffer_t * const destination,
		buffer_t * const source) {
	return buffer_copy(
			destination,
			destination->content_length,
			source,
			0,
			source->content_length);
}

/*
 * Copy parts of a buffer to another buffer.
 *
 * Returns 0 on success.
 */
int buffer_copy(
		buffer_t * const destination,
		const size_t destination_offset,
		const buffer_t * const source,
		const size_t source_offset,
		const size_t copy_length) {
	if (destination->readonly) {
		return -5;
	}

	if ((destination->buffer_length < destination->content_length) || (source->buffer_length < source->content_length)) {
		//the content length should never be longer than the buffer length
		return -7;
	}

	if ((destination_offset > destination->content_length) || (copy_length > (destination->buffer_length - destination_offset))) {
		//destination buffer isn't long enough
		return -6;
	}

	if ((source_offset > source->content_length) || (copy_length > (source->content_length - source_offset))) {
		//source buffer isn't long enough
		return -6;
	}

	memcpy(destination->content + destination_offset, source->content + source_offset, copy_length);
	destination->content_length = (destination->content_length > destination_offset + copy_length)
		? destination->content_length
		: destination_offset + copy_length;
	destination->content_length = destination_offset + copy_length;
	return 0;
}
