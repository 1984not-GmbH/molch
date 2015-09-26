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
	return buffer_init_with_pointer(
			buffer,
			(unsigned char*) buffer + sizeof(buffer_t), //address after buffer_t struct
			buffer_length,
			content_length);
}

/*
 * initialize a buffer with a pointer to the character array.
 */
buffer_t* buffer_init_with_pointer(
		buffer_t * const buffer,
		unsigned char * const content,
		const size_t buffer_length,
		const size_t content_length) {
	//write to constant buffer length value (HACK)
	//This allows restricting access to the buffer length
	//while still being able to set it here
	 size_t *writable_buffer_length = (size_t*) &(buffer->buffer_length);
	*writable_buffer_length = buffer_length;

	buffer->content_length = (content_length > buffer_length)
		? buffer_length
		: content_length;
	buffer->readonly = false;

	//write to constant content pointer (HACK)
	//This allows restricting access to the pointer
	//while still being able to set it here
	unsigned char **writable_content_pointer = (unsigned char**) &buffer->content;
	if (buffer_length == 0) {
		*writable_content_pointer = NULL;
	} else {
		*writable_content_pointer = content;
	}

	return buffer;
}

/*
 * Copy a raw array to a buffer and return the
 * buffer.
 *
 * This should not be used directly, it is intended for the use
 * with the macro buffer_create_from_string.
 *
 * Returns NULL on error.
 */
buffer_t* buffer_create_from_string_helper(
		buffer_t * const buffer,
		const unsigned char * const content,
		const size_t content_length) {
	if (buffer->buffer_length < content_length) {
		return NULL;
	}

	if (buffer_clone_from_raw(buffer, content, content_length) != 0) {
		return NULL;
	}

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
		const buffer_t * const source) {
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

/*
 * Copy the content of a buffer to the beginning of another
 * buffer and set the destinations content length to the
 * same length as the source.
 *
 * Returns 0 on success.
 */
int buffer_clone(
		buffer_t * const destination,
		const buffer_t * const source) {
	if (destination->buffer_length < source->content_length) {
		return -6;
	}

	destination->content_length = source->content_length;

	return buffer_copy(
			destination,
			0,
			source,
			0,
			source->content_length);
}

/*
 * Copy from a raw array to a buffer.
 *
 * Returns 0 on success.
 */
int buffer_copy_from_raw(
		buffer_t * const destination,
		const size_t destination_offset,
		const unsigned char * const source,
		const size_t source_offset,
		const size_t copy_length) {
	if (destination->readonly) {
		return -5;
	}

	if (destination->buffer_length < destination->content_length) {
		//the content length should never be longer than the buffer length
		return -7;
	}

	if ((destination->content_length < destination_offset) || (copy_length > (destination->buffer_length - destination_offset))) {
		//destination buffer isn't long enough
		return -6;
	}

	memcpy(destination->content + destination_offset, source + source_offset, copy_length);
	destination->content_length = (destination->content_length > destination_offset + copy_length)
		? destination->content_length
		: destination_offset + copy_length;

	return 0;
}

/*
 * Copy the content of a raw array to the
 * beginning of a buffer, setting the buffers
 * content length to the length that was copied.
 *
 * Returns 0 on success.
 */
int buffer_clone_from_raw(
		buffer_t * const destination,
		const unsigned char * const source,
		const size_t length) {
	if (destination->buffer_length < length) {
		return -6;
	}

	destination->content_length = length;

	return buffer_copy_from_raw(
			destination,
			0,
			source,
			0,
			length);
}

/*
 * Copy from a buffer to a raw array.
 *
 * Returns 0 on success.
 */
int buffer_copy_to_raw(
		unsigned char * const destination,
		const size_t destination_offset,
		const buffer_t * const source,
		const size_t source_offset,
		const size_t copy_length) {
	if ((source_offset > source->content_length) || (copy_length > (source->content_length - source_offset))) {
		//source buffer isn't long enough
		return -6;
	}

	if (source->buffer_length < source->content_length) {
		//the content length should never be longer than the buffer length
		return -7;
	}

	memcpy(destination + destination_offset, source->content + source_offset, copy_length);

	return 0;
}

/*
 * Copy the entire content of a buffer
 * to a raw array.
 *
 * Returns 0 on success.
 */
int buffer_clone_to_raw(
		unsigned char * const destination,
		const size_t destination_length,
		const buffer_t *source) {
	if (destination_length < source->content_length) {
		return -6;
	}

	return buffer_copy_to_raw(
			destination,
			0,
			source,
			0,
			source->content_length);
}

/*
 * Compare two buffers.
 *
 * Returns 0 if both buffers match.
 */
int buffer_compare(
		const buffer_t * const buffer1,
		const buffer_t * const buffer2) {
	if (buffer1->content_length != buffer2->content_length) {
		//FIXME: Does this introduce a sidechannel? This can leak the information that
		//the size of two buffers doesn't match.
		return -1;
	}

	return sodium_memcmp(buffer1->content, buffer2->content, buffer1->content_length);
}

/*
 * Compare parts of two buffers.
 *
 * Returns 0 if both buffers match.
 */
int buffer_compare_partial(
		const buffer_t * const buffer1,
		const size_t position1,
		const buffer_t * const buffer2,
		const size_t position2,
		const size_t length) {
	if (((buffer1->content_length + position1) < length) || ((buffer2->content_length + position2) < length)) {
		//buffers don't match the length of the comparison
		return -6;
	}

	return sodium_memcmp(buffer1->content + position1, buffer2->content + position2, length);
}

/*
 * Fill a buffer with random numbers.
 */
int buffer_fill_random(
		buffer_t * const buffer,
		const size_t length) {
	if (length > buffer->buffer_length) {
		return -6;
	}

	if (buffer->readonly) {
		return -5;
	}

	buffer->content_length = length;
	randombytes_buf(buffer->content, length);

	return 0;
}
