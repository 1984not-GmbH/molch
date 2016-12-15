/*
 * Molch, an implementation of the axolotl ratchet based on libsodium
 *
 * ISC License
 *
 * Copyright (C) 2015-2016 Max Bruckner (FSMaxB) <max at maxbruckner dot de>
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

	buffer->position = 0;

	return buffer;
}

/*
 * Create a new buffer on the heap.
 */
buffer_t *buffer_create_on_heap(
		const size_t buffer_length,
		const size_t content_length) {
	buffer_t *buffer = malloc(sizeof(buffer_t));
	if (buffer == NULL) {
		return NULL;
	}

	unsigned char *content = NULL;
	if (buffer_length != 0) {
		content = malloc(buffer_length);
		if (content == NULL) {
			free(buffer);
			return NULL;
		}
	}

	return buffer_init_with_pointer(
			buffer,
			content,
			buffer_length,
			content_length);
}

/*
 * Create a new buffer with a custom allocator.
 */
buffer_t *buffer_create_with_custom_allocator(
		const size_t buffer_length,
		const size_t content_length,
		void *(*allocator)(size_t size),
		void (*deallocator)(void *pointer)
		) {
	unsigned char *content = NULL;
	if (buffer_length != 0) {
		content = allocator(buffer_length);
		if (content == NULL) {
			return NULL;
		}
	}

	buffer_t *buffer = allocator(sizeof(buffer_t));
	if (buffer == NULL) {
		deallocator(content);
		return NULL;
	}

	return buffer_init_with_pointer(buffer, content, buffer_length, content_length);
}

/*
 * Create hexadecimal string from a buffer.
 *
 * The output buffer has to be at least twice
 * as large as the input data plus one.
 */
int buffer_to_hex(buffer_t * const hex, const buffer_t * const data) {
	//check size
	if (hex->buffer_length < (data->content_length * 2 + 1)) {
		return -6;
	}

	if (sodium_bin2hex((char*)hex->content, hex->buffer_length, data->content, data->content_length) == NULL) {
		sodium_memzero(hex->content, hex->buffer_length);
		hex->content_length = 0;
		return -10;
	}

	hex->content_length = 2 * data->content_length + 1;
	return 0;
}

/*
 * Free and clear a heap allocated buffer.
 */
void buffer_destroy_from_heap(buffer_t * const buffer) {
	buffer_clear(buffer);
	free(buffer->content);
	free(buffer);
}

/*
 * Destroy a buffer that was created using a custom allocator.
 */
void buffer_destroy_with_custom_deallocator(
		buffer_t * buffer,
		void (*deallocator)(void *pointer)) {
	if (buffer == NULL) {
		return;
	}

	if (buffer->content != NULL) {
		sodium_memzero(buffer->content, buffer->content_length);
		deallocator(buffer->content);
	}
	deallocator(buffer);
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
	if ((buffer == NULL) || (buffer->buffer_length == 0)) {
		return;
	}
	sodium_memzero(buffer->content, buffer->buffer_length);
	buffer->content_length = 0;
	buffer->position = 0;
}

/*
 * Concatenate a buffer to the first.
 *
 * Return 0 on success.
 */
int buffer_concat(
		buffer_t * const destination,
		const buffer_t * const source) {
	if (destination->readonly) {
		return -5;
	}

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

	if (source->buffer_length == 0) {
		return 0;
	}

	if ((destination->content == NULL) || (source->content == NULL)) {
		return -11;
	}

	memcpy(destination->content + destination_offset, source->content + source_offset, copy_length);
	destination->content_length = (destination->content_length > destination_offset + copy_length)
		? destination->content_length
		: destination_offset + copy_length;

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
	if ((destination == NULL) || (source == NULL)) {
		return -1;
	}

	if (destination->readonly) {
		return -5;
	}

	if (destination->buffer_length < source->content_length) {
		return -6;
	}

	destination->content_length = source->content_length;

	int status = buffer_copy(
			destination,
			0,
			source,
			0,
			source->content_length);
	if (status != 0) {
		buffer_clear(destination);
		return status;
	}

	destination->position = source->position;

	return status;
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

	if ((destination->buffer_length < destination_offset) || (copy_length > (destination->buffer_length - destination_offset))) {
		//destination buffer isn't long enough
		return -6;
	}

	if (copy_length == 0) {
		return 0;
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
	if (destination->readonly) {
		return -5;
	}

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
 * Write the contents of a buffer with hexadecimal digits to a buffer with
 * binary data.
 * The destination buffer size needs to be at least half the size of the input.
 */
int buffer_clone_from_hex(
		buffer_t * const destination,
		const buffer_t * const source) {
	if ((destination == NULL) || (source == NULL)) {
		return -1;
	}

	if (destination->readonly) {
		return -5;
	}

	destination->content_length = 0;

	if (destination->buffer_length < (source->content_length / 2)) {
		return -6;
	}

	size_t length; //number of bytes written
	int status = sodium_hex2bin(
				destination->content, destination->buffer_length,
				(const char*) source->content, source->content_length,
				NULL,
				&length,
				NULL);
	if (status != 0) {
		buffer_clear(destination);
		return -7;
	}

	if (length != (source->content_length / 2)) {
		buffer_clear(destination);
		return -8;
	}

	destination->content_length = length;

	return 0;
}

/*
 * Write the contents of a buffer into another buffer as hexadecimal digits.
 * Note that the destination buffer needs to be twice the size of the source buffers content plus one.
 */
int buffer_clone_as_hex(
		buffer_t * const destination,
		const buffer_t * const source) {
	if ((destination == NULL) || (source == NULL)) {
		return -1;
	}

	if (destination->readonly) {
		return -5;
	}

	destination->content_length = 0;

	if (destination->buffer_length < (2 * source->content_length + 1)) {
		return -6;
	}

	if (sodium_bin2hex((char*)destination->content, destination->buffer_length, (const unsigned char*)source->content, source->content_length) == NULL) {
		buffer_clear(destination);
		return -7;
	}

	destination->content_length = 2 * source->content_length + 1;

	return 0;
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

	if (source->buffer_length == 0) {
		return 0;
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
	return buffer_compare_to_raw(buffer1, buffer2->content, buffer2->content_length);
}

/*
 * Compare a buffer to a raw array.
 *
 * Returns 0 if both buffers match.
 */
int buffer_compare_to_raw(
		const buffer_t * const buffer,
		const unsigned char * const array,
		const size_t array_length) {
	return buffer_compare_to_raw_partial(buffer, 0, array, array_length, 0, buffer->content_length);
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
	return buffer_compare_to_raw_partial(buffer1, position1, buffer2->content, buffer2->content_length, position2, length);
}

/*
 * Compare parts of a buffer to parts of a raw array.
 *
 * Returns 0 if both buffers match.
 */
int buffer_compare_to_raw_partial(
		const buffer_t * const buffer,
		const size_t position1,
		const unsigned char * const array,
		const size_t array_length,
		const size_t position2,
		const size_t comparison_length) {
	if (((buffer->content_length - position1) < comparison_length) || ((array_length - position2) < comparison_length)) {
		//FIXME: Does this introduce a timing sidechannel? This leaks the information that two buffers don't have the same length
		//buffers are too short
		return -6;
	}

	if ((buffer->buffer_length == 0) || (array_length == 0)) {
		if (comparison_length == 0) {
			return 0;
		} else {
			return -1;
		}
	}

	return sodium_memcmp(buffer->content + position1, array + position2, comparison_length);
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

	if (buffer->buffer_length == 0) {
		return 0;
	}

	buffer->content_length = length;
	randombytes_buf(buffer->content, length);

	return 0;
}

/*
 * Xor a buffer onto another of the same length.
 */
//FIXME: Make sure this doesn't introduce any sidechannels
int buffer_xor(
		buffer_t * const destination,
		const buffer_t * const source) {
	if (destination->readonly) {
		return -5;
	}

	if ((destination->content_length != source->content_length)
			|| (destination->buffer_length < destination->content_length)
			|| (source->buffer_length < source->content_length)) {
		return -6;
	}

	//xor source onto destination
	for (size_t i = 0; i < destination->content_length; i++) {
		destination->content[i] ^= source->content[i];
	}

	return 0;
}

/*
 * Set a single character in a buffer.
 */
int buffer_set_at(
		const buffer_t * const buffer,
		const size_t pos,
		const unsigned char character) {
	if (buffer->readonly) {
		return -5;
	}
	if (pos >= buffer->content_length) {
		return -6;
	}

	buffer->content[pos] = character;

	return 0;
}

/*
 * Set parts of a buffer to a given character.
 */
int buffer_memset_partial(
		buffer_t * const buffer,
		const unsigned char character,
		const size_t length) {
	if (buffer->readonly) {
		return -5;
	}

	if ((length == 0) || (buffer->buffer_length == 0)) {
		return 0;
	}

	if (length > buffer->buffer_length) {
		return -6;
	}

	if (character == 0x00) {
		sodium_memzero(buffer->content, length);
		buffer->content_length = length;
		return 0;
	}

	buffer->content_length = length;
	memset(buffer->content, character, buffer->content_length);

	return 0;
}

/*
 * Set the entire buffer to a given character.
 * (content_length is used as the length, not buffer_length)
 */
void buffer_memset(
		buffer_t * const buffer,
		const unsigned char character) {
	int status __attribute__((unused));
	status = buffer_memset_partial(buffer, character, buffer->content_length);
}

/*
 * Grow a heap allocated buffer to a new length.
 *
 * Does nothing if the new size is smaller than the buffer.
 */
int buffer_grow_on_heap(
		buffer_t * const buffer,
		const size_t new_size) {
	if (new_size <= buffer->buffer_length) {
		//nothing to do
		return 0;
	}

	//allocate new content
	unsigned char *content = malloc(new_size);
	if (content == NULL) {
		return -11;
	}

	//copy the content
	int status = buffer_copy_to_raw(content, 0, buffer, 0, buffer->content_length);
	if (status != 0) {
		sodium_memzero(content, buffer->content_length);
		free(content);
		return status;
	}

	//replace content pointer
	sodium_memzero(buffer->content, buffer->buffer_length);
	free(buffer->content);
	unsigned char **writable_content_pointer = (unsigned char**) &buffer->content;
	*writable_content_pointer = content;

	//update buffer length
	size_t *writable_buffer_length = (size_t*) &buffer->buffer_length;
	*writable_buffer_length = new_size;

	return 0;
}

/*
 * Get the content of a buffer at buffer->position.
 *
 * Returns '\0' when out of bounds.
 */
unsigned char buffer_get_at_pos(const buffer_t * const buffer) {
	if ((buffer->position > buffer->content_length) || (buffer->position > buffer->buffer_length)) {
		return '\0';
	}

	return buffer->content[buffer->position];
}

/*
 * Set a character at buffer->position.
 *
 * Returns 0 if not out of bounds.
 */
int buffer_set_at_pos(buffer_t * const buffer, const unsigned char character) {
	if ((buffer->position > buffer->buffer_length) || (buffer->position > buffer->content_length)) {
		return -6;
	}
	buffer->content[buffer->position] = character;
	return 0;
}

/*
 * Fill a buffer with a specified amount of a given value.
 *
 * Returns 0 on success
 */
int buffer_fill(buffer_t * const buffer, const unsigned char character, size_t length) {
	if ((buffer->readonly) || (length > buffer->buffer_length)) {
		return -1;
	}

	memset(buffer->content, character, length);
	buffer->content_length = length;

	return 0;
}
