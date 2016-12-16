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

#include <alloca.h>
#include <stdbool.h>
#include <stdlib.h>

#ifndef LIB_BUFFER_H
#define LIB_BUFFER_H

typedef struct buffer_t {
	const size_t buffer_length;
	size_t content_length;
	/*This position can be used by parsers etc. to keep track of the position
	it is initialized with a value of 0.*/
	size_t position;
	bool readonly; //if set, this buffer shouldn't be written to.
	unsigned char * const content;
} buffer_t;

/*
 * Initialize a buffer with a given length.
 *
 * This is normally not called directly but via
 * the buffer_create macro.
 */
buffer_t* buffer_init(
		buffer_t * const buffer,
		const size_t buffer_length,
		const size_t content_length) __attribute__((warn_unused_result));

/*
 * initialize a buffer with a pointer to the character array.
 */
buffer_t* buffer_init_with_pointer(
		buffer_t * const buffer,
		unsigned char * const content,
		const size_t buffer_length,
		const size_t content_length);

/*
 * Macro to create a new buffer of a given length.
 */
#define buffer_create(buffer_length, content_length) buffer_init(alloca(sizeof(buffer_t) + buffer_length), buffer_length, content_length)

/*
 * Create a new buffer on the heap.
 */
buffer_t *buffer_create_on_heap(
		const size_t buffer_length,
		const size_t content_length) __attribute__((warn_unused_result));

/*
 * Create a new buffer with a custom allocator.
 */
buffer_t *buffer_create_with_custom_allocator(
		const size_t buffer_length,
		const size_t content_length,
		void *(*allocator)(size_t size),
		void (*deallocator)(void *pointer)
		) __attribute__((warn_unused_result));

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
		const size_t content_length) __attribute__((warn_unused_result));

/*
 * Create a new buffer from a string literal.
 */
#define buffer_create_from_string(name, string) buffer_t name[1]; buffer_init_with_pointer(name, (unsigned char*) (string), sizeof(string), sizeof(string)); name->readonly = true

/*
 * Create a new buffer from a string literal on heap.
 */
#define buffer_create_from_string_on_heap(string) buffer_create_from_string_helper(buffer_create_on_heap(sizeof(string), sizeof(string)), (unsigned char*) string, sizeof(string))

/*
 * Clear a buffer.
 *
 * Overwrites the buffer with zeroes and
 * resets the content size.
 */
void buffer_clear(buffer_t *buffer);

/*
 * Create hexadecimal string from a buffer.
 *
 * The output buffer has to be at least twice
 * as large as the input data plus one.
 */
int buffer_to_hex(buffer_t * const hex, const buffer_t * const data) __attribute__((warn_unused_result));

/*
 * Free and clear a heap allocated buffer.
 */
void buffer_destroy_from_heap(buffer_t *buffer);

/*
 * Destroy a buffer that was created using a custom allocator.
 */
void buffer_destroy_with_custom_deallocator(
		buffer_t * buffer,
		void (*deallocator)(void *pointer));

/*
 * Macro to create a buffer with already existing data without cloning it.
 */
#define buffer_create_with_existing_array(name, array, length) buffer_t name[1]; buffer_init_with_pointer(name, array, length, length)

/*
 * Concatenate a buffer to the first.
 *
 * Return 0 on success.
 */
int buffer_concat(
		buffer_t * const destination,
		const buffer_t * const source) __attribute__((warn_unused_result));

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
		const size_t copy_length) __attribute__((warn_unused_result));

/*
 * Copy the content of a buffer to the beginning of another
 * buffer and set the destinations content length to the
 * same length as the source.
 *
 * Returns 0 on success.
 */
int buffer_clone(
		buffer_t * const destination,
		const buffer_t * const source) __attribute__((warn_unused_result));

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
		const size_t copy_length) __attribute__((warn_unused_result));

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
		const size_t length) __attribute__((warn_unused_result));

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
		const size_t length) __attribute__((warn_unused_result));

/*
 * Write the contents of a buffer with hexadecimal digits to a buffer with
 * binary data.
 * The destination buffer size needs to be at least half the size of the input.
 */
int buffer_clone_from_hex(
		buffer_t * const destination,
		const buffer_t * const source) __attribute((warn_unused_result));

/*
 * Write the contents of a buffer into another buffer as hexadecimal digits.
 * Note that the destination buffer needs to be twice the size of the source buffers content.
 */
int buffer_clone_as_hex(
		buffer_t * const destination,
		const buffer_t * const source) __attribute((warn_unused_result));

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
		const size_t copy_length) __attribute__((warn_unused_result));

/*
 * Copy the entire content of a buffer
 * to a raw array.
 *
 * Returns 0 on success.
 */
int buffer_clone_to_raw(
		unsigned char * const destination,
		const size_t destination_length,
		const buffer_t *source) __attribute__((warn_unused_result));

/*
 * Compare two buffers.
 *
 * Returns 0 if both buffers match.
 */
int buffer_compare(
		const buffer_t * const buffer1,
		const buffer_t * const buffer2) __attribute__((warn_unused_result));

/*
 * Compare a buffer to a raw array.
 *
 * Returns 0 if both buffers match.
 */
int buffer_compare_to_raw(
		const buffer_t * const buffer,
		const unsigned char * const array,
		const size_t array_length) __attribute__((warn_unused_result));

/*
 * Macro to compare a buffer to a string.
 */
#define buffer_compare_to_string(buffer, string) buffer_compare_to_raw(buffer, (unsigned char*)string, sizeof(string))

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
		const size_t length) __attribute__((warn_unused_result));

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
		const size_t comparison_length);

/*
 * Fill a buffer with random numbers.
 */
int buffer_fill_random(
		buffer_t * const buffer,
		const size_t length) __attribute__((warn_unused_result));

/*
 * Xor a buffer onto another of the same length.
 */
int buffer_xor(
		buffer_t * const destination,
		const buffer_t * const source) __attribute__((warn_unused_result));

/*
 * Set a single character in a buffer.
 */
int buffer_set_at(
		const buffer_t * const buffer,
		const size_t pos,
		const unsigned char character) __attribute__((warn_unused_result));

/*
 * Set parts of a buffer to a given character.
 * ( sets the content length to the given length! )
 */
int buffer_memset_partial(
		buffer_t * const buffer,
		const unsigned char character,
		const size_t length) __attribute__((warn_unused_result));

/*
 * Set the entire buffer to a given character.
 * (content_length is used as the length, not buffer_length)
 */
void buffer_memset(
		buffer_t * const buffer,
		const unsigned char character);

/*
 * Grow a heap allocated buffer to a new length.
 *
 * Does nothing if the new size is smaller than the buffer.
 */
int buffer_grow_on_heap(
		buffer_t * buffer,
		const size_t new_size) __attribute__((warn_unused_result));

/*
 * Get the content of a buffer at buffer->position.
 *
 * Returns '\0' when out of bounds.
 */
unsigned char buffer_get_at_pos(const buffer_t * const buffer);

/*
 * Set a character at buffer->position.
 *
 * Returns 0 if not out of bounds.
 */
int buffer_set_at_pos(buffer_t * const buffer, const unsigned char character);

/*
 * Fill a buffer with a specified amount of a given value.
 *
 * Returns 0 on success
 */
int buffer_fill(buffer_t * const buffer, const unsigned char character, size_t length) __attribute__((warn_unused_result));
#endif
