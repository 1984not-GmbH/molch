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
#include <algorithm>

#include "buffer.h"

size_t Buffer::getBufferLength() {
	return this->buffer_length;
}

bool Buffer::isReadOnly() {
	return this->readonly;
}

/*
 * Initialize a molch buffer with a given length.
 *
 * This is normally not called directly but via
 * the molch_buffer_create macro.
 */
Buffer* Buffer::init(const size_t buffer_length_,
		const size_t content_length_) {
	return this->init_with_pointer(
			(unsigned char*) this + sizeof(Buffer), //address after Buffer struct
			buffer_length_,
			content_length_);
}

void Buffer::setReadOnly(bool readonly_) {
	this->readonly = readonly_;
}

/*
 * initialize a buffer with a pointer to the character array.
 */
Buffer* Buffer::init_with_pointer(
		unsigned char * const content_,
		const size_t buffer_length_,
		const size_t content_length_) {
	this->buffer_length = buffer_length_;

	this->content_length = (content_length_ > buffer_length_)
		? buffer_length_
		: content_length_;
	this->readonly = false;

	if (buffer_length_ == 0) {
		this->content = nullptr;
	} else {
		this->content = content_;
	}

	this->position = 0;

	return this;
}

Buffer* Buffer::init_with_pointer_to_const(
		const unsigned char * const content_,
		const size_t buffer_length_,
		const size_t content_length_) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
	Buffer *result = this->init_with_pointer((unsigned char*)content_, buffer_length_, content_length_);
#pragma GCC diagnostic pop
	if (result != nullptr) {
		result->readonly = true;
	}

	return result;
}


/*
 * Create a new buffer on the heap.
 */
Buffer *buffer_create_on_heap(
		const size_t buffer_length,
		const size_t content_length) {
	Buffer *buffer = (Buffer*)malloc(sizeof(Buffer));
	if (buffer == nullptr) {
		return nullptr;
	}

	unsigned char *content = nullptr;
	if (buffer_length != 0) {
		content = (unsigned char*)malloc(buffer_length);
		if (content == nullptr) {
			free(buffer);
			return nullptr;
		}
	}

	return buffer->init_with_pointer(content, buffer_length, content_length);
}

/*
 * Create a new buffer with a custom allocator.
 */
Buffer *buffer_create_with_custom_allocator(
		const size_t buffer_length,
		const size_t content_length,
		void *(*allocator)(size_t size),
		void (*deallocator)(void *pointer)
		) {
	unsigned char *content = nullptr;
	if (buffer_length != 0) {
		content = (unsigned char*)allocator(buffer_length);
		if (content == nullptr) {
			return nullptr;
		}
	}

	Buffer *buffer = (Buffer*)allocator(sizeof(Buffer));
	if (buffer == nullptr) {
		deallocator(content);
		return nullptr;
	}

	return buffer->init_with_pointer(content, buffer_length, content_length);
}

/*
 * Free and clear a heap allocated buffer.
 */
void Buffer::destroy_from_heap() {
	this->clear();
	free(this->content);
	free(this);
}

/*
 * Destroy a buffer that was created using a custom allocator.
 */
void Buffer::destroy_with_custom_deallocator(void (*deallocator)(void *pointer)) {
	if (this->content != nullptr) {
		sodium_memzero(this->content, this->content_length);
		deallocator(this->content);
	}
	deallocator(this);
}

Buffer* Buffer::create_from_string_on_heap_helper(
		const unsigned char * const content_,
		const size_t content_length_) {
	if (this->buffer_length < content_length_) {
		return nullptr;
	}

	if (buffer_clone_from_raw(this, content_, content_length_) != 0) {
		return nullptr;
	}

	return this;
}

/*
 * Clear a buffer.
 *
 * Overwrites the buffer with zeroes and
 * resets the content size.
 */
void Buffer::clear() {
	if (this->buffer_length == 0) {
		return;
	}
	sodium_memzero(this->content, this->buffer_length);
	this->content_length = 0;
	this->position = 0;
}

/*
 * Copy parts of a buffer to another buffer.
 *
 * Returns 0 on success.
 */
int buffer_copy(
		Buffer * const destination,
		const size_t destination_offset,
		Buffer * const source,
		const size_t source_offset,
		const size_t copy_length) {
	if (destination->isReadOnly()) {
		return -5;
	}

	if ((destination->getBufferLength() < destination->content_length) || (source->getBufferLength() < source->content_length)) {
		//the content length should never be longer than the buffer length
		return -7;
	}

	if ((destination_offset > destination->content_length) || (copy_length > (destination->getBufferLength() - destination_offset))) {
		//destination buffer isn't long enough
		return -6;
	}

	if ((source_offset > source->content_length) || (copy_length > (source->content_length - source_offset))) {
		//source buffer isn't long enough
		return -6;
	}

	if (source->getBufferLength() == 0) {
		return 0;
	}

	if ((destination->content == nullptr) || (source->content == nullptr)) {
		return -11;
	}

	std::copy(source->content + source_offset, source->content + source_offset + copy_length, destination->content + destination_offset);
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
		Buffer * const destination,
		Buffer * const source) {
	if ((destination == nullptr) || (source == nullptr)) {
		return -1;
	}

	if (destination->isReadOnly()) {
		return -5;
	}

	if (destination->getBufferLength() < source->content_length) {
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
		destination->clear();
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
		Buffer * const destination,
		const size_t destination_offset,
		const unsigned char * const source,
		const size_t source_offset,
		const size_t copy_length) {
	if (destination->isReadOnly()) {
		return -5;
	}

	if (destination->getBufferLength() < destination->content_length) {
		//the content length should never be longer than the buffer length
		return -7;
	}

	if ((destination->getBufferLength() < destination_offset) || (copy_length > (destination->getBufferLength() - destination_offset))) {
		//destination buffer isn't long enough
		return -6;
	}

	if (copy_length == 0) {
		return 0;
	}

	std::copy(source + source_offset, source + source_offset + copy_length, destination->content + destination_offset);
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
		Buffer * const destination,
		const unsigned char * const source,
		const size_t length) {
	if (destination->isReadOnly()) {
		return -5;
	}

	if (destination->getBufferLength() < length) {
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
		Buffer * const source,
		const size_t source_offset,
		const size_t copy_length) {
	if ((source_offset > source->content_length) || (copy_length > (source->content_length - source_offset))) {
		//source buffer isn't long enough
		return -6;
	}

	if (source->getBufferLength() < source->content_length) {
		//the content length should never be longer than the buffer length
		return -7;
	}

	if (source->getBufferLength() == 0) {
		return 0;
	}

	std::copy(source->content + source_offset, source->content + source_offset + copy_length, destination + destination_offset);

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
		Buffer *source) {
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
		Buffer * const buffer1,
		Buffer * const buffer2) {
	return buffer_compare_to_raw(buffer1, buffer2->content, buffer2->content_length);
}

/*
 * Compare a buffer to a raw array.
 *
 * Returns 0 if both buffers match.
 */
int buffer_compare_to_raw(
		Buffer * const buffer,
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
		Buffer * const buffer1,
		const size_t position1,
		Buffer * const buffer2,
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
		Buffer * const buffer,
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

	if ((buffer->getBufferLength() == 0) || (array_length == 0)) {
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
		Buffer * const buffer,
		const size_t length) {
	if (length > buffer->getBufferLength()) {
		return -6;
	}

	if (buffer->isReadOnly()) {
		return -5;
	}

	if (buffer->getBufferLength() == 0) {
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
		Buffer * const destination,
		Buffer * const source) {
	if (destination->isReadOnly()) {
		return -5;
	}

	if ((destination->content_length != source->content_length)
			|| (destination->getBufferLength() < destination->content_length)
			|| (source->getBufferLength() < source->content_length)) {
		return -6;
	}

	//xor source onto destination
	for (size_t i = 0; i < destination->content_length; i++) {
		destination->content[i] ^= source->content[i];
	}

	return 0;
}
