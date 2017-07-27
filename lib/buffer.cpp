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

Buffer::Buffer() noexcept {
	this->buffer_length = 0;
	this->manage_memory = false;
	this->readonly = false;
	this->is_valid = false;
	this->deallocator = nullptr;
	this->content_length = 0;
	this->content = nullptr;
}

Buffer::Buffer(const std::string& string) noexcept {
	this->buffer_length = string.length() + sizeof("");
	this->content_length = string.length() + sizeof("");
	this->readonly = false;
	this->manage_memory = true;
	this->is_valid = true;
	this->deallocator = nullptr;

	try {
		this->content = new unsigned char[string.length() + sizeof("")];
	} catch (...) {
		this->buffer_length = 0;
		this->content_length = 0;
		this->content = nullptr;
		this->is_valid = false;
		return;
	}

	std::copy(string.begin(), string.end(), this->content);
	this->content[string.length()] = '\0';
}

Buffer::Buffer(const size_t buffer_length, const size_t content_length) noexcept {
	this->buffer_length = buffer_length;
	this->content_length = content_length;
	this->readonly = false;
	this->manage_memory = true;
	this->is_valid = true;
	this->deallocator = nullptr;

	if (buffer_length == 0) {
		this->content = nullptr;
	} else {
		try {
			this->content = new unsigned char[buffer_length];
		} catch (...) {
			this->buffer_length = 0;
			this->content_length = 0;
			this->content = nullptr;
			this->is_valid = false;
			return;
		}
	}
}

Buffer::Buffer(const size_t buffer_length, const size_t content_length, void* (*allocator)(size_t), void (*deallocator)(void*)) noexcept {
	this->buffer_length = buffer_length;
	this->content_length = content_length;
	this->readonly = false;
	this->manage_memory = true;
	this->is_valid = true;
	this->deallocator = deallocator;

	if (buffer_length == 0) {
		this->content = nullptr;
	} else {
		this->content = (unsigned char*)allocator(buffer_length);
		if (this->content == nullptr) {
			this->buffer_length = 0;
			this->content_length = 0;
			this->is_valid = false;
		}
	}
}

Buffer::Buffer(unsigned char * const content, const size_t buffer_length) noexcept {
	this->init(content, buffer_length, buffer_length);
}

Buffer::Buffer(const unsigned char * const content, const size_t buffer_length) noexcept {
	this->initWithConst(content, buffer_length, buffer_length);
}

Buffer::~Buffer() noexcept {
	//only do something if this was created using a constructor
	if (this->manage_memory) {
		this->clear();
		if ((this->deallocator != nullptr) && (this->content != nullptr)) {
			deallocator(this->content);
			return;
		}

		delete[] this->content;
	}
}

Buffer& Buffer::operator=(Buffer&& buffer) noexcept {
	//copy the buffer
	unsigned char& source_reference = reinterpret_cast<unsigned char&>(buffer);
	unsigned char& destination_reference = reinterpret_cast<unsigned char&>(*this);
	std::copy(&source_reference, &source_reference + sizeof(Buffer), &destination_reference);

	//steal resources from the source buffer
	buffer.buffer_length = 0;
	buffer.manage_memory = false;
	buffer.readonly = false;
	buffer.is_valid = false;
	buffer.deallocator = nullptr;
	buffer.content_length = 0;
	buffer.content = nullptr;

	return *this;
}

size_t Buffer::getBufferLength() const noexcept {
	return this->buffer_length;
}

bool Buffer::isReadOnly() const noexcept {
	return this->readonly;
}

void Buffer::setReadOnly(bool readonly_) noexcept {
	this->readonly = readonly_;
}

/*
 * initialize a buffer with a pointer to the character array.
 */
Buffer* Buffer::init(
		unsigned char * const content_,
		const size_t buffer_length_,
		const size_t content_length_) noexcept {
	this->buffer_length = buffer_length_;
	this->manage_memory = false;
	this->is_valid = true;
	this->deallocator = nullptr;

	this->content_length = (content_length_ > buffer_length_)
		? buffer_length_
		: content_length_;
	this->readonly = false;

	if (buffer_length_ == 0) {
		this->content = nullptr;
	} else {
		this->content = content_;
	}

	return this;
}

Buffer* Buffer::initWithConst(
		const unsigned char * const content_,
		const size_t buffer_length_,
		const size_t content_length_) noexcept {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
	Buffer *result = this->init((unsigned char*)content_, buffer_length_, content_length_);
#pragma GCC diagnostic pop
	if (result != nullptr) {
		result->readonly = true;
	}

	return result;
}


/*
 * Create a new buffer on the heap.
 */
Buffer* Buffer::create(
		const size_t buffer_length,
		const size_t content_length) noexcept {
	return Buffer::createWithCustomAllocator(buffer_length, content_length, &malloc, &free);
}

/*
 * Create a new buffer with a custom allocator.
 */
Buffer* Buffer::createWithCustomAllocator(
		const size_t buffer_length,
		const size_t content_length,
		void *(*allocator)(size_t size),
		void (*deallocator)(void *pointer)
		) noexcept {
	Buffer *buffer = (Buffer*)allocator(sizeof(Buffer));
	if (buffer == nullptr) {
		return nullptr;
	}

	unsigned char *content = nullptr;
	if (buffer_length != 0) {
		content = (unsigned char*)allocator(buffer_length);
		if (content == nullptr) {
			deallocator(buffer);
			return nullptr;
		}
	}

	buffer->init(content, buffer_length, content_length);
	buffer->deallocator = deallocator;

	return buffer;
}

void Buffer::destroy() noexcept {
	this->clear();
	if (this->content != nullptr) {
		this->deallocator(this->content);
	}
	this->deallocator(this);
}

/*
 * Clear a buffer.
 *
 * Overwrites the buffer with zeroes and
 * resets the content size.
 */
void Buffer::clear() noexcept {
	if (this->buffer_length == 0) {
		return;
	}
	sodium_memzero(this->content, this->buffer_length);
	this->content_length = 0;
}

/*
 * Copy parts of a buffer to another buffer.
 *
 * Returns 0 on success.
 */
int Buffer::copyFrom(
		const size_t destination_offset,
		const Buffer * const source,
		const size_t source_offset,
		const size_t copy_length) noexcept {
	if (this->readonly) {
		return -5;
	}

	if ((this->buffer_length < this->content_length) || (source->buffer_length < source->content_length)) {
		//the content length should never be longer than the buffer length
		return -7;
	}

	if ((destination_offset > this->content_length) || (copy_length > (this->buffer_length - destination_offset))) {
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

	if ((this->content == nullptr) || (source->content == nullptr)) {
		return -11;
	}

	std::copy(source->content + source_offset, source->content + source_offset + copy_length, this->content + destination_offset);
	this->content_length = (this->content_length > destination_offset + copy_length)
		? this->content_length
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
int Buffer::cloneFrom(const Buffer * const source) noexcept {
	if (source == nullptr) {
		return -1;
	}

	if (this->readonly) {
		return -5;
	}

	if (this->buffer_length < source->content_length) {
		return -6;
	}

	this->content_length = source->content_length;

	int status = this->copyFrom(0, source, 0, source->content_length);
	if (status != 0) {
		this->clear();
		return status;
	}

	return status;
}

/*
 * Copy from a raw array to a buffer.
 *
 * Returns 0 on success.
 */
int Buffer::copyFromRaw(
		const size_t destination_offset,
		const unsigned char * const source,
		const size_t source_offset,
		const size_t copy_length) noexcept {
	if (this->readonly) {
		return -5;
	}

	if (this->buffer_length < this->content_length) {
		//the content length should never be longer than the buffer length
		return -7;
	}

	if ((this->buffer_length < destination_offset) || (copy_length > (this->buffer_length - destination_offset))) {
		//destination buffer isn't long enough
		return -6;
	}

	if (copy_length == 0) {
		return 0;
	}

	std::copy(source + source_offset, source + source_offset + copy_length, this->content + destination_offset);
	this->content_length = (this->content_length > destination_offset + copy_length)
		? this->content_length
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
int Buffer::cloneFromRaw(const unsigned char * const source, const size_t length) noexcept {
	if (this->readonly) {
		return -5;
	}

	if (this->buffer_length < length) {
		return -6;
	}

	this->content_length = length;

	return this->copyFromRaw(0, source, 0, length);
}

/*
 * Copy from a buffer to a raw array.
 *
 * Returns 0 on success.
 */
int Buffer::copyToRaw(
		unsigned char * const destination,
		const size_t destination_offset,
		const size_t source_offset,
		const size_t copy_length) noexcept {
	if ((source_offset > this->content_length) || (copy_length > (this->content_length - source_offset))) {
		//source buffer isn't long enough
		return -6;
	}

	if (this->buffer_length < this->content_length) {
		//the content length should never be longer than the buffer length
		return -7;
	}

	if (this->buffer_length == 0) {
		return 0;
	}

	std::copy(this->content + source_offset, this->content + source_offset + copy_length, destination + destination_offset);

	return 0;
}

/*
 * Copy the entire content of a buffer
 * to a raw array.
 *
 * Returns 0 on success.
 */
int Buffer::cloneToRaw(unsigned char * const destination, const size_t destination_length) noexcept {
	if (destination_length < this->content_length) {
		return -6;
	}

	return this->copyToRaw(destination, 0, 0, this->content_length);
}

/*
 * Compare two buffers.
 *
 * Returns 0 if both buffers match.
 */
int Buffer::compare(const Buffer * const buffer) const noexcept {
	return this->compareToRaw(buffer->content, buffer->content_length);
}

/*
 * Compare a buffer to a raw array.
 *
 * Returns 0 if both buffers match.
 */
int Buffer::compareToRaw(const unsigned char * const array, const size_t array_length) const noexcept {
	return this->compareToRawPartial(0, array, array_length, 0, this->content_length);
}

/*
 * Compare parts of two buffers.
 *
 * Returns 0 if both buffers match.
 */
int Buffer::comparePartial(
		const size_t position1,
		Buffer * const buffer2,
		const size_t position2,
		const size_t length) const noexcept {
	return this->compareToRawPartial(position1, buffer2->content, buffer2->content_length, position2, length);
}

/*
 * Compare parts of a buffer to parts of a raw array.
 *
 * Returns 0 if both buffers match.
 */
int Buffer::compareToRawPartial(
		const size_t position1,
		const unsigned char * const array,
		const size_t array_length,
		const size_t position2,
		const size_t comparison_length) const noexcept {
	if (((this->content_length - position1) < comparison_length) || ((array_length - position2) < comparison_length)) {
		//FIXME: Does this introduce a timing sidechannel? This leaks the information that two buffers don't have the same length
		//buffers are too short
		return -6;
	}

	if ((this->buffer_length == 0) || (array_length == 0)) {
		if (comparison_length == 0) {
			return 0;
		} else {
			return -1;
		}
	}

	return sodium_memcmp(this->content + position1, array + position2, comparison_length);
}

/*
 * Fill a buffer with random numbers.
 */
int Buffer::fillRandom(const size_t length) noexcept {
	if (length > this->buffer_length) {
		return -6;
	}

	if (this->readonly) {
		return -5;
	}

	if (this->buffer_length == 0) {
		return 0;
	}

	this->content_length = length;
	randombytes_buf(this->content, length);

	return 0;
}

//FIXME: Make sure this doesn't introduce any sidechannels
int Buffer::xorWith(Buffer * const source) noexcept {
	if (this->readonly) {
		return -5;
	}

	if ((this->content_length != source->content_length)
			|| (this->buffer_length < this->content_length)
			|| (source->buffer_length < source->content_length)) {
		return -6;
	}

	//xor source onto destination
	for (size_t i = 0; i < this->content_length; i++) {
		this->content[i] ^= source->content[i];
	}

	return 0;
}

/*
 * Helper function that checks if a buffer is <none>
 * (filled with zeroes), and does so without introducing
 * side channels, especially timing side channels.
 */
bool Buffer::isNone() const noexcept {
	return (this->content_length == 0) || sodium_is_zero(this->content, this->content_length);
}

bool Buffer::isValid() const noexcept {
	return this->is_valid;
}

bool Buffer::operator ==(const Buffer& buffer) const noexcept {
	return this->compare(&buffer) == 0;
}

bool Buffer::operator !=(const Buffer& buffer) const noexcept {
	return !(*this == buffer);
}

bool Buffer::fits(const size_t size) const noexcept {
	return this->buffer_length >= size;
}

bool Buffer::contains(const size_t size) const noexcept {
	return this->fits(size) && (this->content_length == size);
}
