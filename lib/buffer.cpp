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
#include <memory>
#include <iterator>
#include <exception>

#include "buffer.hpp"
#include "molch-exception.hpp"

namespace Molch {
	Buffer::Buffer(const std::string& string) :
			buffer_length{string.length() + sizeof("")},
			size{string.length() + sizeof("")},
			content{new unsigned char[string.length() + sizeof("")]} {
		std::copy(std::begin(string), std::end(string), this->content);
		this->content[string.length()] = '\0';
	}

	Buffer::Buffer(const size_t capacity, const size_t size) :
			buffer_length{capacity},
			size{size} {
		if (capacity == 0) {
			this->content = nullptr;
		} else {
			this->content = new unsigned char[capacity];
		}
	}

	Buffer::Buffer(const size_t capacity, const size_t size, void* (*allocator)(size_t), void (*deallocator)(void*)) :
			buffer_length{capacity},
			deallocator{deallocator},
			size{size} {
		if (capacity == 0) {
			this->content = nullptr;
		} else {
			this->content = reinterpret_cast<unsigned char*>(allocator(capacity));
			if (this->content == nullptr) {
				this->buffer_length = 0;
				this->size = 0;

				throw std::bad_alloc{};
			}
		}
	}

	Buffer::Buffer(unsigned char * const content, const size_t capacity, const size_t size) :
			buffer_length{capacity},
			manage_memory{false},
			readonly{false} {
		this->size = (size > capacity)
			? capacity
			: size;

		if (capacity == 0) {
			this->content = nullptr;
		} else {
			this->content = content;
		}
	}
	Buffer::Buffer(unsigned char * const content, const size_t capacity) :
		Buffer{content, capacity, capacity} {}

	Buffer::Buffer(const unsigned char * const content, const size_t capacity, const size_t size) :
			Buffer{const_cast<unsigned char*>(content), capacity, size} {
		this->readonly = false;
	}
	Buffer::Buffer(const unsigned char * const content, const size_t capacity)
		: Buffer{content, capacity, capacity} {}

	void Buffer::destruct() {
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

	Buffer::~Buffer() {
		this->destruct();
	}

	Buffer& Buffer::copy(const Buffer& buffer) {
		this->destruct();

		this->buffer_length = buffer.buffer_length;
		this->manage_memory = true;
		this->readonly = buffer.readonly;
		this->deallocator = nullptr;
		this->size = buffer.size;

		this->content = new unsigned char[buffer.buffer_length];
		std::copy(buffer.content, buffer.content + buffer.size, this->content);

		return *this;
	}

	Buffer& Buffer::move(Buffer&& buffer) {
		this->destruct();

		//copy the buffer
		auto& source_reference{reinterpret_cast<unsigned char&>(buffer)};
		auto& destination_reference{reinterpret_cast<unsigned char&>(*this)};
		std::copy(&source_reference, &source_reference + sizeof(Buffer), &destination_reference);

		//steal resources from the source buffer
		buffer.buffer_length = 0;
		buffer.manage_memory = false;
		buffer.readonly = false;
		buffer.deallocator = nullptr;
		buffer.size = 0;
		buffer.content = nullptr;

		return *this;
	}

	Buffer& Buffer::operator=(Buffer&& buffer) {
		return this->move(std::move(buffer));
	}

	Buffer& Buffer::operator=(const Buffer& buffer) {
		return this->copy(buffer);
	}

	Buffer::Buffer(Buffer&& buffer) {
		this->move(std::move(buffer));
	}

	Buffer::Buffer(const Buffer& buffer) {
		this->copy(buffer);
	}

	size_t Buffer::capacity() const {
		return this->buffer_length;
	}

	void Buffer::setReadOnly(bool readonly) {
		this->readonly = readonly;
	}

	void Buffer::clear() {
		if (this->buffer_length == 0) {
			return;
		}
		sodium_memzero(this->content, this->buffer_length);
		this->size = 0;
	}

	void Buffer::copyFrom(
			const size_t destination_offset,
			const Buffer& source,
			const size_t source_offset,
			const size_t copy_length) {
		if (this->readonly) {
			throw Exception{status_type::BUFFER_ERROR, "Can't copy to readonly buffer."};
		}

		if ((this->buffer_length < this->size) || (source.buffer_length < source.size)) {
			throw Exception{status_type::BUFFER_ERROR, "The content is larger than the buffer."};
		}

		if ((destination_offset > this->size) || (copy_length > (this->buffer_length - destination_offset))) {
			throw Exception{status_type::BUFFER_ERROR, "Can't copy to buffer that is too small."};
		}

		if ((source_offset > source.size) || (copy_length > (source.size - source_offset))) {
			throw Exception{status_type::BUFFER_ERROR, "Can't copy more than buffer_length bytes."};
		}

		if (source.buffer_length == 0) {
			return; //nothing to do
		}

		if ((this->content == nullptr) || (source.content == nullptr)) {
			throw Exception{status_type::BUFFER_ERROR, "The source or destination buffer has no content."};
		}

		std::copy(source.content + source_offset, source.content + source_offset + copy_length, this->content + destination_offset);
		this->size = (this->size > destination_offset + copy_length)
			? this->size
			: destination_offset + copy_length;
	}

	void Buffer::cloneFrom(const Buffer& source) {
		if (this->readonly) {
			throw Exception{status_type::BUFFER_ERROR, "Can't clone to readonly buffer."};
		}

		if (this->buffer_length < source.size) {
			throw Exception{status_type::BUFFER_ERROR, "The source doesn't fit into the destination."};
		}

		this->size = source.size;

		this->copyFrom(0, source, 0, source.size);
	}

	void Buffer::copyFromRaw(
			const size_t destination_offset,
			const unsigned char * const source,
			const size_t source_offset,
			const size_t copy_length) {
		if (this->readonly) {
			throw Exception{status_type::BUFFER_ERROR, "Can't copy to readonly buffer."};
		}

		if (this->buffer_length < this->size) {
			throw Exception{status_type::BUFFER_ERROR, "The content is longer than the buffer."};
		}

		if ((this->buffer_length < destination_offset) || (copy_length > (this->buffer_length - destination_offset))) {
			throw Exception{status_type::BUFFER_ERROR, "The source doesn't fit into the destination."};
		}

		if (copy_length == 0) {
			return;
		}

		std::copy(source + source_offset, source + source_offset + copy_length, this->content + destination_offset);
		this->size = (this->size > destination_offset + copy_length)
			? this->size
			: destination_offset + copy_length;
	}

	void Buffer::cloneFromRaw(const unsigned char * const source, const size_t length) {
		if (this->readonly) {
			throw Exception{status_type::BUFFER_ERROR, "Can't clone to readonly buffer."};
		}

		if (this->buffer_length < length) {
			throw Exception{status_type::BUFFER_ERROR, "The source doesn't fit into the destination."};
		}

		this->size = length;

		this->copyFromRaw(0, source, 0, length);
	}

	void Buffer::copyToRaw(
			unsigned char * const destination,
			const size_t destination_offset,
			const size_t source_offset,
			const size_t copy_length) const {
		if ((source_offset > this->size) || (copy_length > (this->size - source_offset))) {
			throw Exception{status_type::BUFFER_ERROR, "The source doesn't fit into the destination."};
		}

		if (this->buffer_length < this->size) {
			throw Exception{status_type::BUFFER_ERROR, "The content is longer than the buffer."};
		}

		if (this->buffer_length == 0) {
			return;
		}

		std::copy(this->content + source_offset, this->content + source_offset + copy_length, destination + destination_offset);
	}

	void Buffer::cloneToRaw(unsigned char * const destination, const size_t destination_length) const {
		if (destination_length < this->size) {
			throw Exception{status_type::BUFFER_ERROR, "Can't clone to raw buffer that is to small."};
		}

		this->copyToRaw(destination, 0, 0, this->size);
	}

	int Buffer::compare(const Buffer& buffer) const {
		return this->compareToRaw(buffer.content, buffer.size);
	}

	int Buffer::compareToRaw(const unsigned char * const array, const size_t array_length) const {
		return this->compareToRawPartial(0, array, array_length, 0, this->size);
	}

	int Buffer::comparePartial(
			const size_t position1,
			const Buffer& buffer2,
			const size_t position2,
			const size_t length) const {
		return this->compareToRawPartial(position1, buffer2.content, buffer2.size, position2, length);
	}

	int Buffer::compareToRawPartial(
			const size_t position1,
			const unsigned char * const array,
			const size_t array_length,
			const size_t position2,
			const size_t comparison_length) const {
		if (((this->size - position1) < comparison_length) || ((array_length - position2) < comparison_length)) {
			//FIXME: Does this introduce a timing sidechannel? This leaks the information that two buffers don't have the same length
			//buffers are too short
			return -6; //TODO: Is this an exception?
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

	void Buffer::fillRandom(const size_t length) {
		if (length > this->buffer_length) {
			throw Exception{status_type::BUFFER_ERROR, "Can't fill more than the entire buffer."};
		}

		if (this->readonly) {
			throw Exception{status_type::BUFFER_ERROR, "Can't fill readonly buffer with random numbers."};
		}

		if (this->buffer_length == 0) {
			return;
		}

		this->size = length;
		randombytes_buf(this->content, length);
	}

	//FIXME: Make sure this doesn't introduce any sidechannels
	void Buffer::xorWith(const Buffer& source) {
		if (this->readonly) {
			throw Exception{status_type::BUFFER_ERROR, "Can't xor to readonly buffer."};
		}

		if ((this->size != source.size)
				|| (this->buffer_length < this->size)
				|| (source.buffer_length < source.size)) {
			throw Exception{status_type::BUFFER_ERROR, "Buffer length mismatch."};
		}

		//xor source onto destination
		for (size_t i{0}; i < this->size; i++) {
			this->content[i] ^= source.content[i];
		}
	}

	unsigned char* Buffer::release() {
		auto content{this->content};
		this->content = nullptr;
		this->size = 0;
		this->buffer_length = 0;

		return content;
	}

	std::ostream& Buffer::print(std::ostream& stream) const {
		stream << std::string(reinterpret_cast<char*>(this->content), this->size);

		return stream;
	}

	std::ostream& Buffer::printHex(std::ostream& stream) const {
		static const size_t width{30};
		//buffer for the hex string
		const size_t hex_length{this->size * 2 + sizeof("")};
		auto hex{std::make_unique<char[]>(hex_length)};
		if (sodium_bin2hex(hex.get(), hex_length, this->content, this->size) == nullptr) {
			throw Exception{status_type::BUFFER_ERROR, "Failed to converst binary to hex with sodium_bin2hex."};
		}

		for (size_t i{0}; i < hex_length; i++) {
			if ((width != 0) && ((i % width) == 0) && (i != 0)) {
				stream << '\n';
			} else if ((i % 2 == 0) && (i != 0)) {
				stream << ' ';
			}
			stream << hex[i];
		}

		return stream;
	}

	bool Buffer::isNone() const {
		return (this->size == 0) || sodium_is_zero(this->content, this->size);
	}

	bool Buffer::operator ==(const Buffer& buffer) const {
		return this->compare(buffer) == 0;
	}

	bool Buffer::operator !=(const Buffer& buffer) const {
		return !(*this == buffer);
	}

	bool Buffer::fits(const size_t size) const {
		return this->buffer_length >= size;
	}

	bool Buffer::contains(const size_t size) const {
		return this->fits(size) && (this->size == size);
	}
}
