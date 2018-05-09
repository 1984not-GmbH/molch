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

#ifndef LIB_BUFFER_H
#define LIB_BUFFER_H

#include <cstdlib>
#include <ostream>
#include <memory>
#include <exception>
#include <sodium.h>
#include <algorithm>
#include <iterator>

#include "gsl.hpp"
#include "molch-exception.hpp"
#include "malloc.hpp"
#include "sodium-wrappers.hpp"

namespace Molch {
	template <typename Allocator>
	class BaseBuffer {
	private:
		Allocator allocator;
		size_t buffer_length{0};

		size_t content_length{0};
		std::byte* content{nullptr};


		/* implementation of copy construction and assignment */
		template <typename OtherAllocator>
		BaseBuffer& copy(const BaseBuffer<OtherAllocator>& buffer) {
			this->destruct();

			this->buffer_length = buffer.capacity();
			this->content_length = buffer.size();

			this->content = allocator.allocate(buffer.capacity(), nullptr);
			std::copy(std::cbegin(buffer), std::cend(buffer), std::begin(*this));

			return *this;
		}

		/* implementation of move construction and assignment */
		BaseBuffer& move(BaseBuffer&& buffer) {
			this->destruct();

			//move the buffer over
			this->buffer_length = buffer.buffer_length;
			this->content_length = buffer.content_length;
			this->content = buffer.content;

			//steal resources from the source buffer
			buffer.buffer_length = 0;
			buffer.content_length = 0;
			buffer.content = nullptr;

			return *this;
		}

		/*
		 * Deallocate all dynamically allocated memory
		 */
		void destruct() {
			this->clear();
			allocator.deallocate(this->content, this->content_length);
		}

	public:
		using value_type = std::byte;
		using allocator_type = Allocator;
		using size_type = size_t;
		using difference_type = ptrdiff_t;
		using reference = value_type&;
		using const_reference = const value_type&;
		using pointer = value_type*;
		using const_pointer = const value_type*;
		using iterator = pointer;
		using const_iterator = const_pointer;

		BaseBuffer() = default; // does nothing
		/* move constructor */
		BaseBuffer(BaseBuffer&& buffer) {
			this->move(std::move(buffer));
		}

		/* copy constructor */
		BaseBuffer(const BaseBuffer& buffer) {
			this->copy(buffer);
		}

		BaseBuffer(const std::string& string) :
				buffer_length{string.length() + sizeof("")},
				content_length{string.length() + sizeof("")},
				content{allocator.allocate(string.length() + sizeof(""), nullptr)} {
			std::copy(std::begin(string), std::end(string), reinterpret_cast<char*>(this->content));
			this->content[string.length()] = static_cast<std::byte>('\0');
		}

		BaseBuffer(const size_t capacity, const size_t size) :
				buffer_length{capacity},
				content_length{size} {
			if (capacity == 0) {
				this->content = nullptr;
			} else {
				this->content = allocator.allocate(capacity, nullptr);
			}
		}

		~BaseBuffer() {
			this->destruct();
		}

		//move assignment
		BaseBuffer& operator=(BaseBuffer&& buffer) {
			return this->move(std::move(buffer));
		}
		//copy assignment
		template <typename OtherAllocator>
		BaseBuffer& operator=(const BaseBuffer<OtherAllocator>& buffer) {
			return this->copy(buffer);
		}

		std::byte& operator[](size_t index) {
			Expects(index < this->content_length);

			return this->content[index];
		}
		const std::byte& operator[](size_t index) const {
			Expects(index < this->content_length);

			return this->content[index];
		}

		std::byte* data() noexcept {
			return this->content;
		}
		const std::byte* data() const noexcept {
			return this->content;
		}

		size_t size() const noexcept {
			return this->content_length;
		}

		bool empty() const noexcept {
			return this->content_length == 0;
		}

		void setSize(size_t size) {
			Expects(size <= this->buffer_length);

			this->content_length = size;
		}

		std::byte* begin() noexcept {
			return this->content;
		}
		const std::byte* begin() const noexcept {
			return this->content;
		}
		std::byte* end() noexcept {
			return this->content + this->content_length;
		}
		const std::byte* end() const noexcept {
			return this->content + this->content_length;
		}

		/*
		 * Clear a buffer.
		 *
		 * Overwrites the buffer with zeroes and
		 * resets the content size.
		 */
		void clear() noexcept {
			if (this->buffer_length == 0) {
				return;
			}
			try {
				sodium_memzero(*this);
				this->content_length = 0;
			} catch (...) {
				std::terminate();
			}
		}

		/*
		 * Fill a buffer with random numbers.
		 */
		void fillRandom(const size_t length) {
			Expects(length <= this->buffer_length);

			if (this->buffer_length == 0) {
				return;
			}

			this->content_length = length;
			randombytes_buf({this->content, length});
		}

		/*
		 * Compare two buffers.
		 *
		 * Returns 0 if both buffers match.
		 */
		template <typename OtherAllocator>
		int compare(const BaseBuffer<OtherAllocator>& buffer) const {
			return this->compareToRaw(buffer);
		}

		/*
		 * Compare parts of two buffers.
		 *
		 * Returns 0 if both buffers match.
		 */
		template <typename OtherAllocator>
		int comparePartial(
				const size_t position1,
				const BaseBuffer<OtherAllocator>& buffer2,
				const size_t position2,
				const size_t length) const {
			return this->compareToRawPartial(position1, buffer2, position2, length);
		}

		/*
		 * Compare a buffer to a raw array.
		 *
		 * Returns 0 if both buffers match.
		 */
		int compareToRaw(const span<const std::byte> array) const {
			return this->compareToRawPartial(0, array, 0, this->content_length);
		}


		/*
		 * Compare parts of a buffer to parts of a raw array.
		 *
		 * Returns 0 if both buffers match.
		 */
		int compareToRawPartial(
				const size_t position1,
				const span<const std::byte> array,
				const size_t position2,
				const size_t comparison_length) const {
			if (((this->content_length - position1) < comparison_length) || ((array.size() - position2) < comparison_length)) {
				//FIXME: Does this introduce a timing sidechannel? This leaks the information that two buffers don't have the same length
				//buffers are too short
				return -6; //TODO: Is this an exception?
			}

			if ((this->buffer_length == 0) || (array.empty())) {
				if (comparison_length == 0) {
					return 0;
				} else {
					return -1;
				}
			}

			bool comparison{sodium_memcmp({this->content + position1, comparison_length}, {array.data() + position2, comparison_length})};

			if (comparison) {
				return 0;
			}

			return -1;
		}

		/*
		 * Copy parts of a buffer to another buffer.
		 */
		template <typename OtherAllocator>
		void copyFrom(
				const size_t destination_offset,
				const BaseBuffer<OtherAllocator>& source,
				const size_t source_offset,
				const size_t copy_length) {
			Expects((this->buffer_length >= this->content_length)
					&& (source.capacity() >= source.size())
					&& (destination_offset <= this->content_length)
					&& (copy_length <= (this->buffer_length - destination_offset))
					&& (source_offset <= source.size())
					&& (copy_length <= (source.size() - source_offset))
					&& ((this->content_length == 0) || (this->content != nullptr))
					&& ((source.size() == 0) || (source.data() != nullptr)));

			if (source.empty()) {
				return; //nothing to do
			}

			std::copy(std::cbegin(source) + source_offset, std::cbegin(source) + source_offset + copy_length, std::begin(*this) + destination_offset);
			this->content_length = (this->content_length > destination_offset + copy_length)
				? this->content_length
				: destination_offset + copy_length;
		}

		/*
		 * Copy the content of a buffer to the beginning of another
		 * buffer and set the destinations content length to the
		 * same length as the source.
		 */
		template <typename OtherAllocator>
		void cloneFrom(const BaseBuffer<OtherAllocator>& source) {
			Expects(this->buffer_length >= source.size());

			this->content_length = source.size();

			this->copyFrom(0, source, 0, source.size());
		}

		/*
		 * Copy from a raw array to a buffer.
		 */
		void copyFromRaw(
				const size_t destination_offset,
				const std::byte * const source,
				const size_t source_offset,
				const size_t copy_length) {
			Expects(this->buffer_length >= destination_offset
					&& (copy_length <= (this->buffer_length - destination_offset)));

			if (copy_length == 0) {
				return;
			}

			std::copy(source + source_offset, source + source_offset + copy_length, this->content + destination_offset);
			this->content_length = (this->content_length > destination_offset + copy_length)
				? this->content_length
				: destination_offset + copy_length;
		}

		/*
		 * Copy the content of a raw array to the
		 * beginning of a buffer, setting the buffers
		 * content length to the length that was copied.
		 */
		void cloneFromRaw(const span<const std::byte> source) {
			Expects(this->buffer_length >= source.size());

			this->content_length = source.size();

			this->copyFromRaw(0, source.data(), 0, source.size());
		}

		/*
		 * Copy from a buffer to a raw array.
		 */
		void copyToRaw(
				std::byte * const destination,
				const size_t destination_offset,
				const size_t source_offset,
				const size_t copy_length) const {
			Expects((source_offset <= this->content_length) && (copy_length <= (this->content_length - source_offset))
					&& (this->buffer_length >= this->content_length));

			if (this->buffer_length == 0) {
				return;
			}

			std::copy(this->content + source_offset, this->content + source_offset + copy_length, destination + destination_offset);
		}

		/*
		 * Copy the entire content of a buffer
		 * to a raw array.
		 */
		void cloneToRaw(const span<std::byte> destination) const {
			Expects(destination.size() >= this->content_length);

			this->copyToRaw(destination.data(), 0, 0, this->content_length);
		}

		/*
		 * Return the content and set the capacity to 0 and size to 0.
		 */
		std::byte* release() {
			auto content{this->content};
			this->content = nullptr;
			this->content_length = 0;
			this->buffer_length = 0;

			return content;
		}

		std::ostream& print(std::ostream& stream) const {
			stream << std::string(reinterpret_cast<char*>(this->content), this->content_length);

			return stream;
		}

		std::ostream& printHex(std::ostream& stream) const {
			static const int width{30};
			//buffer for the hex string
			const size_t hex_length{this->content_length * 2 + sizeof("")};
			auto hex{std::make_unique<char[]>(hex_length)};
			sodium_bin2hex({hex.get(), hex_length}, *this);

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

		template <typename OtherAllocator>
		bool operator ==(const BaseBuffer<OtherAllocator>& buffer) const {
			return this->compare(buffer) == 0;
		}
		template <typename OtherAllocator>
		bool operator !=(const BaseBuffer<OtherAllocator>& buffer) const {
			return !(*this == buffer);
		}

		bool isNone() const noexcept {
			try {
				return (this->content_length == 0) || sodium_is_zero(*this);
			} catch (...) {
				std::terminate();
			}
		}

		size_t capacity() const noexcept {
			return this->buffer_length;
		}

		bool fits(const size_t size) const {
			return this->buffer_length >= size;
		}
		bool contains(const size_t size) const {
			return this->fits(size) && (this->content_length == size);
		}
	};

	using Buffer = BaseBuffer<std::allocator<std::byte>>;
	using SodiumBuffer = BaseBuffer<SodiumAllocator<std::byte>>;
	using MallocBuffer = BaseBuffer<MallocAllocator<std::byte>>;
}
#endif
