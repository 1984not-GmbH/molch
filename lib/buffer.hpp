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

#include <cstdbool>
#include <cstdlib>
#include <ostream>

#include "gsl.hpp"

namespace Molch {
	class Buffer {
	private:
		size_t buffer_length{0};
		bool manage_memory{true}; //should the destructor manage memory?
		bool readonly{false}; //if set, this buffer shouldn't be written to.
		void (*deallocator)(void*){nullptr}; //a deallocator if the buffer has been allocated with a custom allocator

		Buffer& copy(const Buffer& buffer);
		Buffer& move(Buffer&& buffer);

		/*
		 * Deallocate all dynamically allocated memory
		 */
		void destruct();

	public:
		size_t size{0};
		gsl::byte *content{nullptr};

		Buffer() = default; // does nothing
		/* move and copy constructors */
		Buffer(Buffer&& buffer);
		Buffer(const Buffer& buffer);
		Buffer(const std::string& string);
		Buffer(const size_t capacity, const size_t size);
		/*
		 * initialize a buffer with a pointer to the character array.
		 * Won't zero out the data automatically!
		 */
		Buffer(const gsl::span<gsl::byte> content);
		Buffer(const gsl::span<gsl::byte> content, const size_t content_size);
		/*
		 * initialize a buffer with a pointer to an array of const characters.
		 */
		Buffer(const gsl::span<const gsl::byte> content);
		Buffer(const gsl::span<const gsl::byte> content, const size_t content_size);
		Buffer(const size_t capacity, const size_t size, void* (*allocator)(size_t), void (*deallocator)(void*));
		~Buffer();

		//move assignment
		Buffer& operator=(Buffer&& buffer);
		//copy assignment
		Buffer& operator=(const Buffer& buffer);

		/*
		 * Clear a buffer.
		 *
		 * Overwrites the buffer with zeroes and
		 * resets the content size.
		 */
		void clear();

		/*
		 * Xor another buffer with the same length onto this one.
		 */
		void xorWith(const Buffer& source);

		/*
		 * Fill a buffer with random numbers.
		 */
		void fillRandom(const size_t length);

		/*
		 * Compare two buffers.
		 *
		 * Returns 0 if both buffers match.
		 */
		int compare(const Buffer& buffer) const;

		/*
		 * Compare parts of two buffers.
		 *
		 * Returns 0 if both buffers match.
		 */
		int comparePartial(
				const size_t position1,
				const Buffer& buffer2,
				const size_t position2,
				const size_t length) const;

		/*
		 * Compare a buffer to a raw array.
		 *
		 * Returns 0 if both buffers match.
		 */
		int compareToRaw(const gsl::span<const gsl::byte> array) const;


		/*
		 * Compare parts of a buffer to parts of a raw array.
		 *
		 * Returns 0 if both buffers match.
		 */
		int compareToRawPartial(
				const size_t position1,
				const gsl::span<const gsl::byte> array,
				const size_t position2,
				const size_t comparison_length) const;

		/*
		 * Copy parts of a buffer to another buffer.
		 */
		void copyFrom(
				const size_t destination_offset,
				const Buffer& source,
				const size_t source_offset,
				const size_t copy_length);

		/*
		 * Copy the content of a buffer to the beginning of another
		 * buffer and set the destinations content length to the
		 * same length as the source.
		 */
		void cloneFrom(const Buffer& source);

		/*
		 * Copy from a raw array to a buffer.
		 */
		void copyFromRaw(
				const size_t destination_offset,
				const gsl::byte * const source,
				const size_t source_offset,
				const size_t copy_length);

		/*
		 * Copy the content of a raw array to the
		 * beginning of a buffer, setting the buffers
		 * content length to the length that was copied.
		 */
		void cloneFromRaw(const gsl::span<const gsl::byte> source);

		/*
		 * Copy from a buffer to a raw array.
		 */
		void copyToRaw(
				gsl::byte * const destination,
				const size_t destination_offset,
				const size_t source_offset,
				const size_t copy_length) const;

		/*
		 * Copy the entire content of a buffer
		 * to a raw array.
		 */
		void cloneToRaw(const gsl::span<gsl::byte> destination) const;

		/*
		 * Return the content and set the capacity to 0 and size to 0.
		 */
		gsl::byte* release();

		gsl::span<gsl::byte> span();
		gsl::span<const gsl::byte> span() const;

		std::ostream& print(std::ostream& stream) const;
		std::ostream& printHex(std::ostream& stream) const;

		bool operator ==(const Buffer& buffer) const;
		bool operator !=(const Buffer& buffer) const;

		bool isNone() const;

		size_t capacity() const;
		void setReadOnly(bool readonly);

		bool fits(const size_t size) const;
		bool contains(const size_t size) const;
	};
}
#endif
