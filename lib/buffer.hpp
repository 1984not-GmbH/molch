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
#include <string>

class Buffer {
private:
	size_t buffer_length{0};
	bool manage_memory{true}; //should the destructor manage memory?
	bool readonly{false}; //if set, this buffer shouldn't be written to.
	bool is_valid{true}; //has an error happened on initialization?
	void (*deallocator)(void*){nullptr}; //a deallocator if the buffer has been allocated with a custom allocator

	Buffer& copy(const Buffer& buffer) noexcept;
	Buffer& move(Buffer&& buffer) noexcept;

	/*
	 * Deallocate all dynamically allocated memory
	 */
	void destruct() noexcept;

public:
	size_t content_length{0};
	unsigned char *content{nullptr};

	Buffer() noexcept = default; // does nothing
	/* move and copy constructors */
	Buffer(Buffer&& buffer);
	Buffer(const Buffer& buffer);
	Buffer(const std::string& string) noexcept;
	Buffer(const size_t buffer_length, const size_t content_length) noexcept;
	/*
	 * initialize a buffer with a pointer to the character array.
	 */
	Buffer(unsigned char * const content, const size_t buffer_length) noexcept;
	Buffer(unsigned char * const content, const size_t buffer_length, const size_t content_length) noexcept;
	/*
	 * initialize a buffer with a pointer to an array of const characters.
	 */
	Buffer(const unsigned char * const content, const size_t buffer_length) noexcept;
	Buffer(const unsigned char * const content, const size_t buffer_length, const size_t content_length) noexcept;
	Buffer(const size_t buffer_length, const size_t content_length, void* (*allocator)(size_t), void (*deallocator)(void*)) noexcept;
	~Buffer() noexcept;

	//move assignment
	Buffer& operator=(Buffer&& buffer) noexcept;
	//copy assignment
	Buffer& operator=(const Buffer& buffer) noexcept;

	/*
	 * Clear a buffer.
	 *
	 * Overwrites the buffer with zeroes and
	 * resets the content size.
	 */
	void clear() noexcept;

	/*
	 * Free and clear an allocated buffer.
	 */
	void destroy() noexcept;

	/*
	 * Xor another buffer with the same length onto this one.
	 */
	int xorWith(const Buffer * const source) noexcept __attribute__((warn_unused_result));

	/*
	 * Fill a buffer with random numbers.
	 */
	int fillRandom(const size_t length) noexcept __attribute__((warn_unused_result));

	/*
	 * Compare two buffers.
	 *
	 * Returns 0 if both buffers match.
	 */
	int compare(const Buffer * const buffer) const noexcept __attribute__((warn_unused_result));

	/*
	 * Compare parts of two buffers.
	 *
	 * Returns 0 if both buffers match.
	 */
	int comparePartial(
			const size_t position1,
			const Buffer * const buffer2,
			const size_t position2,
			const size_t length) const noexcept __attribute__((warn_unused_result));

	/*
	 * Compare a buffer to a raw array.
	 *
	 * Returns 0 if both buffers match.
	 */
	int compareToRaw(const unsigned char * const array, const size_t array_length) const noexcept __attribute__((warn_unused_result));


	/*
	 * Compare parts of a buffer to parts of a raw array.
	 *
	 * Returns 0 if both buffers match.
	 */
	int compareToRawPartial(
			const size_t position1,
			const unsigned char * const array,
			const size_t array_length,
			const size_t position2,
			const size_t comparison_length) const noexcept;

	/*
	 * Copy parts of a buffer to another buffer.
	 *
	 * Returns 0 on success.
	 */
	int copyFrom(
			const size_t destination_offset,
			const Buffer * const source,
			const size_t source_offset,
			const size_t copy_length) noexcept __attribute__((warn_unused_result));

	/*
	 * Copy the content of a buffer to the beginning of another
	 * buffer and set the destinations content length to the
	 * same length as the source.
	 *
	 * Returns 0 on success.
	 */
	int cloneFrom(const Buffer * const source) noexcept __attribute__((warn_unused_result));

	/*
	 * Copy from a raw array to a buffer.
	 *
	 * Returns 0 on success.
	 */
	int copyFromRaw(
			const size_t destination_offset,
			const unsigned char * const source,
			const size_t source_offset,
			const size_t copy_length) noexcept __attribute__((warn_unused_result));

	/*
	 * Copy the content of a raw array to the
	 * beginning of a buffer, setting the buffers
	 * content length to the length that was copied.
	 *
	 * Returns 0 on success.
	 */
	int cloneFromRaw(const unsigned char * const source, const size_t length) noexcept __attribute__((warn_unused_result));

	/*
	 * Copy from a buffer to a raw array.
	 *
	 * Returns 0 on success.
	 */
	int copyToRaw(
			unsigned char * const destination,
			const size_t destination_offset,
			const size_t source_offset,
			const size_t copy_length) const noexcept __attribute__((warn_unused_result));

	/*
	 * Copy the entire content of a buffer
	 * to a raw array.
	 *
	 * Returns 0 on success.
	 */
	int cloneToRaw(unsigned char * const destination, const size_t destination_length) const noexcept __attribute__((warn_unused_result));

	/*
	 * Create a new buffer on the heap.
	 */
	static Buffer *create(
			const size_t buffer_length,
			const size_t content_length) noexcept __attribute__((warn_unused_result));

	/*
	 * Create a new buffer with a custom allocator.
	 */
	static Buffer *createWithCustomAllocator(
			const size_t buffer_length,
			const size_t content_length,
			void *(*allocator)(size_t size),
			void (*deallocator)(void *pointer)
			) noexcept __attribute__((warn_unused_result));

	std::string toString() const noexcept;
	std::string toHex() const noexcept;

	bool operator ==(const Buffer& buffer) const noexcept;
	bool operator !=(const Buffer& buffer) const noexcept;

	bool isNone() const noexcept;
	bool isValid() const noexcept;

	size_t getBufferLength() const noexcept;
	void setReadOnly(bool readonly) noexcept;

	bool fits(const size_t size) const noexcept;
	bool contains(const size_t size) const noexcept;
};

//throw std::bad_alloc if a buffer is invalid (which the buffer will do automatically in the future)
inline void exception_on_invalid_buffer(const Buffer& buffer) {
	if (!buffer.isValid()) {
		throw std::bad_alloc();
	}
}
#endif
