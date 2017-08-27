/*
 * Molch, an implementation of the axolotl ratchet based on libsodium
 *
 * ISC License
 *
 * Copyright (C) 2015-2016 1984not Security GmbH
 * Author: Max Bruckner (FSMaxB)
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

/* !file
 * Implements a pool allocator for Protobuf exports using sodium_malloc.
 *
 * The idea is to put all the protobuf structs in this pool during export
 * and then just throw it away afterwards, zeroing all the private key
 * material with it.
 */

#ifndef LIB_PROTOBUF_POOL_H
#define LIB_PROTOBUF_POOL_H

#include <vector>
#include <memory>
#include <algorithm>
#include <iterator>
#include <cstddef>
#include <protobuf-c/protobuf-c.h>

#include "sodium-wrappers.hpp"
#include "gsl.hpp"

namespace Molch {
	class ProtobufPoolBlock {
	private:
		std::unique_ptr<unsigned char,SodiumDeleter<unsigned char>> block;
		size_t block_size{default_block_size};
		size_t offset{0}; //offset of the next available pointer

		ProtobufPoolBlock& move(ProtobufPoolBlock&& block);

	public:
		static constexpr size_t default_block_size{102400}; //100KiB

		ProtobufPoolBlock();
		ProtobufPoolBlock(size_t block_size);
		ProtobufPoolBlock(ProtobufPoolBlock&&) = default;
		ProtobufPoolBlock(const ProtobufPoolBlock&) = delete;

		ProtobufPoolBlock& operator=(ProtobufPoolBlock&&) = delete;
		ProtobufPoolBlock& operator=(const ProtobufPoolBlock&) = delete;

		template <typename T>
		T* allocate(const size_t elements) {
			if (!this->block || (elements == 0)) {
				throw std::bad_alloc();
			}

			//check for overflow
			if ((std::numeric_limits<size_t>::max() / elements) < sizeof(T)) {
				throw std::bad_alloc();
			}

			size_t size{elements * sizeof(T)};
			size_t space{this->remainingSpace()};

			if (space <= (size + alignof(T))) {
				throw std::bad_alloc();
			}

			auto offset_pointer{reinterpret_cast<void*>(this->block.get() + this->offset)};

			//align the pointer
			if (std::align(alignof(T), size, offset_pointer, space) == nullptr) {
				throw std::bad_alloc();
			}

			if (reinterpret_cast<unsigned char*>(offset_pointer) < this->block.get()) {
				throw std::bad_alloc();
			}

			this->offset = gsl::narrow<size_t>(reinterpret_cast<unsigned char*>(offset_pointer) - this->block.get()) + size;

			return reinterpret_cast<T*>(offset_pointer);
		}

		size_t size() const;
		size_t remainingSpace() const;
	};

	template <>
	void* ProtobufPoolBlock::allocate<void>(size_t size);

	class ProtobufPool {
	private:
		std::vector<ProtobufPoolBlock> blocks;

	public:
		ProtobufPool() = default;

		template <typename T>
		T* allocate(size_t elements) {
			//check for overflow
			if ((std::numeric_limits<size_t>::max() / elements) < sizeof(T)) {
				throw std::bad_alloc();
			}

			size_t size{elements * sizeof(T)};

			if (size > ProtobufPoolBlock::default_block_size) {
				this->blocks.emplace_back(size + alignof(T));
				return this->blocks.back().allocate<T>(size);
			}

			//find a block with enough space
			auto block{std::find_if(std::begin(this->blocks), std::end(this->blocks),
					[size](const ProtobufPoolBlock& block) {
						return block.remainingSpace() >= (alignof(T) - 1 + size);
					})};
			if (block != std::end(this->blocks)) {
				return block->template allocate<T>(elements);
			}

			//create a new block if no block was found
			this->blocks.emplace_back();
			return this->blocks.back().allocate<T>(elements);
		}

		/* functions for Protobuf-C */
		static void* poolAllocate(void* pool, size_t size) noexcept;
		static void poolFree(void* pool, void* pointer) noexcept;

		/* returns a ProtobufCAllocator struct for this allocator */
		ProtobufCAllocator getProtobufCAllocator();
	};

	template <>
	void* ProtobufPool::allocate<void>(size_t size);
}

#endif /* LIB_PROTOBUF_POOL_H */
