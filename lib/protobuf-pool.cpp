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

#include <algorithm>
#include <iterator>
#include "protobuf-pool.hpp"

namespace Molch {
	ProtobufPoolBlock::ProtobufPoolBlock() : ProtobufPoolBlock(default_block_size) {}

	ProtobufPoolBlock::ProtobufPoolBlock(size_t block_size) {
		//allocate the block
		this->block = std::unique_ptr<unsigned char,SodiumDeleter<unsigned char>>(throwing_sodium_malloc<unsigned char>(block_size));

		this->block_size = block_size;
	}

	size_t ProtobufPoolBlock::size() const {
		return this->block_size;
	}

	size_t ProtobufPoolBlock::remainingSpace() const {
		if ((this->block_size < this->offset)) {
			return 0;
		}

		return this->block_size - this->offset;
	}

	void* ProtobufPoolBlock::allocateAligned(const size_t size, const size_t alignment) {
			if (!this->block) {
				throw std::bad_alloc();
			}

			size_t space = this->remainingSpace();

			if (space < (size + alignment - 1)) {
				throw std::bad_alloc();
			}

			void* offset_pointer = reinterpret_cast<void*>(this->block.get() + this->offset);

			//align the pointer
			if (std::align(alignment, size, offset_pointer, space) == nullptr) {
				throw std::bad_alloc();
			}

			if (reinterpret_cast<unsigned char*>(offset_pointer) < this->block.get()) {
				throw std::bad_alloc();
			}

			//update the offset
			this->offset = static_cast<size_t>(reinterpret_cast<unsigned char*>(offset_pointer) - this->block.get()) + size;

			return offset_pointer;
	}

	template <>
	void* ProtobufPoolBlock::allocate<void>(size_t size) {
		return reinterpret_cast<void*>(this->allocateAligned(size, alignof(max_align_t)));
	}

	void* ProtobufPool::allocateAligned(const size_t size, const size_t alignment) {
		if (size > ProtobufPoolBlock::default_block_size) {
			this->blocks.emplace_back(size + alignment);
			return this->blocks.back().allocateAligned(size, alignment);
		}

		//find a block with enough space
		auto block = std::find_if(std::begin(this->blocks), std::end(this->blocks),
				[size, alignment](const ProtobufPoolBlock& block) {
					return block.remainingSpace() >= (alignment - 1 + size);
				});
		if (block != std::end(this->blocks)) {
			return block->allocateAligned(size, alignment);
		}

		//create a new block if no block was found
		this->blocks.emplace_back();
		return this->blocks.back().allocateAligned(size, alignment);
	}

	template <>
	void* ProtobufPool::allocate<void>(size_t size) {
		return this->allocateAligned(size, alignof(max_align_t));
	}

	void* ProtobufPool::poolAllocate(void* pool, size_t size) noexcept {
		if (pool == nullptr) {
			return nullptr;
		}

		return reinterpret_cast<ProtobufPool*>(pool)->allocate<void>(size);
	}

	void ProtobufPool::poolFree(void* pool, void* pointer) noexcept {
		(void)pool;
		(void)pointer;
	}

	ProtobufCAllocator ProtobufPool::getProtobufCAllocator() {
		return {
			&ProtobufPool::poolAllocate,
			&ProtobufPool::poolFree,
			reinterpret_cast<void*>(this)
		};
	}
}
