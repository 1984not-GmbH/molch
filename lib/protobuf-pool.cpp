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

	template <>
	void* ProtobufPoolBlock::allocate<void>(size_t size) {
		size_t elements{size / sizeof(max_align_t)};
		if ((size % sizeof(max_align_t)) != 0) {
			elements++;
		}

		//check for overflow
		return reinterpret_cast<void*>(this->allocate<max_align_t>(elements));
	}

	template <>
	void* ProtobufPool::allocate<void>(size_t size) {
		size_t elements{size / sizeof(max_align_t)};
		if ((size % sizeof(max_align_t)) != 0) {
			elements++;
		}

		return this->allocate<max_align_t>(elements);
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

	void *protobuf_c_new(void *allocator_data, size_t size) {
		(void)allocator_data;
		return reinterpret_cast<void*>(new unsigned char[size]);
	}
	void protobuf_c_delete(void *allocator_data, void *pointer) {
		(void)allocator_data;
		delete[] reinterpret_cast<unsigned char*>(pointer);
	}
}
