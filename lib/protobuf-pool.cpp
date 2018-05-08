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
		this->block = std::unique_ptr<gsl::byte,SodiumDeleter<gsl::byte>>(sodium_malloc<gsl::byte>(block_size));

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
	void* ProtobufPoolBlock::allocate<void>(size_t elements) {
		size_t amount{elements / sizeof(max_align_t)};
		if ((elements % sizeof(max_align_t)) != 0) {
			amount++;
		}

		//check for overflow
		return reinterpret_cast<void*>(this->allocate<max_align_t>(amount));
	}

	template <>
	void* ProtobufPool::allocate<void>(size_t elements) {
		size_t amount{elements / sizeof(max_align_t)};
		if ((elements % sizeof(max_align_t)) != 0) {
			amount++;
		}

		return this->allocate<max_align_t>(amount);
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
