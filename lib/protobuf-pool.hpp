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
#include <protobuf-c/protobuf-c.h>
#include <cstddef>

#include "sodium-wrappers.hpp"

class ProtobufPoolBlock {
private:
	std::unique_ptr<unsigned char,SodiumDeleter<unsigned char>> block;
	size_t block_size = default_block_size;
	size_t offset = 0; //offset of the next available pointer

	ProtobufPoolBlock& move(ProtobufPoolBlock&& block);

public:
	static constexpr size_t default_block_size = 100000; //100KB

	ProtobufPoolBlock(); //uses the default block size
	ProtobufPoolBlock(size_t block_size);
	ProtobufPoolBlock(ProtobufPoolBlock&& block) = default;
	ProtobufPoolBlock(const ProtobufPoolBlock& block) = delete;

	ProtobufPoolBlock& operator=(ProtobufPoolBlock&& block) = default;
	ProtobufPoolBlock& operator=(const ProtobufPoolBlock& block) = delete;

	void* allocateAligned(const size_t size, const size_t alignment);

	template <typename T>
	T* allocate(size_t size) {
		return reinterpret_cast<T*>(this->allocateAligned(size, alignof(T)));
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

	void* allocateAligned(const size_t size, const size_t alignment);

	template <typename T>
	T* allocate(size_t size) {
		return reinterpret_cast<T*>(this->allocateAligned(size, alignof(T)));
	}

	/* functions for Protobuf-C */
	static void* poolAllocate(void* pool, size_t size) noexcept;
	static void poolFree(void* pool, void* pointer) noexcept;

	/* returns a ProtobufCAllocator struct for this allocator */
	ProtobufCAllocator getProtobufCAllocator();
};

template <>
void* ProtobufPool::allocate<void>(size_t size);

#endif /* LIB_PROTOBUF_POOL_H */
