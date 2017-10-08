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

#include <iostream>
#include <cstdlib>
#include <exception>

#include "../lib/molch-exception.hpp"
#include "../lib/protobuf-pool.hpp"

using namespace Molch;

int main() {
	try {
		Molch::sodium_init();

		ProtobufPool pool;

		auto buffer1{pool.allocate<gsl::byte>(ProtobufPoolBlock::default_block_size - 10)};
		std::cout << "buffer1 = " << reinterpret_cast<void*>(buffer1) << std::endl;
		auto buffer2{pool.allocate<gsl::byte>(10)};
		std::cout << "buffer2 = " << reinterpret_cast<void*>(buffer2) << std::endl;

		if (buffer2 != (buffer1 + ProtobufPoolBlock::default_block_size - 10)) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Allocation wasn't following the previous."};
		}
		std::cout << "Successfully allocated consecutive regions." << std::endl;

		auto in_new_block{pool.allocate<gsl::byte>(1)};
		std::cout << "in_new_block = " << reinterpret_cast<void*>(in_new_block) << std::endl;
		if (in_new_block == (buffer2 + 10)) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Allocation didn't use a new block."};
		}
		std::cout << "Successfully created new block for allocations." << std::endl;

		auto large{pool.allocate<gsl::byte>(2 * ProtobufPoolBlock::default_block_size)};
		std::cout << "large = " << reinterpret_cast<void*>(large) << std::endl;
		auto fill_gap{pool.allocate<gsl::byte>(2)};
		std::cout << "fill_gap = " << reinterpret_cast<void*>(fill_gap) << std::endl;
		if ((in_new_block + 1) != fill_gap) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Failed to fill gap in block."};
		}
		std::cout << "Filled the gap." << std::endl;

		auto integer{pool.allocate<uint32_t>(sizeof(uint32_t))};
		std::cout << "integer = " << reinterpret_cast<void*>(integer) << std::endl;
		if (reinterpret_cast<unsigned char*>(integer) != reinterpret_cast<unsigned char*>(in_new_block + alignof(uint32_t))) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Failed to align new allocation."};
		}
		std::cout << "Properly aligned new allocation." << std::endl;

		auto allocator{pool.getProtobufCAllocator()};
		if (allocator.alloc != &ProtobufPool::poolAllocate) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "allocator.alloc is incorrect."};
		}
		if (allocator.free != &ProtobufPool::poolFree) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "allocator.free is incorrect."};
		}
		if (allocator.allocator_data != reinterpret_cast<void*>(&pool)) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "allocator.allocator_data isn't a pointer to the pool"};
		}
		std::cout << "ProtobufCAllocator struct is correct." << std::endl;
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
