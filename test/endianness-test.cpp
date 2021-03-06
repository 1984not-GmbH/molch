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

#include <cstdio>
#include <cstdlib>
#include <iostream>

#include "../lib/endianness.hpp"
#include "utils.hpp"
#include "inline-utils.hpp"
#include "exception.hpp"

using namespace Molch;

int main() {
	try {
		if (endianness_is_little_endian()) {
			std::cout << "Current byte order: Little Endian!\n";
		} else {
			std::cout << "Current_byte_oder: Big Endian!\n";
		}

		//uint32_t -> big endian
		Buffer buffer32{4, 4};
		uint32_t uint32{67305985ULL};
		uint32_t uint32_from_big_endian{0};
		TRY_VOID(to_big_endian(uint32, buffer32));
		std::cout << "uint32_t " << uint32 << " to big endian:\n";
		std::cout << buffer32;

		TRY_WITH_RESULT(big_endian_result, buffer32.compareToRaw({char_to_byte("\x04\x03\x02\x01"), sizeof(uint32_t)}));
		if (!big_endian_result.value()) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "Big endian of uint32_t is incorrect."};
		}

		//uint32_t <- big endian
		TRY_VOID(from_big_endian(uint32_from_big_endian, buffer32));
		if (uint32 != uint32_from_big_endian) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "uint32_t from big endian is incorrect."};
		}
		std::cout << "Successfully converted back!\n\n";

		//int32_t -> big endian
		int32_t int32{-66052LL};
		int32_t int32_from_big_endian;
		TRY_VOID(to_big_endian(int32, buffer32));
		std::cout << "int32_t " << int32 << " to big endian:\n";
		std::cout << buffer32;

		{
			TRY_WITH_RESULT(buffer32_comparison, buffer32.compareToRaw({char_to_byte("\xFF\xFE\xFD\xFC"), sizeof(int32_t)}));
			if (!buffer32_comparison.value()) {
				throw Molch::Exception{status_type::INCORRECT_DATA, "Big endian of int32_t is incorrect."};
			}
		}

		//int32_t <- big endian
		TRY_VOID(from_big_endian(int32_from_big_endian, buffer32));
		if (int32 != int32_from_big_endian) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "uint32_t from big endian is incorrect."};
		}
		std::cout << "Successfully converted back!\n\n";

		//uint64_t -> big endian
		Buffer buffer64{8, 8};
		uint64_t uint64{578437695752307201ULL};
		uint64_t uint64_from_big_endian;
		TRY_VOID(to_big_endian(uint64, buffer64));
		std::cout << "uint64_t " << uint64 << " to big endian:\n";
		std::cout << buffer64;

		{
			TRY_WITH_RESULT(buffer64_comparison, buffer64.compareToRaw({char_to_byte("\x08\x07\x06\x05\x04\x03\x02\x01"), sizeof(uint64_t)}));
			if (!buffer64_comparison.value()) {
				throw Molch::Exception{status_type::INCORRECT_DATA, "Big endian of uint64_t is incorrect."};
			}
		}

		//uint64_t <- big endian
		TRY_VOID(from_big_endian(uint64_from_big_endian, buffer64));
		if (uint64 != uint64_from_big_endian) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "uint64_t from big endian is incorrect."};
		}
		std::cout << "Successfully converted back!\n\n";

		//int64_t -> big endian
		int64_t int64{-283686952306184LL};
		int64_t int64_from_big_endian;
		TRY_VOID(to_big_endian(int64, buffer64));
		std::cout << "int64_t " << int64 << " to big endian:\n";
		std::cout << buffer64;

		{
			TRY_WITH_RESULT(buffer64_comparison, buffer64.compareToRaw({char_to_byte("\xFF\xFE\xFD\xFC\xFB\xFA\xF9\xF8"), sizeof(int64_t)}));
			if (!buffer64_comparison.value()) {
				throw Molch::Exception{status_type::INCORRECT_DATA, "Big endian of int64_t is incorrect."};
			}
		}

		//int64_t <- big endian
		TRY_VOID(from_big_endian(int64_from_big_endian, buffer64));
		if (int64 != int64_from_big_endian) {
			throw Molch::Exception{status_type::INCORRECT_DATA, "unit64_t from big endian is incorrect."};
		}
		std::cout << "Successfully converted back!\n\n";
	} catch (const std::exception& exception) {
		std::cout << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
