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

#include <algorithm>
#include <cstdlib>
#include <sodium.h>
#include <iostream>
#include <exception>

#include "../lib/buffer.hpp"
#include "../lib/destroyers.hpp"
#include "utils.hpp"
#include "inline-utils.hpp"
#include "exception.hpp"

using namespace Molch;

int main() {
	try {
		TRY_VOID(Molch::sodium_init());

		Buffer string1{"1234"};
		Buffer string2{"1234"};
		Buffer string3{"2234"};
		Buffer string4{"12345"};
		if ((string1 != string2)
				|| (string1 == string3)
				|| (string1 == string4)) {
			throw Molch::Exception{status_type::BUFFER_ERROR, "buffer_compare doesn't work as expected."};
		}

		TRY_WITH_RESULT(string1_4_comparison, string1.comparePartial(0, string4, 0, 4));
		TRY_WITH_RESULT(string1_3_comparison, string1.comparePartial(2, string3, 2, 2));
		if (!string1_4_comparison.value() || !string1_3_comparison.value()) {
			throw Molch::Exception{status_type::BUFFER_ERROR, "buffer_compare_partial doesn't work as expected."};
		}
		std::cout << "Successfully tested buffer comparison ..." << std::endl;

		//test buffer with custom allocator
		SodiumBuffer custom{10, 2};

		//create a new buffer
		Buffer buffer1{14, 10};
		std::byte buffer1_content[10];
		randombytes_buf(buffer1_content, sizeof(buffer1_content));
		std::copy(std::cbegin(buffer1_content), std::cend(buffer1_content), std::begin(buffer1));

		std::cout << "Random buffer (" << buffer1.size() << " Bytes):\n";
		std::cout << buffer1 << '\n';

		unsigned char buffer2_content[]{0xde, 0xad, 0xbe, 0xef, 0x00};
		Buffer buffer2{sizeof(buffer2_content), sizeof(buffer2_content)};
		TRY_VOID(buffer2.cloneFromRaw({uchar_to_byte(buffer2_content), sizeof(buffer2_content)}));

		std::cout << "Second buffer (" << buffer2.size() << " Bytes):\n";
		std::cout << buffer2 << std::endl;

		Buffer empty{static_cast<size_t>(0), 0};
		Buffer empty2{static_cast<size_t>(0), 0};
		TRY_VOID(empty2.cloneFrom(empty));

		//copy buffer
		Buffer buffer3{5, 0};
		TRY_VOID(buffer3.copyFrom(0, buffer2, 0, buffer2.size()));
		if (buffer2 != buffer3) {
			throw Molch::Exception{status_type::BUFFER_ERROR, "Failed to copy buffer."};
		}
		std::cout << "Buffer successfully copied.\n";

		if (buffer3.copyFrom(buffer2.size(), buffer2, 0, buffer2.size())) {
			throw Molch::Exception{status_type::GENERIC_ERROR, "Failed to detect out of bounds buffer copying."};
		}
		std::cout << "Detected out of bounds buffer copying.\n";

		TRY_VOID(buffer3.copyFrom(1, buffer2, 0, buffer2.size() - 1));
		if ((buffer3[0] != buffer2[0]) || (sodium_memcmp(buffer2.data(), buffer3.data() + 1, buffer2.size() - 1) != 0)) {
			throw Molch::Exception{status_type::BUFFER_ERROR, "Failed to copy buffer."};
		}
		std::cout << "Successfully copied buffer.\n";

		//copy from raw array
		unsigned char heeelo[14]{"Hello World!\n"};
		TRY_VOID(buffer1.copyFromRaw(
				0, //offset
				uchar_to_byte(heeelo), //source
				0, //offset
				sizeof(heeelo))); //length
		if (sodium_memcmp(heeelo, buffer1.data(), sizeof(heeelo))) {
			throw Molch::Exception{status_type::BUFFER_ERROR, "Failed to copy from raw array to buffer."};
		}
		std::cout << "Successfully copied raw array to buffer.\n";

		if (buffer1.copyFromRaw(1, uchar_to_byte(heeelo), 0, sizeof(heeelo))) {
			throw Molch::Exception{status_type::GENERIC_ERROR, "Failed to detect out of bounds read."};
		}
		std::cout << "Out of bounds read detected.\n";

		//create a buffer from a string
		Buffer string{"This is a string!"};
		if (string.size() != sizeof("This is a string!")) {
			throw Molch::Exception{status_type::BUFFER_ERROR, "Buffer created from string has incorrect length."};
		}
		if (sodium_memcmp(string.data(), "This is a string!", string.size()) != 0) {
			throw Molch::Exception{status_type::BUFFER_ERROR, "Failed to create buffer from string."};
		}
		std::cout << "Successfully created buffer from string.\n";

		//erase the buffer
		std::cout << "Erasing buffer.\n";
		buffer1.clear();

		//check if the buffer was properly cleared
		for (size_t i{0}; i < buffer1.capacity(); i++) {
			if (buffer1.data()[i] != static_cast<std::byte>('\0')) {
				throw Molch::Exception{status_type::BUFFER_ERROR, "Buffer hasn't been erased properly."};
			}
		}

		if (!buffer1.empty()) {
			throw Molch::Exception{status_type::BUFFER_ERROR, "The content length of the buffer hasn't been set to zero."};
		}
		std::cout << "Buffer successfully erased.\n";

		//compare buffer to an array
		Buffer true_buffer{"true"};
		{
			TRY_WITH_RESULT(comparison, true_buffer.compareToRaw({char_to_byte("true"), sizeof("true")}));
			if (!comparison.value()) {
				throw Molch::Exception{status_type::BUFFER_ERROR, "Failed to compare buffer to array."};
			}
		}
		{
			TRY_WITH_RESULT(comparison, true_buffer.compareToRaw({char_to_byte("fals"), sizeof("fals")}));
			if (comparison.value()) {
				throw Molch::Exception{status_type::BUFFER_ERROR, "Failed to detect difference in buffer and array."};
			}
		}
		{
			TRY_WITH_RESULT(comparison, true_buffer.compareToRaw({char_to_byte("false"), sizeof("false")}));
			if (comparison.value()) {
				throw Molch::Exception{status_type::BUFFER_ERROR, "ERROR: Failed to detect difference in buffer and array."};
			}
		}

		//test custom allocator
		SodiumBuffer custom_allocated{10, 10};
		MallocBuffer custom_allocated_empty_buffer{0, 0};
		if (custom_allocated_empty_buffer.data() != nullptr) {
			throw Molch::Exception{status_type::BUFFER_ERROR, "Customly allocated empty buffer has content."};
		}
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
