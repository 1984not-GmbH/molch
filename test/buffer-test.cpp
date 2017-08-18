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
#include "../lib/molch-exception.hpp"
#include "utils.hpp"

int main(void) {
	try {
		if (sodium_init() == -1) {
			throw MolchException(INIT_ERROR, "Failed to initialize libsodium.");
		}

		Buffer string1("1234");
		Buffer string2("1234");
		Buffer string3("2234");
		Buffer string4("12345");
		if ((string1 != string2)
				|| (string1 == string3)
				|| (string1 == string4)) {
			throw MolchException(BUFFER_ERROR, "buffer_compare doesn't work as expected.");
		}

		if ((string1.comparePartial(0, string4, 0, 4) != 0)
				|| (string1.comparePartial(2, string3, 2, 2) != 0)) {
			throw MolchException(BUFFER_ERROR, "buffer_compare_partial doesn't work as expected.");
		}
		std::cout << "Successfully tested buffer comparison ..." << std::endl;

		//test buffer with custom allocator
		Buffer custom(10, 2, &sodium_malloc, &sodium_free);

		//create a new buffer
		Buffer buffer1(14, 10);
		unsigned char buffer1_content[10];
		randombytes_buf(buffer1_content, sizeof(buffer1_content));
		std::copy(buffer1_content, buffer1_content + sizeof(buffer1_content), buffer1.content);
		printf("Here\n");

		std::cout << "Random buffer (" << buffer1.content_length << " Bytes):\n";
		buffer1.printHex(std::cout) << '\n';

		unsigned char buffer2_content[]{0xde, 0xad, 0xbe, 0xef, 0x00};
		Buffer buffer2;
		new (&buffer2) Buffer{buffer2_content, 5, 4};

		printf("Second buffer (%zu Bytes):\n", buffer2.content_length);
		buffer2.printHex(std::cout) << std::endl;

		Buffer empty(static_cast<size_t>(0), 0);
		Buffer empty2(static_cast<size_t>(0), 0);
		empty2.cloneFrom(empty);

		//copy buffer
		Buffer buffer3(5, 0);
		buffer3.copyFrom(0, buffer2, 0, buffer2.content_length);
		if (buffer2 != buffer3) {
			throw MolchException(BUFFER_ERROR, "Failed to copy buffer.");
		}
		printf("Buffer successfully copied.\n");

		bool detected = false;
		try {
			buffer3.copyFrom(buffer2.content_length, buffer2, 0, buffer2.content_length);
		} catch (...) {
			detected = true;
		}
		if (!detected) {
			throw MolchException(GENERIC_ERROR, "Failed to detect out of bounds buffer copying.");
		}
		printf("Detected out of bounds buffer copying.\n");

		buffer3.copyFrom(1, buffer2, 0, buffer2.content_length);
		if ((buffer3.content[0] != buffer2.content[0]) || (sodium_memcmp(buffer2.content, buffer3.content + 1, buffer2.content_length) != 0)) {
			throw MolchException(BUFFER_ERROR, "Failed to copy buffer.");
		}
		printf("Successfully copied buffer.\n");

		//copy to a raw array
		unsigned char raw_array[4];
		buffer1.copyToRaw(
				raw_array, //destination
				0, //destination offset
				1, //source offset
				4); //length
		if (sodium_memcmp(raw_array, buffer1.content + 1, 4) != 0) {
			throw MolchException(BUFFER_ERROR, "Failed to copy buffer to raw array.");
		}
		printf("Successfully copied buffer to raw array.\n");

		detected = false;
		try {
			buffer2.copyToRaw(raw_array, 0, 3, 4);
		} catch (...) {
			detected = true;
		}
		if (!detected) {
			throw MolchException(GENERIC_ERROR, "Failed to detect out of bounds read.");
		}
		printf("Successfully detected out of bounds read.\n");

		//copy from raw array
		unsigned char heeelo[14] = "Hello World!\n";
		buffer1.copyFromRaw(
				0, //offset
				heeelo, //source
				0, //offset
				sizeof(heeelo)); //length
		if (sodium_memcmp(heeelo, buffer1.content, sizeof(heeelo))) {
			throw MolchException(BUFFER_ERROR, "Failed to copy from raw array to buffer.");
		}
		printf("Successfully copied raw array to buffer.\n");

		detected = false;
		try {
			buffer1.copyFromRaw(
					1,
					heeelo,
					0,
					sizeof(heeelo));
		} catch (...) {
			detected = true;
		}
		if (!detected) {
			throw MolchException(GENERIC_ERROR, "Failed to detect out of bounds read.");
		}
		printf("Out of bounds read detected.\n");

		//create a buffer from a string
		Buffer string("This is a string!");
		if (string.content_length != sizeof("This is a string!")) {
			throw MolchException(BUFFER_ERROR, "Buffer created from string has incorrect length.");
		}
		if (sodium_memcmp(string.content, "This is a string!", string.content_length) != 0) {
			throw MolchException(BUFFER_ERROR, "Failed to create buffer from string.");
		}
		printf("Successfully created buffer from string.\n");

		//erase the buffer
		printf("Erasing buffer.\n");
		buffer1.clear();

		//check if the buffer was properly cleared
		size_t i;
		for (i = 0; i < buffer1.getBufferLength(); i++) {
			if (buffer1.content[i] != '\0') {
				throw MolchException(BUFFER_ERROR, "Buffer hasn't been erased properly.");
			}
		}

		if (buffer1.content_length != 0) {
			throw MolchException(BUFFER_ERROR, "The content length of the buffer hasn't been set to zero.");
		}
		printf("Buffer successfully erased.\n");

		//fill a buffer with random numbers
		Buffer random(10, 0);
		random.fillRandom(5);

		if (random.content_length != 5) {
			throw MolchException(BUFFER_ERROR, "Wrong content length.\n");
		}
		printf("Buffer with %zu random bytes:\n", random.content_length);
		random.printHex(std::cout);

		detected = false;
		try {
			random.fillRandom(20);
		} catch(...) {
			detected = true;
		}
		if (!detected) {
			throw MolchException(BUFFER_ERROR, "Failed to detect too long write to buffer.");
		}

		random.setReadOnly(true);
		detected = false;
		try {
			random.fillRandom(4);
		} catch (...) {
			detected = true;
		}
		if (!detected) {
			throw MolchException(BUFFER_ERROR, "Failed to prevent write to readonly buffer.");
		}

		//test xor
		Buffer text("Hello World!");
		Buffer to_xor(text.content_length, text.content_length);
		to_xor.cloneFrom(text);

		Buffer random2(text.content_length, text.content_length);
		random2.fillRandom(random2.getBufferLength());

		//xor random data to xor-buffer
		to_xor.xorWith(random2);

		//make sure that xor doesn't contain either 'text' or 'random2'
		if ((to_xor == text) || (to_xor == random2)) {
			throw MolchException(BUFFER_ERROR, "ERROR: xor buffer contains 'text' or 'random2'.");
		}

		//xor the buffer with text again to get out the random data
		to_xor.xorWith(text);

		//xor should now contain the same as random2
		if (to_xor != random2) {
			throw MolchException(BUFFER_ERROR, "ERROR: Failed to xor buffers properly.");
		}
		printf("Successfully tested xor.\n");

		//test creating a buffer with an existing array
		unsigned char array[] = "Hello World!\n";
		Buffer buffer_with_array(array, sizeof(array));
		if ((buffer_with_array.content != array)
				|| (buffer_with_array.content_length != sizeof(array))
				|| (buffer_with_array.getBufferLength() != sizeof(array))) {
			throw MolchException(BUFFER_ERROR, "Failed to create buffer with existing array.");
		}

		//compare buffer to an array
		Buffer true_buffer("true");
		int status = true_buffer.compareToRaw(reinterpret_cast<const unsigned char*>("true"), sizeof("true"));
		if (status != 0) {
			throw MolchException(BUFFER_ERROR, "Failed to compare buffer to array.");
		}
		status = true_buffer.compareToRaw(reinterpret_cast<const unsigned char*>("fals"), sizeof("fals"));
		if (status == 0) {
			throw MolchException(BUFFER_ERROR, "Failed to detect difference in buffer and array.");
		}
		status = true_buffer.compareToRaw(reinterpret_cast<const unsigned char*>("false"), sizeof("false"));
		if (status == 0) {
			throw MolchException(BUFFER_ERROR, "ERROR: Failed to detect difference in buffer and array.");
		}

		//test custom allocator
		Buffer custom_allocated(10, 10, sodium_malloc, sodium_free);
		Buffer custom_allocated_empty_buffer(0, 0, malloc, free);
		if (custom_allocated_empty_buffer.content != nullptr) {
			throw MolchException(BUFFER_ERROR, "Customly allocated empty buffer has content.");
		}

		Buffer four_two(4, 2);
		if ((!four_two.fits(4)) || (!four_two.fits(2)) || four_two.fits(5)) {
			throw MolchException(BUFFER_ERROR, "Buffer doesn't detect correctly what fits in it.");
		}

		if ((!four_two.contains(2)) || four_two.contains(1) || four_two.contains(3)) {
			throw MolchException(BUFFER_ERROR, "Buffer doesn't detect correctly what it contains.");
		}
	} catch (const MolchException& exception) {
		exception.print(std::cerr) << std::endl;
		return EXIT_FAILURE;
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
