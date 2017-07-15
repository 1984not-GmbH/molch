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
#include <cstdio>
#include <cstdlib>
#include <sodium.h>
#include <cassert>

#include "../lib/buffer.h"
#include "../lib/common.h"
#include "utils.h"

int main(void) {
	int status = EXIT_SUCCESS;

	//test comparison function
	buffer_create_from_string(string1, "1234");
	buffer_create_from_string(string2, "1234");
	buffer_create_from_string(string3, "2234");
	buffer_create_from_string(string4, "12345");
	Buffer *buffer1 = NULL;
	Buffer *buffer2 = NULL;
	Buffer *buffer3 = NULL;
	Buffer *empty = NULL;
	Buffer *empty2 = NULL;
	Buffer *empty3 = NULL;
	Buffer *random = NULL;
	Buffer *random2 = NULL;
	Buffer *to_xor = NULL;
	Buffer *character_buffer = NULL;
	Buffer *heap_buffer = NULL;
	Buffer *custom_allocated_empty_buffer = NULL;
	Buffer *custom_allocated = NULL;

	if (sodium_init() == -1) {
		fprintf(stderr, "ERROR: Failed to initialize libsodium!\n");
		goto fail;
	}

	if (!string1->isReadOnly()) {
		fprintf(stderr, "ERROR: buffer_create_from_string doesn't create readonly buffers.\n");
		goto fail;
	}

	if ((string1->compare(string2) != 0)
			|| (string1->compare(string3) != -1)
			|| (string1->compare(string4) != -1)) {
		fprintf(stderr, "ERROR: buffer_compare doesn't work as expected\n");

		goto fail;
	}

	if ((string1->comparePartial(0, string4, 0, 4) != 0)
			|| (string1->comparePartial(2, string3, 2, 2) != 0)) {
		fprintf(stderr, "ERROR: buffer_compare_partial doesn't work as expected\n");
		goto fail;
	}
	printf("Successfully tested buffer comparison ...\n");

	//test heap allocated buffers
	heap_buffer = Buffer::create(10, 0);
	heap_buffer->destroy_from_heap();

	//zero length heap buffer
	heap_buffer = Buffer::create(0, 0);
	heap_buffer->destroy_from_heap();

	//create a new buffer
	buffer1 = Buffer::create(14, 10);
	unsigned char buffer1_content[10];
	randombytes_buf(buffer1_content, sizeof(buffer1_content));
	std::copy(buffer1_content, buffer1_content + sizeof(buffer1_content), buffer1->content);
	printf("Here\n");

	printf("Random buffer (%zu Bytes):\n", buffer1->content_length);
	print_hex(buffer1);
	putchar('\n');

	//make second buffer (from pointer)
	buffer2 = ((Buffer*)malloc(sizeof(Buffer)))->init((unsigned char*)malloc(5), 5, 4);
	buffer2->content[0] = 0xde;
	buffer2->content[1] = 0xad;
	buffer2->content[2] = 0xbe;
	buffer2->content[3] = 0xef;

	printf("Second buffer (%zu Bytes):\n", buffer2->content_length);
	print_hex(buffer2);
	putchar('\n');

	empty = Buffer::create(0, 0);
	empty2 = Buffer::create(0, 0);
	status = empty2->cloneFrom(empty);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to clone empty buffer.\n");
		goto fail;
	}

	//copy buffer
	buffer3 = Buffer::create(5,0);
	status = buffer3->copyFrom(0, buffer2, 0, buffer2->content_length);
	if ((status != 0) || (buffer2->compare(buffer3) != 0)) {
		fprintf(stderr, "ERROR: Failed to copy buffer. (%i)\n", status);
		goto fail;
	}
	printf("Buffer successfully copied.\n");

	status = buffer3->copyFrom(buffer2->content_length, buffer2, 0, buffer2->content_length);
	if (status == 0) {
		fprintf(stderr, "ERROR: Copied buffer that out of bounds.\n");
		goto fail;
	}
	printf("Detected out of bounds buffer copying.\n");

	status = buffer3->copyFrom(1, buffer2, 0, buffer2->content_length);
	if ((status != 0) || (buffer3->content[0] != buffer2->content[0]) || (sodium_memcmp(buffer2->content, buffer3->content + 1, buffer2->content_length) != 0)) {
		fprintf(stderr, "ERROR: Failed to copy buffer. (%i)\n", status);
		goto fail;
	}
	printf("Successfully copied buffer.\n");

	//copy to a raw array
	{
		unsigned char raw_array[4];
		status = buffer1->copyToRaw(
				raw_array, //destination
				0, //destination offset
				1, //source offset
				4); //length
		if ((status != 0) || (sodium_memcmp(raw_array, buffer1->content + 1, 4) != 0)) {
			fprintf(stderr, "ERROR: Failed to copy buffer to raw array. (%i)\n", status);
			goto fail;
		}
		printf("Successfully copied buffer to raw array.\n");

		status = buffer2->copyToRaw(
				raw_array,
				0,
				3,
				4);
		if (status == 0) {
			fprintf(stderr, "ERROR: Failed to detect out of bounds read!\n");
			goto fail;
		}
		printf("Successfully detected out of bounds read.\n");
	}

	//copy from raw array
	{
		unsigned char heeelo[14] = "Hello World!\n";
		status = buffer1->copyFromRaw(
				0, //offset
				heeelo, //source
				0, //offset
				sizeof(heeelo)); //length
		if ((status != 0) || (sodium_memcmp(heeelo, buffer1->content, sizeof(heeelo)))) {
			fprintf(stderr, "ERROR: Failed to copy from raw array to buffer. (%i)\n", status);
			goto fail;
		}
		printf("Successfully copied raw array to buffer.\n");

		status = buffer1->copyFromRaw(
				1,
				heeelo,
				0,
				sizeof(heeelo));
		if (status == 0) {
			fprintf(stderr, "ERROR: Failed to detect out of bounds read.\n");
			goto fail;
		}
		printf("Out of bounds read detected.\n");
	}

	//create a buffer from a string
	buffer_create_from_string(string, "This is a string!");
	if (string->content_length != sizeof("This is a string!")) {
		fprintf(stderr, "ERROR: Buffer created from string has incorrect length.\n");
		goto fail;
	}
	if (sodium_memcmp(string->content, "This is a string!", string->content_length) != 0) {
		fprintf(stderr, "ERROR: Failed to create buffer from string.\n");
		goto fail;
	}
	printf("Successfully created buffer from string.\n");

	//erase the buffer
	printf("Erasing buffer.\n");
	buffer1->clear();

	//check if the buffer was properly cleared
	size_t i;
	for (i = 0; i < buffer1->getBufferLength(); i++) {
		if (buffer1->content[i] != '\0') {
			fprintf(stderr, "ERROR: Byte %zu of the buffer hasn't been erased.\n", i);
			goto fail;
		}
	}

	if (buffer1->content_length != 0) {
		fprintf(stderr, "ERROR: The content length of the buffer hasn't been set to zero.\n");
		goto fail;
	}
	printf("Buffer successfully erased.\n");

	//fill a buffer with random numbers
	random = Buffer::create(10, 0);
	status = random->fillRandom(5);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to fill buffer with random numbers. (%i)\n", status);
		goto fail;
	}

	if (random->content_length != 5) {
		fprintf(stderr, "ERROR: Wrong content length.\n");
		goto fail;
	}
	printf("Buffer with %zu random bytes:\n", random->content_length);
	print_hex(random);

	if (random->fillRandom(20) == 0) {
		fprintf(stderr, "ERROR: Failed to detect too long write to buffer.\n");
		goto fail;
	}

	random->setReadOnly(true);
	if (random->fillRandom(4) == 0) {
		fprintf(stderr, "ERROR: Failed to prevent write to readonly buffer.\n");
		goto fail;
	}

	//test xor
	buffer_create_from_string(text, "Hello World!");
	to_xor = Buffer::create(text->content_length, text->content_length);
	status = to_xor->cloneFrom(text);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to clone buffer.\n");
		goto fail; /* not fail, because status is set */
	}

	random2 = Buffer::create(text->content_length, text->content_length);
	status = random2->fillRandom(random2->getBufferLength());
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to fill buffer with random data. (%i)\n", status);
		goto fail;
	}

	//xor random data to xor-buffer
	status = to_xor->xorWith(random2);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to xor buffers. (%i)\n", status);
		goto fail;
	}

	//make sure that xor doesn't contain either 'text' or 'random2'
	if ((to_xor->compare(text) == 0) || (to_xor->compare(random2) == 0)) {
		fprintf(stderr, "ERROR: xor buffer contains 'text' or 'random2'\n");
		goto fail;
	}

	//xor the buffer with text again to get out the random data
	status = to_xor->xorWith(text);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to xor buffers. (%i)\n", status);
		goto fail;
	}

	//xor should now contain the same as random2
	if (to_xor->compare(random2) != 0) {
		fprintf(stderr, "ERROR: Failed to xor buffers properly.\n");
		goto fail;
	}
	printf("Successfully tested xor.\n");

	//test creating a buffer with an existing array
	{
		unsigned char array[] = "Hello World!\n";
		buffer_create_with_existing_array(buffer_with_array, array, sizeof(array));
		if ((buffer_with_array->content != array)
				|| (buffer_with_array->content_length != sizeof(array))
				|| (buffer_with_array->getBufferLength() != sizeof(array))) {
			fprintf(stderr, "ERROR: Failed to create buffer with existing array.\n");
			goto fail;
		}
	}

	//compare buffer to an array
	buffer_create_from_string(true_buffer, "true");
	status = true_buffer->compareToRaw((const unsigned char*)"true", sizeof("true"));
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to compare buffer to array! (%i)\n", status);
		goto fail;
	}
	status = true_buffer->compareToRaw((const unsigned char*)"fals", sizeof("fals"));
	if (status != -1) {
		fprintf(stderr, "ERROR: Failed to detect difference in buffer and array.\n");
		goto fail;
	}
	status = true_buffer->compareToRaw((const unsigned char*)"false", sizeof("false"));
	if (status != -1) {
		fprintf(stderr, "ERROR: Failed to detect difference in buffer and array.\n");
		goto fail;
	}
	status = 0;

	//test custom allocator
	custom_allocated = Buffer::createWithCustomAllocator(10, 10, sodium_malloc, sodium_free);
	if (custom_allocated == nullptr) {
		fprintf(stderr, "ERROR: Failed to create buffer with custom allocator!\n");
		goto fail;
	}

	custom_allocated_empty_buffer = Buffer::createWithCustomAllocator(0, 0, malloc, free);
	if (custom_allocated_empty_buffer == nullptr) {
		fprintf(stderr, "ERROR: Failed to customly allocate empty buffer.\n");
		goto fail;
	}
	if (custom_allocated_empty_buffer->content != nullptr) {
		fprintf(stderr, "ERROR: Customly allocated empty buffer has content.\n");
		goto fail;
	}

	goto cleanup;

fail:
	status = EXIT_FAILURE;
cleanup:
	buffer_destroy_from_heap_and_null_if_valid(buffer1);
	buffer_destroy_from_heap_and_null_if_valid(buffer2);
	buffer_destroy_from_heap_and_null_if_valid(buffer3);
	buffer_destroy_from_heap_and_null_if_valid(empty);
	buffer_destroy_from_heap_and_null_if_valid(empty2);
	buffer_destroy_from_heap_and_null_if_valid(empty3);
	buffer_destroy_from_heap_and_null_if_valid(random);
	buffer_destroy_from_heap_and_null_if_valid(random2);
	buffer_destroy_from_heap_and_null_if_valid(to_xor);
	buffer_destroy_from_heap_and_null_if_valid(character_buffer);
	buffer_destroy_with_custom_deallocator_and_null_if_valid(custom_allocated_empty_buffer, free);
	buffer_destroy_with_custom_deallocator_and_null_if_valid(custom_allocated, sodium_free);

	return status;
}
