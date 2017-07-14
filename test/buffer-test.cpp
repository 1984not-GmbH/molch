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

static void print_hex(Buffer *data) {
	Buffer *hex = buffer_create_on_heap(2 * data->content_length + 1, 2 * data->content_length + 1);
	if (hex == NULL) {
		fprintf(stderr, "ERROR: Failed to create hex buffer.\n");
		exit(-1);
	}
	int status = Buffero_hex(hex, data);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to print data as hex! (%i)\n", status);
		exit(-1);
	}
	printf("%.*s\n", (int)hex->content_length, hex->content);

	buffer_destroy_from_heap_and_null_if_valid(hex);
}

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
	Buffer *set_buffer = NULL;
	Buffer *newline_hex = NULL;
	Buffer *newline2 = NULL;
	Buffer *heap_buffer = NULL;
	Buffer *string_on_heap = NULL;
	Buffer *custom_allocated_empty_buffer = NULL;
	Buffer *buffer_to_be_filled = NULL;
	Buffer *custom_allocated = NULL;

	if (sodium_init() == -1) {
		fprintf(stderr, "ERROR: Failed to initialize libsodium!\n");
		goto fail;
	}

	if (!string1->isReadOnly()) {
		fprintf(stderr, "ERROR: buffer_create_from_string doesn't create readonly buffers.\n");
		goto fail;
	}

	if ((buffer_compare(string1, string2) != 0)
			|| (buffer_compare(string1, string3) != -1)
			|| (buffer_compare(string1, string4) != -1)) {
		fprintf(stderr, "ERROR: buffer_compare doesn't work as expected\n");

		goto fail;
	}

	if ((buffer_compare_partial(string1, 0, string4, 0, 4) != 0)
			|| (buffer_compare_partial(string1, 2, string3, 2, 2) != 0)) {
		fprintf(stderr, "ERROR: buffer_compare_partial doesn't work as expected\n");
		goto fail;
	}
	if ((buffer_compare_to_raw_partial(string1, 0, string4->content, string4->content_length, 0, 4) != 0)
			|| (buffer_compare_to_raw_partial(string1, 2, string3->content, string3->content_length, 2, 2) != 0)) {
		fprintf(stderr, "ERROR: buffer_compare_to_raw_partial doesn't work as expected\n");
		goto fail;
	}
	printf("Successfully tested buffer comparison ...\n");

	//test heap allocated buffers
	heap_buffer = buffer_create_on_heap(10, 0);
	heap_buffer->destroy_from_heap();

	//zero length heap buffer
	heap_buffer = buffer_create_on_heap(0, 0);
	heap_buffer->destroy_from_heap();

	//create a new buffer
	buffer1 = buffer_create_on_heap(14, 10);
	unsigned char buffer1_content[10];
	randombytes_buf(buffer1_content, sizeof(buffer1_content));
	std::copy(buffer1_content, buffer1_content + sizeof(buffer1_content), buffer1->content);
	printf("Here\n");

	printf("Random buffer (%zu Bytes):\n", buffer1->content_length);
	print_hex(buffer1);
	putchar('\n');

	//make second buffer (from pointer)
	buffer2 = ((Buffer*)malloc(sizeof(Buffer)))->init_with_pointer((unsigned char*)malloc(5), 5, 4);
	buffer2->content[0] = 0xde;
	buffer2->content[1] = 0xad;
	buffer2->content[2] = 0xbe;
	buffer2->content[3] = 0xef;

	printf("Second buffer (%zu Bytes):\n", buffer2->content_length);
	print_hex(buffer2);
	putchar('\n');

	//concatenate buffers
	printf("Concatenating buffers!\n");
	{
		status = buffer_concat(buffer1, buffer2);
		if (status != 0) {
			fprintf(stderr, "ERROR: Failed to concatenate both buffers. (%i)\n", status);
			goto fail;
		}
	}
	assert(buffer1->content_length == 14);
	print_hex(buffer1);
	putchar('\n');

	//check if the buffers were successfully concatenated
	if ((sodium_memcmp(buffer1->content, buffer1_content, sizeof(buffer1_content)) != 0)
			|| (sodium_memcmp(buffer1->content + sizeof(buffer1_content), buffer2->content, buffer2->content_length) !=0)) {
		fprintf(stderr, "ERROR: Failed to concatenate buffers.\n");
		goto fail;
	}
	printf("Buffers successfully concatenated.\n");

	//concatenate buffers that are to long
	status = buffer_concat(buffer1, buffer2);
	if (status == 0) {
		fprintf(stderr, "ERROR: Concatenated buffers that go over the bounds.\n");
		goto fail;
	}
	printf("Detected out of bounds buffer concatenation.\n");

	//test empty buffers
	empty = buffer_create_on_heap(0, 0);
	status = buffer_concat(buffer1, empty);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to concatenate empty buffer to buffer.\n");
		goto fail;
	}
	empty2 = buffer_create_on_heap(0, 0);
	status = buffer_clone(empty2, empty);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to clone empty buffer.\n");
		goto fail;
	}
	//TODO more tests with empty buffers
	//FIXME Yeah this needs to be done ASAP!!!!!!!!!!!!!

	//TODO check readonly
	//TODO check content lengths
	//TODO test buffer clone functions

	//copy buffer
	buffer3 = buffer_create_on_heap(5,0);
	status = buffer_copy(buffer3, 0, buffer2, 0, buffer2->content_length);
	if ((status != 0) || (buffer_compare(buffer2, buffer3) != 0)) {
		fprintf(stderr, "ERROR: Failed to copy buffer. (%i)\n", status);
		goto fail;
	}
	printf("Buffer successfully copied.\n");

	status = buffer_copy(buffer3, buffer2->content_length, buffer2, 0, buffer2->content_length);
	if (status == 0) {
		fprintf(stderr, "ERROR: Copied buffer that out of bounds.\n");
		goto fail;
	}
	printf("Detected out of bounds buffer copying.\n");

	status = buffer_copy(buffer3, 1, buffer2, 0, buffer2->content_length);
	if ((status != 0) || (buffer3->content[0] != buffer2->content[0]) || (sodium_memcmp(buffer2->content, buffer3->content + 1, buffer2->content_length) != 0)) {
		fprintf(stderr, "ERROR: Failed to copy buffer. (%i)\n", status);
		goto fail;
	}
	printf("Successfully copied buffer.\n");

	//copy to a raw array
	{
		unsigned char raw_array[4];
		status = buffer_copy_to_raw(
				raw_array, //destination
				0, //destination offset
				buffer1, //source
				1, //source offset
				4); //length
		if ((status != 0) || (sodium_memcmp(raw_array, buffer1->content + 1, 4) != 0)) {
			fprintf(stderr, "ERROR: Failed to copy buffer to raw array. (%i)\n", status);
			goto fail;
		}
		printf("Successfully copied buffer to raw array.\n");

		status = buffer_copy_to_raw(
				raw_array,
				0,
				buffer2,
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
		status = buffer_copy_from_raw(
				buffer1, //destination
				0, //offset
				heeelo, //source
				0, //offset
				sizeof(heeelo)); //length
		if ((status != 0) || (sodium_memcmp(heeelo, buffer1->content, sizeof(heeelo)))) {
			fprintf(stderr, "ERROR: Failed to copy from raw array to buffer. (%i)\n", status);
			goto fail;
		}
		printf("Successfully copied raw array to buffer.\n");

		status = buffer_copy_from_raw(
				buffer1,
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
	random = buffer_create_on_heap(10, 0);
	status = buffer_fill_random(random, 5);
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

	if (buffer_fill_random(random, 20) == 0) {
		fprintf(stderr, "ERROR: Failed to detect too long write to buffer.\n");
		goto fail;
	}

	random->setReadOnly(true);
	if (buffer_fill_random(random, 4) == 0) {
		fprintf(stderr, "ERROR: Failed to prevent write to readonly buffer.\n");
		goto fail;
	}

	//test xor
	buffer_create_from_string(text, "Hello World!");
	to_xor = buffer_create_on_heap(text->content_length, text->content_length);
	status = buffer_clone(to_xor, text);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to clone buffer.\n");
		goto fail; /* not fail, because status is set */
	}

	random2 = buffer_create_on_heap(text->content_length, text->content_length);
	status = buffer_fill_random(random2, random2->getBufferLength());
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to fill buffer with random data. (%i)\n", status);
		goto fail;
	}

	//xor random data to xor-buffer
	status = buffer_xor(to_xor, random2);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to xor buffers. (%i)\n", status);
		goto fail;
	}

	//make sure that xor doesn't contain either 'text' or 'random2'
	if ((buffer_compare(to_xor, text) == 0) || (buffer_compare(to_xor, random2) == 0)) {
		fprintf(stderr, "ERROR: xor buffer contains 'text' or 'random2'\n");
		goto fail;
	}

	//xor the buffer with text again to get out the random data
	status = buffer_xor(to_xor, text);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to xor buffers. (%i)\n", status);
		goto fail;
	}

	//xor should now contain the same as random2
	if (buffer_compare(to_xor, random2) != 0) {
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

		//test reading a buffer at ->position
		buffer_with_array->position = 4;
		if (buffer_get_at_pos(buffer_with_array) != 'o') {
			fprintf(stderr, "ERROR: Failed to access buffer at ->position.\n");
			goto fail;
		}
		buffer_with_array->position = 20;
		if (buffer_get_at_pos(buffer_with_array) != '\0') {
			fprintf(stderr, "ERROR: Failed to prevent out of bounds read when accessing buffer at position.\n");
			goto fail;
		}

		//test writing a buffer at ->position
		buffer_with_array->position = 4;
		status = buffer_set_at_pos(buffer_with_array, '0');
		if (status != 0) {
			fprintf(stderr, "ERROR: Failed to write to buffer at ->position. (%i)\n", status);
			goto fail;
		}
		if (buffer_with_array->content[buffer_with_array->position] != '0') {
			fprintf(stderr, "ERROR: Failed to write to buffer at ->position. (%i)\n", status);
			goto fail;
		}
		buffer_with_array->position = 20;
		if (buffer_set_at_pos(buffer_with_array, 'x') == 0) {
			fprintf(stderr, "ERROR: Failed to detect out of bounds write at ->position.\n");
			goto fail;
		}
	}

	//test character access
	character_buffer = buffer_create_on_heap(4,3);
	buffer_create_from_string(test_buffer, "Hi");
	status = buffer_set_at(character_buffer, 0, 'H');
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to set character at given position. (%i)\n", status);
		goto fail;
	}
	status = buffer_set_at(character_buffer, 1, 'i');
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to set character at given position. (%i)\n", status);
		goto fail;
	}
	status = buffer_set_at(character_buffer, 2, '\0');
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to set character at given position. (%i)\n", status);
		goto fail;
	}
	status = buffer_set_at(character_buffer, 3, '!');
	if (status == 0) {
		fprintf(stderr, "ERROR: Failed to detect out of bound write to buffer.\n");
		goto fail;
	}
	//compare the bufers
	if (buffer_compare(character_buffer, test_buffer) != 0) {
		fprintf(stderr, "ERROR: Setting characters manually failed!\n");
		goto fail;
	}

	//test memset functions
	set_buffer = buffer_create_on_heap(10, 10);
	buffer_memset(set_buffer, 0x01);
	if (set_buffer->content[3] != 0x01) {
		fprintf(stderr, "ERROR: Failed to memset buffer.\n");
		goto fail;
	}
	status = buffer_memset_partial(set_buffer, 0x02, 5);
	if ((status != 0) || (set_buffer->content[3] != 0x02) || (set_buffer->content[4] != 0x02) || (set_buffer->content[5] != 0x01) || (set_buffer->content_length != 5)) {
		fprintf(stderr, "ERROR: Failed to partially memset buffer.\n");
		goto fail;
	}

	//create buffer from string on heap
	string_on_heap = buffer_create_from_string_on_heap("Hello world!");
	if (sodium_memcmp(string_on_heap->content, "Hello world!", sizeof("Hello world!")) != 0) {
		fprintf(stderr, "ERROR: Failed to create buffer from string on heap!\n");
		goto fail;
	}

	//compare buffer to an array
	buffer_create_from_string(true_buffer, "true");
	status = buffer_compare_to_raw(true_buffer, (const unsigned char*)"true", sizeof("true"));
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to compare buffer to array! (%i)\n", status);
		goto fail;
	}
	status = buffer_compare_to_raw(true_buffer, (const unsigned char*)"fals", sizeof("fals"));
	if (status != -1) {
		fprintf(stderr, "ERROR: Failed to detect difference in buffer and array.\n");
		goto fail;
	}
	status = buffer_compare_to_raw(true_buffer, (const unsigned char*)"false", sizeof("false"));
	if (status != -1) {
		fprintf(stderr, "ERROR: Failed to detect difference in buffer and array.\n");
		goto fail;
	}
	status = buffer_compare_to_string(true_buffer, "true");
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to use macro to compare buffer to string! (%i)\n", status);
		goto fail;
	}
	status = buffer_compare_to_raw_partial(true_buffer, 3, (const unsigned char*)"true", sizeof("true"), 0, 3);
	if (status == 0) {
		fprintf(stderr, "ERROR: Failed to detect out of bounds read when comparing buffers!\n");
		goto fail;
	}

	//clone buffer to hex
	buffer_create_from_string(newline, "\r\n");
	newline_hex = buffer_create_on_heap(2 * newline->content_length + 1, 0);

	status = buffer_clone_as_hex(newline_hex, newline);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to clone buffer as hex digits. (%i)\n", status);
		goto fail;
	}

	buffer_create_from_string(cr_newline, "0d0a00");
	if (buffer_compare(cr_newline, newline_hex) != 0) {
		fprintf(stderr, "ERROR: Buffer cloned as hex is incorrect.\n");
		goto fail;
	}
	printf("Hex-Buffer: %.*s\n", (int)newline_hex->content_length, (char*)newline_hex->content);

	//clone buffer from hex
	newline2 = buffer_create_on_heap(sizeof(newline), sizeof(newline));
	status = buffer_clone_from_hex(newline2, newline_hex);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to clone buffer from hex digits. (%i)\n", status);
		goto fail;
	}

	buffer_create_from_string(newline3, "\r\n");
	if (buffer_compare(newline3, newline2) != 0) {
		fprintf(stderr, "ERROR: Buffer cloned from hex is incorrect.\n");
		goto fail;
	}

	//test custom allocator
	custom_allocated = buffer_create_with_custom_allocator(10, 10, sodium_malloc, sodium_free);
	if (custom_allocated == nullptr) {
		fprintf(stderr, "ERROR: Failed to create buffer with custom allocator!\n");
		goto fail;
	}

	//test buffer_fill
	buffer_to_be_filled = buffer_create_on_heap(10, 0);

	buffer_to_be_filled->setReadOnly(true);
	status = buffer_fill(buffer_to_be_filled, 'c', buffer_to_be_filled->getBufferLength());
	if (status != -1) {
		fprintf(stderr, "ERROR: buffer_fill() did not respect the read-only attribute of the buffer. (%i)\n", status);
		goto fail;
	}
	buffer_to_be_filled->setReadOnly(false);

	status = buffer_fill(buffer_to_be_filled, 'c', buffer_to_be_filled->getBufferLength() + 1);
	if (status != -1) {
		fprintf(stderr, "ERROR: buffer_fill() overflowed the buffer. (%i)\n", status);
		goto fail;
	}

	status = buffer_fill(buffer_to_be_filled, 'c', buffer_to_be_filled->getBufferLength());
	if (status != 0) {
		fprintf(stderr, "ERROR: Buffer couldn't be filled with character. (%i)\n", status);
		goto fail;
	}

	{
		unsigned char raw_value[] = {'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c'};
		if (buffer_compare_to_raw(buffer_to_be_filled, raw_value, sizeof(raw_value)) != 0) {
			fprintf(stderr, "ERROR: Buffer didn't contain the correct value after filling.\n");
			goto fail;
		}
	}

	status = buffer_fill(buffer_to_be_filled, 'c', buffer_to_be_filled->getBufferLength() - 1);
	if (status != 0) {
		fprintf(stderr, "ERROR: Buffer couldn't be filled with character. (%i)\n", status);
		goto fail;
	}
	if (buffer_to_be_filled->content_length != (buffer_to_be_filled->getBufferLength() - 1)) {
		fprintf(stderr, "ERROR: Content length wasn't set correctly.\n");
		goto fail;
	}

	custom_allocated_empty_buffer = buffer_create_with_custom_allocator(0, 0, malloc, free);
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
	buffer_destroy_from_heap_and_null_if_valid(set_buffer);
	buffer_destroy_from_heap_and_null_if_valid(newline_hex);
	buffer_destroy_from_heap_and_null_if_valid(newline2);
	buffer_destroy_from_heap_and_null_if_valid(string_on_heap);
	buffer_destroy_from_heap_and_null_if_valid(buffer_to_be_filled);
	buffer_destroy_with_custom_deallocator_and_null_if_valid(custom_allocated_empty_buffer, free);
	buffer_destroy_with_custom_deallocator_and_null_if_valid(custom_allocated, sodium_free);

	return status;
}
