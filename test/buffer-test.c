/* Molch, an implementation of the axolotl ratchet based on libsodium
 *  Copyright (C) 2015  Max Bruckner (FSMaxB)
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>
#include <string.h>
#include <assert.h>

#include "../lib/buffer.h"
#include "utils.h"

int main(void) {
	sodium_init();

	//create a new buffer
	buffer_t *buffer1 = buffer_create(14, 10);
	unsigned char buffer1_content[10];
	randombytes_buf(buffer1_content, sizeof(buffer1_content));
	memcpy(buffer1->content, buffer1_content, sizeof(buffer1_content));
	printf("Here\n");

	printf("Random buffer (%zi Bytes):\n", buffer1->content_length);
	print_hex(buffer1->content, buffer1->content_length, 30);
	putchar('\n');

	//make second buffer
	buffer_t *buffer2 = buffer_create(5, 4);
	buffer2->content[0] = 0xde;
	buffer2->content[1] = 0xad;
	buffer2->content[2] = 0xbe;
	buffer2->content[3] = 0xef;

	printf("Second buffer (%zi Bytes):\n", buffer2->content_length);
	print_hex(buffer2->content, buffer2->content_length, 30);
	putchar('\n');

	//concatenate buffers
	printf("Concatenating buffers!\n");
	int status = buffer_concat(buffer1, buffer2);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to concatenate both buffers. (%i)\n", status);
		return status;
	}
	assert(buffer1->content_length == 14);
	print_hex(buffer1->content, buffer1->content_length, 30);
	putchar('\n');

	//check if the buffers were successfully concatenated
	if ((sodium_memcmp(buffer1->content, buffer1_content, sizeof(buffer1_content)) != 0)
			|| (sodium_memcmp(buffer1->content + sizeof(buffer1_content), buffer2->content, buffer2->content_length) !=0)) {
		fprintf(stderr, "ERROR: Failed to concatenate buffers.\n");
		return EXIT_FAILURE;
	}
	printf("Buffers successfully concatenated.\n");

	//concatenate buffers that are to long
	status = buffer_concat(buffer1, buffer2);
	if (status == 0) {
		fprintf(stderr, "ERROR: Concatenated buffers that go over the bounds.\n");
		return EXIT_FAILURE;
	}
	printf("Detected out of bounds buffer concatenation.\n");

	//TODO check readonly

	//copy buffer
	buffer_t *buffer3 = buffer_create(5,0);
	status = buffer_copy(buffer3, 0, buffer2, 0, buffer2->content_length);
	if ((status != 0) || (sodium_memcmp(buffer2->content, buffer3->content, buffer2->content_length) != 0)) {
		fprintf(stderr, "ERROR: Failed to copy buffer. (%i)\n", status);
		return EXIT_FAILURE;
	}

	printf("Buffer successfully copied.\n");

	status = buffer_copy(buffer3, buffer2->content_length, buffer2, 0, buffer2->content_length);
	if (status == 0) {
		fprintf(stderr, "ERROR: Copied buffer that out of bounds.\n");
		return EXIT_FAILURE;
	}
	printf("Detected out of bounds buffer copying.\n");

	status = buffer_copy(buffer3, 1, buffer2, 0, buffer2->content_length);
	if ((status != 0) || (buffer3->content[0] != buffer2->content[0]) || (sodium_memcmp(buffer2->content, buffer3->content + 1, buffer2->content_length) != 0)) {
		fprintf(stderr, "ERROR: Failed to copy buffer. (%i)\n", status);
		return EXIT_FAILURE;
	}
	printf("Successfully copied buffer.\n");


	//erase the buffer
	printf("Erasing buffer.\n");
	buffer_clear(buffer1);

	//check if the buffer was properly cleared
	size_t i;
	for (i = 0; i < buffer1->buffer_length; i++) {
		if (buffer1->content[i] != '\0') {
			fprintf(stderr, "ERROR: Byte %zi of the buffer hasn't been erased.\n", i);
			return EXIT_FAILURE;
		}
	}

	if (buffer1->content_length != 0) {
		fprintf(stderr, "ERROR: The content length of the buffer hasn't been set to zero.\n");
		return EXIT_FAILURE;
	}
	printf("Buffer successfully erased.\n");

	return EXIT_SUCCESS;
}
