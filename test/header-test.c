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

#include "../lib/header.h"
#include "utils.h"

int main(void) {
	if (sodium_init() == -1) {
		return -1;
	}

	//create buffers
	buffer_t *our_public_ephemeral_key = buffer_create_on_heap(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	buffer_t *header = buffer_create_on_heap(crypto_box_PUBLICKEYBYTES + 8, crypto_box_PUBLICKEYBYTES + 8);
	buffer_t *extracted_public_ephemeral_key = buffer_create_on_heap(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);

	int status;
	//create ephemeral key
	status = buffer_fill_random(our_public_ephemeral_key, our_public_ephemeral_key->content_length);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to create our public ephemeral. (%i)\n", status);
		goto cleanup;
	}
	printf("Our public ephemeral key (%zu Bytes):\n", our_public_ephemeral_key->content_length);
	print_hex(our_public_ephemeral_key);

	//message numbers
	uint32_t message_number = 2;
	uint32_t previous_message_number = 10;
	printf("Message number: %u\n", message_number);
	printf("Previous message number: %u\n", previous_message_number);
	putchar('\n');

	//create the header
	status = header_construct(
			header,
			our_public_ephemeral_key,
			message_number,
			previous_message_number);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to create header. (%i)\n", status);
		goto cleanup;
	}

	//print the header
	printf("Header (%zu Bytes):\n", header->content_length);
	print_hex(header);
	putchar('\n');

	//get data back out of the header again
	uint32_t extracted_message_number;
	uint32_t extracted_previous_message_number;
	status = header_extract(
			header,
			extracted_public_ephemeral_key,
			&extracted_message_number,
			&extracted_previous_message_number);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to extract data from header. (%i)\n", status);
		goto cleanup;
	}

	printf("Extracted public ephemeral key (%zu Bytes):\n", extracted_public_ephemeral_key->content_length);
	print_hex(extracted_public_ephemeral_key);
	printf("Extracted message number: %u\n", extracted_message_number);
	printf("Extracted previous message number: %u\n", extracted_previous_message_number);
	putchar('\n');

	//compare them
	if (buffer_compare(our_public_ephemeral_key, extracted_public_ephemeral_key) != 0) {
		fprintf(stderr, "ERROR: Public ephemeral keys don't match.\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	printf("Public ephemeral keys match.\n");

	if (message_number != extracted_message_number) {
		fprintf(stderr, "ERROR: Message numbers don't match.\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	printf("Message numbers match.\n");

	if (previous_message_number != extracted_previous_message_number) {
		fprintf(stderr, "ERROR: Message numbers don't match.\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	printf("Previous message numbers match.\n");

cleanup:
	buffer_destroy_from_heap(our_public_ephemeral_key);
	buffer_destroy_from_heap(header);
	buffer_destroy_from_heap(extracted_public_ephemeral_key);

	return status;
}
