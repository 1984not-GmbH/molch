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
	sodium_init();

	//create ephemeral key
	unsigned char our_public_ephemeral_key[crypto_box_PUBLICKEYBYTES];
	randombytes_buf(our_public_ephemeral_key, sizeof(our_public_ephemeral_key));
	printf("Our public ephemeral key (%zi Bytes):\n", sizeof(our_public_ephemeral_key));
	print_hex(our_public_ephemeral_key, sizeof(our_public_ephemeral_key), 30);

	//message numbers
	uint32_t message_number = 2;
	uint32_t previous_message_number = 10;
	printf("Message number: %u\n", message_number);
	printf("Previous message number: %u\n", previous_message_number);
	putchar('\n');

	//create the header
	unsigned char header[crypto_box_PUBLICKEYBYTES + 8];
	header_construct(
			header,
			our_public_ephemeral_key,
			message_number,
			previous_message_number);

	//print the header
	printf("Header (%zi Bytes):\n", sizeof(header));
	print_hex(header, sizeof(header), 30);
	putchar('\n');

	//get data back out of the header again
	unsigned char extracted_public_ephemeral_key[crypto_box_PUBLICKEYBYTES];
	uint32_t extracted_message_number;
	uint32_t extracted_previous_message_number;
	header_extract(
			header,
			extracted_public_ephemeral_key,
			&extracted_message_number,
			&extracted_previous_message_number);

	printf("Extracted public ephemeral key (%zi Bytes):\n", sizeof(extracted_public_ephemeral_key));
	print_hex(extracted_public_ephemeral_key, sizeof(extracted_public_ephemeral_key), 30);
	printf("Extracted message number: %u\n", extracted_message_number);
	printf("Extracted previous message number: %u\n", extracted_previous_message_number);
	putchar('\n');

	//compare them
	if (sodium_memcmp(our_public_ephemeral_key, extracted_public_ephemeral_key, sizeof(our_public_ephemeral_key)) != 0) {
		fprintf(stderr, "ERROR: Public ephemeral keys don't match.\n");
		return EXIT_FAILURE;
	}
	printf("Public ephemeral keys match.\n");

	if (message_number != extracted_message_number) {
		fprintf(stderr, "ERROR: Message numbers don't match.\n");
		return EXIT_FAILURE;
	}
	printf("Message numbers match.\n");

	if (previous_message_number != extracted_previous_message_number) {
		fprintf(stderr, "ERROR: Message numbers don't match.\n");
		return EXIT_FAILURE;
	}
	printf("Previous message numbers match.\n");

	return EXIT_SUCCESS;
}
