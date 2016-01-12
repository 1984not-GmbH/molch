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

#include "../lib/hkdf.h"
#include "utils.h"

int main(void) {
	if (sodium_init() == -1) {
		return -1;
	}

	printf("HKDF as described in RFC 5869 based on HMAC-SHA512256!\n\n");

	//create buffers
	buffer_t *output_key = buffer_create_on_heap(200, 0);
	buffer_t *salt = buffer_create_on_heap(crypto_auth_KEYBYTES, crypto_auth_KEYBYTES);
	buffer_t *input_key = buffer_create_on_heap(100, 100);
	buffer_t *empty = buffer_create_on_heap(0, 0);

	//create random salt
	randombytes_buf(salt->content, salt->content_length);
	printf("Salt (%zu Bytes):\n", salt->content_length);
	print_hex(salt);
	putchar('\n');

	//create key to derive from
	randombytes_buf(input_key->content, input_key->content_length);
	printf("Input key (%zu Bytes):\n", input_key->content_length);
	print_hex(input_key);
	putchar('\n');

	//info
	int status;
	buffer_create_from_string(info, "This is some info!");
	printf("Info (%zu Bytes):\n", info->content_length); //this could also be binary data
	printf("%s\n\n", info->content);

	status = hkdf(output_key, output_key->buffer_length, salt, input_key, info);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to derive key. %i\n", status);
		goto cleanup;
	}

	printf("Derived key (%zu Bytes):\n", output_key->content_length);
	print_hex(output_key);
	putchar('\n');

	//check for crash with 0 length output
	status = hkdf(empty, empty->buffer_length, salt, input_key, info);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to derive key. %i\n", status);
		goto cleanup;
	}

cleanup:
	buffer_destroy_from_heap(output_key);
	buffer_destroy_from_heap(salt);
	buffer_destroy_from_heap(input_key);
	buffer_destroy_from_heap(empty);

	return status;
}
