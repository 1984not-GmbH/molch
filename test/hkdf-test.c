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
	sodium_init();

	printf("HKDF as described in RFC 5869 based on HMAC-SHA512256!\n\n");

	buffer_t *output_key = buffer_create(200, 0);

	//create random salt
	buffer_t *salt = buffer_create(crypto_auth_KEYBYTES, crypto_auth_KEYBYTES);
	randombytes_buf(salt->content, salt->content_length);
	printf("Salt (%zi Bytes):\n", salt->content_length);
	print_hex(salt->content, salt->content_length, 30);
	putchar('\n');

	//create key to derive from
	buffer_t *input_key = buffer_create(100, 100);
	randombytes_buf(input_key->content, input_key->content_length);
	printf("Input key (%zu Bytes):\n", input_key->content_length);
	print_hex(input_key->content, input_key->content_length, 30);
	putchar('\n');

	//info
	const unsigned char info_string[] = "This is some info!";
	buffer_t *info = buffer_create(sizeof(info_string), sizeof(info_string));
	buffer_clone_from_raw(info, info_string, sizeof(info_string));
	printf("Info (%zu Bytes):\n", info->content_length); //this could also be binary data
	printf("%s\n\n", info->content);

	int status;
	status = hkdf(output_key, output_key->buffer_length, salt, input_key, info);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to derive key. %i\n", status);
		return EXIT_FAILURE;
	}

	printf("Derived key (%zu Bytes):\n", output_key->content_length);
	print_hex(output_key->content, output_key->content_length, 30);
	putchar('\n');
	return EXIT_SUCCESS;
}
