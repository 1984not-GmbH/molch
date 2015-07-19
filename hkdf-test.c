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

#include "hkdf.h"
#include "utils.h"

int main(void) {
	sodium_init();

	printf("HKDF as described in RFC 5869 based on HMAC-SHA512256!\n\n");

	unsigned char output_key[200];
	unsigned int output_key_length = sizeof(output_key);

	//create random salt
	unsigned char salt[crypto_auth_KEYBYTES];
	randombytes_buf(salt, crypto_auth_KEYBYTES);
	printf("Salt (%i Bytes):\n", crypto_auth_KEYBYTES);
	print_hex(salt, crypto_auth_KEYBYTES, 30);
	putchar('\n');

	//create key to derive from
	unsigned char input_key[100];
	unsigned int input_key_length = sizeof(input_key);
	randombytes_buf(input_key, input_key_length);
	printf("Input key (%i Bytes):\n", input_key_length);
	print_hex(input_key, input_key_length, 30);
	putchar('\n');

	//info
	unsigned char* info = "This is some info!";
	unsigned int info_length = sizeof(info);
	printf("Info (%i Bytes):\n", info_length); //this could also be binary data
	printf("%s\n\n", info);

	int status;
	status = hkdf(output_key, output_key_length, salt, input_key, input_key_length, info, info_length);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to derive key. %i\n", status);
		return EXIT_FAILURE;
	}

	printf("Derived key (%i Bytes):\n", output_key_length);
	print_hex(output_key, output_key_length, 30);
	putchar('\n');
	return EXIT_SUCCESS;
}
