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
#include <string.h>
#include <sodium.h>

#include "../key-derivation.h"
#include "../utils.h"

int main(void) {
	sodium_init();

	//create random chain key
	unsigned char chain_key[crypto_auth_BYTES];
	randombytes_buf(chain_key, crypto_auth_BYTES);

	//print first chain key
	printf("Chain key (%i Bytes):\n", crypto_auth_BYTES);
	print_hex(chain_key, crypto_auth_BYTES, 30);
	putchar('\n');

	int status;


	//derive message key from chain key
	unsigned char message_key[crypto_auth_BYTES];
	status = derive_message_key(message_key, chain_key);
	sodium_memzero(chain_key, crypto_auth_BYTES);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to derive message key. (%i)\n", status);
		sodium_memzero(message_key, crypto_auth_BYTES);
		return status;
	}

	//print message key
	printf("Message key (%i Bytes):\n", crypto_auth_BYTES);
	print_hex(message_key, crypto_auth_BYTES, 30);
	putchar('\n');

	sodium_memzero(message_key, crypto_auth_BYTES);
	return EXIT_SUCCESS;
}
