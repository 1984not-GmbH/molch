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

	//create random initial chain key
	unsigned char last_chain_key[crypto_auth_BYTES];
	randombytes_buf(last_chain_key, crypto_auth_BYTES);

	//print first chain key
	printf("Initial chain key (%i Bytes):\n", crypto_auth_BYTES);
	print_hex(last_chain_key, crypto_auth_BYTES, 30);
	putchar('\n');

	int status;

	//buffer for derived chain keys
	unsigned char next_chain_key[crypto_auth_BYTES];

	//derive a chain of chain keys
	unsigned int counter;
	for (counter = 1; counter <= 5; counter++) {
		status = derive_chain_key(next_chain_key, last_chain_key);
		if (status != 0) {
			fprintf(stderr, "ERROR: Failed to derive chain key %i. (%i)\n", counter, status);
			sodium_memzero(last_chain_key, crypto_auth_BYTES);
			sodium_memzero(next_chain_key, crypto_auth_BYTES);
			return status;
		}

		//print the derived chain key
		printf("Chain key Nr. %i:\n", counter);
		print_hex(next_chain_key, crypto_auth_BYTES, 30);
		putchar('\n');

		//check that chain keys are different
		status = sodium_memcmp(last_chain_key, next_chain_key, crypto_auth_BYTES);
		if (status == 0) {
			fprintf(stderr, "ERROR: Derived chain key is identical. (%i)\n", status);
			sodium_memzero(last_chain_key, crypto_auth_BYTES);
			sodium_memzero(next_chain_key, crypto_auth_BYTES);
			return -5;
		}

		//move next_chain_key to last_chain_key
		memcpy(last_chain_key, next_chain_key, crypto_auth_BYTES);
	}

	sodium_memzero(last_chain_key, crypto_auth_BYTES);
	sodium_memzero(next_chain_key, crypto_auth_BYTES);
	return EXIT_SUCCESS;
}
