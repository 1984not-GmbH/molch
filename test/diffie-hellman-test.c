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

#include "../lib/diffie-hellman.h"
#include "../lib/utils.h"

int main(void) {
	sodium_init();

	int status;

	//create Alice's keypair
	unsigned char alice_public_key[crypto_box_PUBLICKEYBYTES];
	unsigned char alice_private_key[crypto_box_SECRETKEYBYTES];
	status = crypto_box_keypair(alice_public_key, alice_private_key);
	if (status != 0) {
		fprintf(stderr, "ERROR: Couldn't create Alice's keypair. (%i)\n", status);
		sodium_memzero(alice_private_key, crypto_box_SECRETKEYBYTES);
		return status;
	}
	//print Alice's keypair
	printf("Alice's public key (%i Bit):\n", 8 * crypto_box_PUBLICKEYBYTES);
	print_hex(alice_public_key, crypto_box_PUBLICKEYBYTES, 30);
	putchar('\n');
	printf("Alice's private key (%i Bit):\n", 8 * crypto_box_SECRETKEYBYTES);
	print_hex(alice_private_key, crypto_box_SECRETKEYBYTES, 30);
	putchar('\n');

	//create Bob's keypair
	unsigned char bob_public_key[crypto_box_PUBLICKEYBYTES];
	unsigned char bob_private_key[crypto_box_SECRETKEYBYTES];
	status = crypto_box_keypair(bob_public_key, bob_private_key);
	if (status != 0) {
		fprintf(stderr, "ERROR: Couldn't create Bob's keypair. (%i)\n", status);
		sodium_memzero(alice_private_key, crypto_box_SECRETKEYBYTES);
		sodium_memzero(bob_private_key, crypto_box_SECRETKEYBYTES);
		return status;
	}
	//print Bob's keypair
	printf("Bob's public key (%i Bit):\n", 8 * crypto_box_PUBLICKEYBYTES);
	print_hex(bob_public_key, crypto_box_PUBLICKEYBYTES, 30);
	putchar('\n');
	printf("Bob's private key (%i Bit):\n", 8 * crypto_box_SECRETKEYBYTES);
	print_hex(bob_private_key, crypto_box_SECRETKEYBYTES, 30);
	putchar('\n');

	//Diffie Hellman on Alice's side
	unsigned char alice_shared_secret[crypto_generichash_BYTES];
	status = diffie_hellman(
			alice_shared_secret,
			alice_private_key,
			alice_public_key,
			bob_public_key,
			true);
	sodium_memzero(alice_private_key, crypto_box_SECRETKEYBYTES);
	if (status != 0) {
		fprintf(stderr, "ERROR: Diffie Hellman with Alice's private key failed. (%i)\n", status);
		sodium_memzero(bob_private_key, crypto_box_SECRETKEYBYTES);
		sodium_memzero(alice_shared_secret, crypto_generichash_BYTES);
		return status;
	}

	//print Alice's shared secret
	printf("Alice's shared secret ECDH(A_priv, B_pub) (%i Bytes):\n", crypto_generichash_BYTES);
	print_hex(alice_shared_secret, crypto_generichash_BYTES, 30);
	putchar('\n');

	//Diffie Hellman on Bob's side
	unsigned char bob_shared_secret[crypto_generichash_BYTES];
	status = diffie_hellman(
			bob_shared_secret,
			bob_private_key,
			bob_public_key,
			alice_public_key,
			false);
	sodium_memzero(bob_private_key, crypto_box_SECRETKEYBYTES);
	if (status != 0) {
		fprintf(stderr, "ERROR: Diffie Hellman with Bob's private key failed. (%i)\n", status);
		sodium_memzero(alice_shared_secret, crypto_generichash_BYTES);
		sodium_memzero(bob_shared_secret, crypto_generichash_BYTES);
		return status;
	}

	//print Bob's shared secret
	printf("Bob's shared secret ECDH(B_priv, A_pub) (%i Bytes):\n", crypto_generichash_BYTES);
	print_hex(bob_shared_secret, crypto_generichash_BYTES, 30);
	putchar('\n');

	//compare both shared secrets
	status = sodium_memcmp(alice_shared_secret, bob_shared_secret, crypto_generichash_BYTES);
	sodium_memzero(alice_shared_secret, crypto_generichash_BYTES);
	sodium_memzero(bob_shared_secret, crypto_generichash_BYTES);
	if (status != 0) {
		fprintf(stderr, "ERROR: Diffie Hellman didn't produce the same shared secret. (%i)\n", status);
		return status;
	}

	printf("Both shared secrets match!\n");
	return EXIT_SUCCESS;
}
