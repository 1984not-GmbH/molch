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

#include "../lib/message.h"
#include "../lib/utils.h"

#define MESSAGE "Hello World, this is a message!"
#define HEADER "This is a header!"

int encrypt(unsigned char* ciphertext, size_t* ciphertext_length, unsigned char* key) {
	unsigned char message[] = MESSAGE;
	printf("Message (%lu Bytes):\n%s\n\n", sizeof(message), message);

	//create random nonce
	unsigned char nonce[crypto_secretbox_NONCEBYTES];
	randombytes_buf(nonce, crypto_secretbox_NONCEBYTES);

	//print nonce
	printf("Nonce (%i Bytes):\n", crypto_secretbox_NONCEBYTES);
	print_hex(nonce, crypto_secretbox_NONCEBYTES, 30);
	putchar('\n');

	const unsigned char header[] = HEADER;
	printf("Header (%lu Bytes):\n%s\n\n", sizeof(header), header);

	int status = encrypt_message(
			ciphertext,
			ciphertext_length,
			message,
			sizeof(message),
			header,
			sizeof(header),
			nonce,
			key);
	sodium_memzero(message, sizeof(message));
	return status;
}

int main(void) {
	sodium_init();

	//create random key
	unsigned char key[crypto_secretbox_KEYBYTES];
	randombytes_buf(key, crypto_secretbox_KEYBYTES);

	//print key
	printf("Key (%i Bytes):\n", crypto_secretbox_KEYBYTES);
	print_hex(key, crypto_secretbox_KEYBYTES, 30);
	putchar('\n');


	//encrypted message
	unsigned char ciphertext[500]; //TODO don't use fixed size buffer here

	size_t ciphertext_length = 0;
	int status;
	status = encrypt(ciphertext, &ciphertext_length, key);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to encrypt message. (%i)\n", status);
		return status;
	}

	//print the ciphertext
	printf("Ciphertext (packet, %zu Bytes):\n", ciphertext_length);
	print_hex(ciphertext, ciphertext_length, 30);
	putchar('\n');

	puts("NOW DECRYPT -------------------------------------------------------------------\n");

	unsigned char message[ciphertext_length];
	unsigned char header[ciphertext_length];

	size_t message_length = 0;
	size_t header_length = 0;

	//now decrypt the message
	status = decrypt_message(
			message, &message_length,
			header, &header_length,
			ciphertext, ciphertext_length,
			key);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to decrypt ciphertext. (%i)\n", status);
		sodium_memzero(message, sizeof(message));
		sodium_memzero(header, sizeof(header));
		return status;
	}

	//print header
	printf("Received header (%zu Bytes):\n%s\n\n", header_length, header);

	//check header
	if (sodium_memcmp(header, HEADER, header_length) != 0) {
		fprintf(stderr, "ERROR: Headers aren't the same.\n");
		sodium_memzero(message, sizeof(message));
		sodium_memzero(header, sizeof(header));
		return -1;
	}

	//print message
	printf("Received message (%zu Bytes):\n%s\n\n", message_length, message);

	//check message
	if (sodium_memcmp(message, MESSAGE, message_length) != 0) {
		fprintf(stderr, "ERROR: Messages aren't the same.\n");
		sodium_memzero(message, sizeof(message));
		return -1;
	}

	sodium_memzero(message, sizeof(message));

	return EXIT_SUCCESS;
}
