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

#include "../lib/packet.h"
#include "utils.h"

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

	//manipulate header
	unsigned char packet_with_modified_header[ciphertext_length];
	memcpy(packet_with_modified_header, ciphertext, ciphertext_length);
	packet_with_modified_header[3] = '\n';

	unsigned char message[ciphertext_length];
	unsigned char header[ciphertext_length];

	size_t message_length = 0;
	size_t header_length = 0;

	//now decrypt the packet with manipulated header
	status = decrypt_message(
			message, &message_length,
			header, &header_length,
			packet_with_modified_header, ciphertext_length,
			key);
	if (status == 0) {
		fprintf(stderr, "ERROR: Failed to detect manipulated header.");
		sodium_memzero(message, sizeof(message));
		return -1;
	}
	printf("Header manipulation successfully detected!\n");

	//manipulate header_length
	unsigned char packet_with_modified_header_length[ciphertext_length];
	memcpy(packet_with_modified_header_length, ciphertext, ciphertext_length);
	packet_with_modified_header_length[0] = 0xff;

	//now decrypt the packet with manipulated header length
	status = decrypt_message(
			message, &message_length,
			header, &header_length,
			packet_with_modified_header_length, ciphertext_length,
			key);
	if (status == 0) {
		fprintf(stderr, "ERROR: Failed to detect manipulated header length.");
		sodium_memzero(message, sizeof(message));
		return -1;
	}
	printf("Header length manipulation successfully detected!\n");

	//manipulate message
	unsigned char packet_with_modified_message[ciphertext_length];
	memcpy(packet_with_modified_message, ciphertext, ciphertext_length);
	packet_with_modified_message[sizeof(HEADER) + 1 + crypto_secretbox_NONCEBYTES + crypto_onetimeauth_BYTES + 3] = 0xff;
	packet_with_modified_message[sizeof(HEADER) + 1 + crypto_secretbox_NONCEBYTES + crypto_onetimeauth_BYTES + 4] = 0xff;

	//now decrypt the packet with manipulated header length
	status = decrypt_message(
			message, &message_length,
			header, &header_length,
			packet_with_modified_message, ciphertext_length,
			key);
	if (status == 0) {
		fprintf(stderr, "ERROR: Failed to detect manipulated message.");
		sodium_memzero(message, sizeof(message));
		return -1;
	}
	printf("Message manipulation successfully detected!\n");

	sodium_memzero(message, sizeof(message));

	return EXIT_SUCCESS;
}
