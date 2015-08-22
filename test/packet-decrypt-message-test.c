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

#include "../lib/packet.h"
#include "utils.h"
#include "packet-test-lib.h"

int main(void) {
	sodium_init();

	//generate keys and message
	unsigned char header_key[crypto_aead_chacha20poly1305_KEYBYTES];
	unsigned char message_key[crypto_secretbox_KEYBYTES];
	unsigned char message[] = "Hello world!\n";
	unsigned char header[] = {0x01, 0x02, 0x03, 0x04};
	unsigned char packet[3 + crypto_aead_chacha20poly1305_NPUBBYTES + crypto_aead_chacha20poly1305_ABYTES + crypto_secretbox_NONCEBYTES + sizeof(message) + sizeof(header) + crypto_secretbox_MACBYTES + 255];
	const unsigned char packet_type = 1;
	printf("Packet type: %02x\n", packet_type);
	const unsigned char current_protocol_version = 2;
	printf("Current protocol version: %02x\n", current_protocol_version);
	const unsigned char highest_supported_protocol_version = 3;
	printf("Highest supported protocol version: %02x\n", highest_supported_protocol_version);
	putchar('\n');
	size_t packet_length;
	int status = create_and_print_message(
			packet,
			&packet_length,
			packet_type,
			current_protocol_version,
			highest_supported_protocol_version,
			message,
			sizeof(message),
			message_key,
			header,
			sizeof(header),
			header_key);
	sodium_memzero(header, sizeof(header));
	if (status != 0) {
		sodium_memzero(message_key, sizeof(message_key));
		sodium_memzero(message, sizeof(message));
		sodium_memzero(header_key, sizeof(header_key));
		return status;
	}

	//now decrypt the header
	unsigned char decrypted_header[255];
	unsigned char decrypted_message_nonce[crypto_secretbox_NONCEBYTES];
	size_t decrypted_header_length;
	status = packet_decrypt_header(
			packet,
			packet_length,
			decrypted_header,
			&decrypted_header_length,
			decrypted_message_nonce,
			header_key);
	sodium_memzero(decrypted_header, sizeof(decrypted_header));
	sodium_memzero(header_key, sizeof(header_key));
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to decrypt header. (%i)\n", status);
		sodium_memzero(message_key, sizeof(message_key));
		sodium_memzero(message, sizeof(message));
		sodium_memzero(decrypted_message_nonce, sizeof(decrypted_message_nonce));
		return status;
	}

	printf("Decrypted message nonce (%i Bytes):\n", crypto_secretbox_NONCEBYTES);
	print_hex(decrypted_message_nonce, crypto_secretbox_NONCEBYTES, 30);
	putchar('\n');

	//now decrypt the message
	unsigned char decrypted_message[packet_length];
	size_t decrypted_message_length;
	status = packet_decrypt_message(
			packet,
			packet_length,
			decrypted_message,
			&decrypted_message_length,
			decrypted_message_nonce,
			message_key);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to decrypt message. (%i)\n", status);
		sodium_memzero(message, sizeof(message));
		sodium_memzero(message_key, sizeof(message_key));
		sodium_memzero(decrypted_message_nonce, sizeof(decrypted_message_nonce));
		sodium_memzero(decrypted_message, sizeof(decrypted_message));
		return status;
	}

	//check the message size
	if (decrypted_message_length != sizeof(message)) {
		fprintf(stderr, "ERROR: Decrypted message length isn't the same.\n");
		sodium_memzero(message, sizeof(message));
		sodium_memzero(message_key, sizeof(message_key));
		sodium_memzero(decrypted_message_nonce, sizeof(decrypted_message_nonce));
		sodium_memzero(decrypted_message, sizeof(decrypted_message));
		return EXIT_FAILURE;
	}
	printf("Decrypted message length is the same.\n");

	//compare the message
	if (sodium_memcmp(message, decrypted_message, decrypted_message_length) != 0) {
		fprintf(stderr, "ERROR: Decrypted message doesn't match!\n");
		sodium_memzero(message, sizeof(message));
		sodium_memzero(message_key, sizeof(message_key));
		sodium_memzero(decrypted_message_nonce, sizeof(decrypted_message_nonce));
		sodium_memzero(decrypted_message, sizeof(decrypted_message));
		return EXIT_FAILURE;
	}
	sodium_memzero(message, sizeof(message));
	sodium_memzero(decrypted_message, sizeof(decrypted_message));
	printf("Decrypted message is the same.\n\n");

	//manipulate the message
	packet[packet_length - crypto_secretbox_MACBYTES - 1] ^= 0xf0;
	printf("Manipulating message.\n");

	//try to decrypt
	status = packet_decrypt_message(
			packet,
			packet_length,
			decrypted_message,
			&decrypted_message_length,
			decrypted_message_nonce,
			message_key);
	if (status == 0) { //message was decrypted although it shouldn't
		fprintf(stderr, "ERROR: Decrypted manipulated message.\n");
		sodium_memzero(decrypted_message, sizeof(decrypted_message));
		sodium_memzero(message_key, sizeof(message_key));
		sodium_memzero(decrypted_message_nonce, sizeof(decrypted_message_nonce));
		return EXIT_FAILURE;
	}
	printf("Manipulation detected.\n");
	sodium_memzero(decrypted_message, sizeof(decrypted_message));

	sodium_memzero(message_key, sizeof(message_key));
	sodium_memzero(decrypted_message_nonce, sizeof(decrypted_message_nonce));

	return EXIT_SUCCESS;
}
