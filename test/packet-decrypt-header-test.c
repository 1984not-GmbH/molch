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
	sodium_memzero(message_key, sizeof(message_key));
	sodium_memzero(message, sizeof(message));
	if (status != 0) {
		sodium_memzero(header_key, sizeof(header_key));
		sodium_memzero(header, sizeof(header));
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
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to decrypt the header. (%i)\n", status);
		sodium_memzero(header, sizeof(header));
		sodium_memzero(decrypted_header, sizeof(decrypted_header));
		sodium_memzero(decrypted_message_nonce, sizeof(decrypted_message_nonce));
		sodium_memzero(header_key, sizeof(header_key));
		return status;
	}


	if (decrypted_header_length != sizeof(header)) {
		fprintf(stderr, "ERROR: Decrypted header isn't of the same length!\n");
		sodium_memzero(header, sizeof(header));
		sodium_memzero(decrypted_header, sizeof(decrypted_header));
		sodium_memzero(decrypted_message_nonce, sizeof(decrypted_message_nonce));
		sodium_memzero(header_key, sizeof(header_key));
		return EXIT_SUCCESS;
	}
	printf("Decrypted header has the same length.\n\n");

	printf("Decrypted message nonce (%i Bytes):\n", crypto_secretbox_NONCEBYTES);
	print_hex(decrypted_message_nonce, crypto_secretbox_NONCEBYTES, 30);
	putchar('\n');
	sodium_memzero(decrypted_message_nonce, sizeof(decrypted_message_nonce));

	//compare headers
	if (sodium_memcmp(header, decrypted_header, decrypted_header_length) != 0) {
		fprintf(stderr, "ERROR: Decrypted header doesn't match!\n");
		sodium_memzero(header, sizeof(header));
		sodium_memzero(decrypted_header, sizeof(decrypted_header));
		sodium_memzero(header_key, sizeof(header_key));
		return EXIT_FAILURE;
	}
	printf("Decrypted header matches.\n\n");

	//check if it decrypts manipulated packets (manipulated metadata)
	printf("Manipulating header length.\n");
	packet[2]++;
	status = packet_decrypt_header(
			packet,
			packet_length,
			decrypted_header,
			&decrypted_header_length,
			decrypted_message_nonce,
			header_key);
	sodium_memzero(decrypted_message_nonce, sizeof(decrypted_message_nonce));
	if (status == 0) { //header was decrypted despite manipulation
		fprintf(stderr, "ERROR: Manipulated packet was accepted!\n");
		sodium_memzero(header, sizeof(header));
		sodium_memzero(decrypted_header, sizeof(decrypted_header));
		sodium_memzero(header_key, sizeof(header_key));
		return EXIT_FAILURE;
	}
	printf("Header manipulation detected.\n\n");

	//repair manipulation
	packet[2]--;
	//check if it decrypts manipulated packets (manipulated header)
	printf("Manipulate header.\n");
	packet[3 + crypto_aead_chacha20poly1305_NPUBBYTES + 1] ^= 0x12;
	status = packet_decrypt_header(
			packet,
			packet_length,
			decrypted_header,
			&decrypted_header_length,
			decrypted_message_nonce,
			header_key);
	if (status == 0) { //header was decrypted desp
		fprintf(stderr, "ERROR: Manipulated packet was accepted!\n");
		sodium_memzero(header, sizeof(header));
		sodium_memzero(decrypted_header, sizeof(decrypted_header));
		sodium_memzero(header_key, sizeof(header_key));
		return EXIT_FAILURE;
	}
	printf("Header manipulation detected!\n");

	//undo header manipulation
	packet[3 + crypto_aead_chacha20poly1305_NPUBBYTES + 1] ^= 0x12;

	sodium_memzero(header, sizeof(header));
	sodium_memzero(decrypted_header, sizeof(decrypted_header));
	sodium_memzero(header_key, sizeof(header_key));

	return EXIT_SUCCESS;
}
