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

/*
 * Create message and header keys, encrypt header and message
 * and print them.
 */
int create_and_print_message(
		unsigned char * const packet, //needs to be 3 + crypto_aead_chacha20poly1305_NPUBBYTES + crypto_aead_chacha20poly1305_ABYTES + crypto_secretbox_NONCEBYTES + message_length + header_length + crypto_secretbox_MACBYTES + 255
		size_t * const packet_length, //output
		const unsigned char packet_type,
		const unsigned char current_protocol_version,
		const unsigned char highest_supported_protocol_version,
		const unsigned char * const message,
		const size_t message_length,
		unsigned char * message_key, //output, crypto_secretbox_KEYBYTES
		const unsigned char * const header,
		const size_t header_length,
		unsigned char * header_key) { //output, crypto_aead_chacha20poly1305_KEYBYTES
	//create header key
	randombytes_buf(header_key, crypto_aead_chacha20poly1305_KEYBYTES);
	printf("Header key (%i Bytes):\n", crypto_aead_chacha20poly1305_KEYBYTES);
	print_hex(header_key, crypto_aead_chacha20poly1305_KEYBYTES, 30);
	putchar('\n');

	//create message key
	randombytes_buf(message_key, crypto_secretbox_KEYBYTES);
	printf("Message key (%i Bytes):\n", crypto_secretbox_KEYBYTES);
	print_hex(message_key, crypto_secretbox_KEYBYTES, 30);
	putchar('\n');

	//print the header (as hex):
	printf("Header (%zi Bytes):\n", header_length);
	print_hex(header, header_length, 30);
	putchar('\n');

	//print the message (as string):
	printf("Message (%zi Bytes):\n%.*s\n\n", message_length, (int)message_length, message);

	//create buffers TODO remove once packet-test-lib.c has been moved over to buffer_t
	buffer_t *packet_buffer = buffer_create_with_existing_array(packet, 3 + crypto_aead_chacha20poly1305_NPUBBYTES + crypto_aead_chacha20poly1305_ABYTES + crypto_secretbox_NONCEBYTES + message_length + header_length + crypto_secretbox_MACBYTES + 255);
	buffer_t *header_buffer = buffer_create_with_existing_array((unsigned char*)header, header_length);
	buffer_t *header_key_buffer = buffer_create_with_existing_array((unsigned char*)header_key, crypto_aead_chacha20poly1305_KEYBYTES);
	buffer_t *message_key_buffer = buffer_create_with_existing_array((unsigned char*)message_key, crypto_secretbox_KEYBYTES);
	buffer_t *message_buffer = buffer_create_with_existing_array((unsigned char*)message, message_length);

	//now encrypt the message
	int status = packet_encrypt(
			packet_buffer,
			packet_type,
			current_protocol_version,
			highest_supported_protocol_version,
			header_buffer,
			header_key_buffer,
			message_buffer,
			message_key_buffer);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to encrypt message and header. (%i)\n", status);
		return status;
	}
	*packet_length = packet_buffer->content_length;

	//print header nonce
	printf("Header Nonce (%i Bytes):\n", crypto_aead_chacha20poly1305_NPUBBYTES);
	print_hex(packet + 3, crypto_aead_chacha20poly1305_NPUBBYTES, 30);
	putchar('\n');

	//print encrypted packet
	printf("Encrypted Packet (%zi Bytes):\n", *packet_length);
	print_hex(packet, *packet_length, 30);
	putchar('\n');

	return 0;
}
