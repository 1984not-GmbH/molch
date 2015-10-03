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
		buffer_t * const packet, //needs to be 3 + crypto_aead_chacha20poly1305_NPUBBYTES + crypto_aead_chacha20poly1305_ABYTES + crypto_secretbox_NONCEBYTES + message_length + header_length + crypto_secretbox_MACBYTES + 255
		const unsigned char packet_type,
		const unsigned char current_protocol_version,
		const unsigned char highest_supported_protocol_version,
		const buffer_t * const message,
		buffer_t * const message_key, //output, crypto_secretbox_KEYBYTES
		const buffer_t * const header,
		buffer_t * const header_key) { //output, crypto_aead_chacha20poly1305_KEYBYTES
	int status;
	//create header key
	status = buffer_fill_random(header_key, crypto_aead_chacha20poly1305_KEYBYTES);
	if (status != 0) {
		buffer_clear(header_key);
		return status;
	}
	printf("Header key (%zi Bytes):\n", header_key->content_length);
	print_hex(header_key);
	putchar('\n');

	//create message key
	status = buffer_fill_random(message_key, crypto_secretbox_KEYBYTES);
	if (status != 0) {
		buffer_clear(header_key);
		buffer_clear(message_key);
		return status;
	}
	printf("Message key (%zi Bytes):\n", message_key->content_length);
	print_hex(message_key);
	putchar('\n');

	//print the header (as hex):
	printf("Header (%zi Bytes):\n", header->content_length);
	print_hex(header);
	putchar('\n');

	//print the message (as string):
	printf("Message (%zi Bytes):\n%.*s\n\n", message->content_length, (int)message->content_length, message->content);

	//now encrypt the message
	status = packet_encrypt(
			packet,
			packet_type,
			current_protocol_version,
			highest_supported_protocol_version,
			header,
			header_key,
			message,
			message_key);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to encrypt message and header. (%i)\n", status);
		return status;
	}

	//print header nonce
	buffer_t *header_nonce = buffer_create_with_existing_array(packet->content + 3, crypto_aead_chacha20poly1305_NPUBBYTES);
	printf("Header Nonce (%zi Bytes):\n", header_nonce->content_length);
	print_hex(header_nonce);
	putchar('\n');

	//print encrypted packet
	printf("Encrypted Packet (%zi Bytes):\n", packet->content_length);
	print_hex(packet);
	putchar('\n');

	return 0;
}
