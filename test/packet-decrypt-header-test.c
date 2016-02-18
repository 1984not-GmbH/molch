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
#include "tracing.h"

int main(void) {
	if(sodium_init() == -1) {
		return -1;
	}

	//decrypted header buffers
	buffer_t *decrypted_header = buffer_create_on_heap(255, 255);
	buffer_t *decrypted_message_nonce = buffer_create_on_heap(crypto_secretbox_NONCEBYTES, crypto_secretbox_NONCEBYTES);

	//generate keys and message
	buffer_t *header_key = buffer_create_on_heap(crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
	buffer_t *message_key = buffer_create_on_heap(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	buffer_create_from_string(message, "Hello world!\n");
	buffer_t *header = buffer_create_on_heap(4, 4);
	header->content[0] = 0x01;
	header->content[1] = 0x02;
	header->content[2] = 0x03;
	header->content[3] = 0x04;
	buffer_t *packet = buffer_create_on_heap(3 + crypto_aead_chacha20poly1305_NPUBBYTES + crypto_aead_chacha20poly1305_ABYTES + crypto_secretbox_NONCEBYTES + message->content_length + header->content_length + crypto_secretbox_MACBYTES + 255, 3 + crypto_aead_chacha20poly1305_NPUBBYTES + crypto_aead_chacha20poly1305_ABYTES + crypto_secretbox_NONCEBYTES + message->content_length + header->content_length + crypto_secretbox_MACBYTES + 255);
	const unsigned char packet_type = 1;
	printf("Packet type: %02x\n", packet_type);
	const unsigned char current_protocol_version = 2;
	printf("Current protocol version: %02x\n", current_protocol_version);
	const unsigned char highest_supported_protocol_version = 3;
	printf("Highest supported protocol version: %02x\n", highest_supported_protocol_version);
	putchar('\n');
	int status = create_and_print_message(
			packet,
			packet_type,
			current_protocol_version,
			highest_supported_protocol_version,
			message,
			message_key,
			header,
			header_key);
	buffer_clear(message_key);
	if (status != 0) {
		goto cleanup;
	}

	//now decrypt the header
	status = packet_decrypt_header(
			packet,
			decrypted_header,
			decrypted_message_nonce,
			header_key);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to decrypt the header. (%i)\n", status);
		goto cleanup;
	}


	if (decrypted_header->content_length != header->content_length) {
		fprintf(stderr, "ERROR: Decrypted header isn't of the same length!\n");
		goto cleanup;
	}
	printf("Decrypted header has the same length.\n\n");

	printf("Decrypted message nonce (%zu Bytes):\n", decrypted_message_nonce->content_length);
	print_hex(decrypted_message_nonce);
	putchar('\n');
	buffer_clear(decrypted_message_nonce);

	//compare headers
	if (buffer_compare(header, decrypted_header) != 0) {
		fprintf(stderr, "ERROR: Decrypted header doesn't match!\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	printf("Decrypted header matches.\n\n");

	//check if it decrypts manipulated packets (manipulated metadata)
	printf("Manipulating header length.\n");
	packet->content[2]++;
	status = packet_decrypt_header(
			packet,
			decrypted_header,
			decrypted_message_nonce,
			header_key);
	if (status == 0) { //header was decrypted despite manipulation
		fprintf(stderr, "ERROR: Manipulated packet was accepted!\n");
		goto cleanup;
	}
	printf("Header manipulation detected.\n\n");

	//repair manipulation
	packet->content[2]--;
	//check if it decrypts manipulated packets (manipulated header)
	printf("Manipulate header.\n");
	packet->content[3 + crypto_aead_chacha20poly1305_NPUBBYTES + 1] ^= 0x12;
	status = packet_decrypt_header(
			packet,
			decrypted_header,
			decrypted_message_nonce,
			header_key);
	if (status == 0) { //header was decrypted desp
		fprintf(stderr, "ERROR: Manipulated packet was accepted!\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	status = EXIT_SUCCESS;
	printf("Header manipulation detected!\n");

	//undo header manipulation
	packet->content[3 + crypto_aead_chacha20poly1305_NPUBBYTES + 1] ^= 0x12;

cleanup:
	buffer_destroy_from_heap(decrypted_header);
	buffer_destroy_from_heap(decrypted_message_nonce);
	buffer_destroy_from_heap(header_key);
	buffer_destroy_from_heap(message_key);
	buffer_destroy_from_heap(header);
	buffer_destroy_from_heap(packet);
	return status;
}
