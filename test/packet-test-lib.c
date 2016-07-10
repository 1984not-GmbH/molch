/*
 * Molch, an implementation of the axolotl ratchet based on libsodium
 *
 * ISC License
 *
 * Copyright (C) 2015-2016 1984not Security GmbH
 * Author: Max Bruckner (FSMaxB)
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>

#include "../lib/packet.h"
#include "../lib/constants.h"
#include "utils.h"
#include "packet-test-lib.h"
#include "tracing.h"

/*
 * Create message and header keys, encrypt header and message
 * and print them.
 *
 * Don't forget to destroy the return status with return_status_destroy_errors()
 * if an error has occurred.
 */
return_status create_and_print_message(
		buffer_t * const packet, //needs to be 3 + HEADER_NONCE_SIZE + crypto_secretbox_MACBYTES + crypto_secretbox_NONCEBYTES + message_length + header_length + crypto_secretbox_MACBYTES + 255
		const unsigned char packet_type,
		const unsigned char current_protocol_version,
		const unsigned char highest_supported_protocol_version,
		const buffer_t * const message,
		buffer_t * const message_key, //output, crypto_secretbox_KEYBYTES
		const buffer_t * const header,
		buffer_t * const header_key, //output, HEADER_KEY_SIZE
		const buffer_t * const public_identity_key, //optional, can be NULL, for prekey messages
		const buffer_t * const public_ephemeral_key, //optional, can be NULL, for prekey messages
		const buffer_t * const public_prekey) { //optional, can be NULL, for prekey messages

	return_status status = return_status_init();
	int status_int;

	//create header key
	status_int = buffer_fill_random(header_key, HEADER_KEY_SIZE);
	if (status_int != 0) {
		throw(KEYGENERATION_FAILED, "Failed to generate header key.");
	}
	printf("Header key (%zu Bytes):\n", header_key->content_length);
	print_hex(header_key);
	putchar('\n');

	//create message key
	status_int = buffer_fill_random(message_key, crypto_secretbox_KEYBYTES);
	if (status_int != 0) {
		throw(KEYGENERATION_FAILED, "Failed to generate message key.");
	}
	printf("Message key (%zu Bytes):\n", message_key->content_length);
	print_hex(message_key);
	putchar('\n');

	//print the header (as hex):
	printf("Header (%zu Bytes):\n", header->content_length);
	print_hex(header);
	putchar('\n');

	//print the message (as string):
	printf("Message (%zu Bytes):\n%.*s\n\n", message->content_length, (int)message->content_length, message->content);

	//now encrypt the message
	status = packet_encrypt(
			packet,
			packet_type,
			current_protocol_version,
			highest_supported_protocol_version,
			header,
			header_key,
			message,
			message_key,
			public_identity_key,
			public_ephemeral_key,
			public_prekey);
	throw_on_error(ENCRYPT_ERROR, "Failed to encrypt message and header.");

	//print header nonce
	buffer_create_with_existing_array(header_nonce, packet->content + 3, HEADER_NONCE_SIZE);
	printf("Header Nonce (%zu Bytes):\n", header_nonce->content_length);
	print_hex(header_nonce);
	putchar('\n');

	//print encrypted packet
	printf("Encrypted Packet (%zu Bytes):\n", packet->content_length);
	print_hex(packet);
	putchar('\n');

cleanup:
	if (status.status != SUCCESS) {
		buffer_clear(header_key);
		buffer_clear(message_key);
	}

	return status;
}
