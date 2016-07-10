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
#include "../lib/molch.h"
#include "../lib/constants.h"
#include "utils.h"
#include "packet-test-lib.h"
#include "tracing.h"

int main(void) {
	buffer_create_from_string(message, "Hello world!\n");
	//create buffers
	buffer_t *header_key = buffer_create_on_heap(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	buffer_t *message_key = buffer_create_on_heap(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	buffer_t *public_identity_key = buffer_create_on_heap(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	buffer_t *public_ephemeral_key = buffer_create_on_heap(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	buffer_t *public_prekey = buffer_create_on_heap(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	buffer_t *header = buffer_create_on_heap(4, 4);
	buffer_t *packet = buffer_create_on_heap(3 + HEADER_NONCE_SIZE + crypto_secretbox_MACBYTES + crypto_secretbox_NONCEBYTES + message->content_length + header->content_length + crypto_secretbox_MACBYTES + 255 + 3 * PUBLIC_KEY_SIZE, 3 + HEADER_NONCE_SIZE + crypto_secretbox_MACBYTES + crypto_secretbox_NONCEBYTES + message->content_length + header->content_length + crypto_secretbox_MACBYTES + 255 + 3 * PUBLIC_KEY_SIZE);
	buffer_t *decrypted_header = buffer_create_on_heap(255, 255);
	buffer_t *decrypted_message_nonce = buffer_create_on_heap(crypto_secretbox_NONCEBYTES, crypto_secretbox_NONCEBYTES);
	buffer_t *decrypted_message = buffer_create_on_heap(packet->content_length, packet->content_length);

	return_status status = return_status_init();

	if (sodium_init() == -1) {
		throw(INIT_ERROR, "Failed to initialize libsodium.");
	}

	//generate keys and message
	header->content[0] = 0x01;
	header->content[1] = 0x02;
	header->content[2] = 0x03;
	header->content[3] = 0x04;
	unsigned char packet_type = 1;
	printf("Packet type: %02x\n", packet_type);
	const unsigned char current_protocol_version = 2;
	printf("Current protocol version: %02x\n", current_protocol_version);
	const unsigned char highest_supported_protocol_version = 3;
	printf("Highest supported protocol version: %02x\n", highest_supported_protocol_version);
	putchar('\n');

	//NORMAL MESSAGE
	printf("NORMAL MESSAGE\n");
	int status_int = 0;
	status = create_and_print_message(
			packet,
			packet_type,
			current_protocol_version,
			highest_supported_protocol_version,
			message,
			message_key,
			header,
			header_key,
			NULL,
			NULL,
			NULL);
	throw_on_error(GENERIC_ERROR, "Failed to create and print message.");

	//now decrypt the header
	status = packet_decrypt_header(
			packet,
			decrypted_header,
			decrypted_message_nonce,
			header_key,
			NULL,
			NULL,
			NULL);
	buffer_clear(decrypted_header);
	throw_on_error(DECRYPT_ERROR, "Failed to decrypt header.");

	printf("Decrypted message nonce (%zu Bytes):\n", decrypted_message_nonce->content_length);
	print_hex(decrypted_message_nonce);
	putchar('\n');

	//now decrypt the message
	status = packet_decrypt_message(
			packet,
			decrypted_message,
			decrypted_message_nonce,
			message_key);
	throw_on_error(DECRYPT_ERROR, "Failed to decrypt message.");

	//check the message size
	if (decrypted_message->content_length != message->content_length) {
		throw(INVALID_VALUE, "Decrypted message length isn't the same.");
	}
	printf("Decrypted message length is the same.\n");

	//compare the message
	if (buffer_compare(message, decrypted_message) != 0) {
		throw(INVALID_VALUE, "Decrypted message doesn't match.");
	}
	buffer_clear(decrypted_message);
	printf("Decrypted message is the same.\n\n");

	//manipulate the message
	packet->content[packet->content_length - crypto_secretbox_MACBYTES - 1] ^= 0xf0;
	printf("Manipulating message.\n");

	//try to decrypt
	status = packet_decrypt_message(
			packet,
			decrypted_message,
			decrypted_message_nonce,
			message_key);
	if (status.status == SUCCESS) { //message was decrypted although it shouldn't
		throw(GENERIC_ERROR, "Decrypted manipulated message.");
	} else {
		return_status_destroy_errors(&status);
	}
	printf("Manipulation detected.\n\n");

	//PREKEY MESSAGE
	printf("PREKEY MESSAGE\n");
	//create the public keys
	status_int = buffer_fill_random(public_identity_key, PUBLIC_KEY_SIZE);
	if (status_int != 0) {
		throw(KEYGENERATION_FAILED, "Failed to generate public identity key.");
	}
	status_int = buffer_fill_random(public_ephemeral_key, PUBLIC_KEY_SIZE);
	if (status_int != 0) {
		throw(KEYGENERATION_FAILED, "Failed to generate public ephemeral key.");
	}
	status_int = buffer_fill_random(public_prekey, PUBLIC_KEY_SIZE);
	if (status_int != 0) {
		throw(KEYGENERATION_FAILED, "Failed to generate public prekey.");
	}

	buffer_clear(packet);
	packet_type = PREKEY_MESSAGE;
	status = create_and_print_message(
			packet,
			packet_type,
			current_protocol_version,
			highest_supported_protocol_version,
			message,
			message_key,
			header,
			header_key,
			public_identity_key,
			public_ephemeral_key,
			public_prekey);
	throw_on_error(GENERIC_ERROR, "Failed to create and print message.");

	//now decrypt the header
	status = packet_decrypt_header(
			packet,
			decrypted_header,
			decrypted_message_nonce,
			header_key,
			NULL,
			NULL,
			NULL);
	throw_on_error(DECRYPT_ERROR, "Failed to decrypt header.");

	printf("Decrypted message nonce (%zu Bytes):\n", decrypted_message_nonce->content_length);
	print_hex(decrypted_message_nonce);
	putchar('\n');

	//now decrypt the message
	status = packet_decrypt_message(
			packet,
			decrypted_message,
			decrypted_message_nonce,
			message_key);
	throw_on_error(DECRYPT_ERROR, "Failed to decrypt message.");

	//check the message size
	if (decrypted_message->content_length != message->content_length) {
		throw(INVALID_VALUE, "Decrypted message length isn't the same.");
	}
	printf("Decrypted message length is the same.\n");

	//compare the message
	if (buffer_compare(message, decrypted_message) != 0) {
		throw(INVALID_VALUE, "Decrypted message doesn't match.");
	}
	buffer_clear(decrypted_message);
	printf("Decrypted message is the same.\n");

cleanup:
	buffer_destroy_from_heap(header_key);
	buffer_destroy_from_heap(message_key);
	buffer_destroy_from_heap(header);
	buffer_destroy_from_heap(packet);
	buffer_destroy_from_heap(decrypted_header);
	buffer_destroy_from_heap(decrypted_message_nonce);
	buffer_destroy_from_heap(decrypted_message);
	buffer_destroy_from_heap(public_identity_key);
	buffer_destroy_from_heap(public_ephemeral_key);
	buffer_destroy_from_heap(public_prekey);

	if (status.status != SUCCESS) {
		print_errors(&status);
		return_status_destroy_errors(&status);
	}

	return status.status;
}
