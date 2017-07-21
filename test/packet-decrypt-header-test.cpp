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

#include <cstdio>
#include <cstdlib>
#include <sodium.h>

#include "../lib/packet.h"
#include "../lib/molch.h"
#include "../lib/constants.h"
#include "utils.h"
#include "packet-test-lib.h"

int main(void) noexcept {
	return_status status = return_status_init();

	//generate keys
	Buffer header_key(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	Buffer message_key(MESSAGE_KEY_SIZE, MESSAGE_KEY_SIZE);
	Buffer public_identity_key(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	Buffer public_ephemeral_key(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	Buffer public_prekey(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);

	Buffer header(4, 4);
	Buffer message("Hello world!\n");

	Buffer *packet = nullptr;
	Buffer *decrypted_header = nullptr;

	molch_message_type packet_type = NORMAL_MESSAGE;

	throw_on_invalid_buffer(header_key);
	throw_on_invalid_buffer(message_key);
	throw_on_invalid_buffer(public_identity_key);
	throw_on_invalid_buffer(public_ephemeral_key);
	throw_on_invalid_buffer(public_prekey);
	throw_on_invalid_buffer(header);

	if(sodium_init() == -1) {
		THROW(INIT_ERROR, "Failed to initialize libsodium.");
	}

	//generate message
	header.content[0] = 0x01;
	header.content[1] = 0x02;
	header.content[2] = 0x03;
	header.content[3] = 0x04;
	printf("Packet type: %02x\n", packet_type);
	putchar('\n');

	//NORMAL MESSAGE
	printf("NORMAL MESSAGE\n");
	status = create_and_print_message(
			packet,
			header_key,
			message_key,
			packet_type,
			header,
			message,
			nullptr,
			nullptr,
			nullptr);
	THROW_on_error(GENERIC_ERROR, "Failed to create and print message.");

	//now decrypt the header
	status = packet_decrypt_header(
			decrypted_header,
			*packet,
			header_key);
	THROW_on_error(DECRYPT_ERROR, "Failed to decrypt the header.");


	if (decrypted_header->content_length != header.content_length) {
		THROW(INVALID_VALUE, "Decrypted header isn't of the same length.");
	}
	printf("Decrypted header has the same length.\n\n");

	//compare headers
	if (header.compare(decrypted_header) != 0) {
		THROW(INVALID_VALUE, "Decrypted header doesn't match.");
	}
	printf("Decrypted header matches.\n\n");

	//check if it decrypts manipulated packets (manipulated metadata)
	printf("Manipulating header length.\n");
	packet->content[2]++;
	status = packet_decrypt_header(
			decrypted_header,
			*packet,
			header_key);
	if (status.status == SUCCESS) {
		THROW(GENERIC_ERROR, "Manipulated packet was accepted.");
	} else {
		return_status_destroy_errors(&status);
	}

	printf("Header manipulation detected.\n\n");

	//repair manipulation
	packet->content[2]--;
	//check if it decrypts manipulated packets (manipulated header)
	printf("Manipulate header.\n");
	packet->content[3 + crypto_aead_chacha20poly1305_NPUBBYTES + 1] ^= 0x12;
	status = packet_decrypt_header(
			decrypted_header,
			*packet,
			header_key);
	if (status.status == SUCCESS) {
		THROW(GENERIC_ERROR, "Manipulated packet was accepted.");
	} else {
		return_status_destroy_errors(&status);
	}

	printf("Header manipulation detected!\n\n");

	//undo header manipulation
	packet->content[3 + crypto_aead_chacha20poly1305_NPUBBYTES + 1] ^= 0x12;

	//PREKEY MESSAGE
	printf("PREKEY_MESSAGE\n");
	//create the public keys
	{
		int status_int = public_identity_key.fillRandom(PUBLIC_KEY_SIZE);
		if (status_int != 0) {
			THROW(KEYGENERATION_FAILED, "Failed to generate public identity key.");
		}
	}
	{
		int status_int = public_ephemeral_key.fillRandom(PUBLIC_KEY_SIZE);
		if (status_int != 0) {
			THROW(KEYGENERATION_FAILED, "Failed to generate public ephemeral key.");
		}
	}
	{
		int status_int = public_prekey.fillRandom(PUBLIC_KEY_SIZE);
		if (status_int != 0) {
			THROW(KEYGENERATION_FAILED, "Failed to generate public prekey.");
		}
	}

	buffer_destroy_and_null_if_valid(packet);

	packet_type = PREKEY_MESSAGE;
	status = create_and_print_message(
			packet,
			header_key,
			message_key,
			packet_type,
			header,
			message,
			&public_identity_key,
			&public_ephemeral_key,
			&public_prekey);
	THROW_on_error(GENERIC_ERROR, "Failed to crate and print message.");

	//now decrypt the header
	status = packet_decrypt_header(
			decrypted_header,
			*packet,
			header_key);
	THROW_on_error(DECRYPT_ERROR, "Failed to decrypt the header.");

	if (decrypted_header->content_length != header.content_length) {
		THROW(INVALID_VALUE, "Decrypted header isn't of the same length.");
	}
	printf("Decrypted header has the same length.\n\n");

	//compare headers
	if (header != *decrypted_header) {
		THROW(INVALID_VALUE, "Decrypted header doesn't match.");
	}
	printf("Decrypted header matches.\n");

cleanup:
	buffer_destroy_and_null_if_valid(packet);
	buffer_destroy_and_null_if_valid(decrypted_header);

	on_error {
		print_errors(status);
	}
	return_status_destroy_errors(&status);

	return status.status;
}
