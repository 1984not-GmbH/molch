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
#include "../lib/constants.h"
#include "../lib/molch.h"
#include "utils.h"
#include "packet-test-lib.h"

int main(void) noexcept {

	Buffer message("Hello world!\n");

	//create buffers
	Buffer header_key(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	Buffer message_key(MESSAGE_KEY_SIZE, MESSAGE_KEY_SIZE);
	Buffer public_identity_key(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	Buffer public_ephemeral_key(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	Buffer public_prekey(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	Buffer extracted_public_identity_key(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	Buffer extracted_public_ephemeral_key(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	Buffer extracted_public_prekey(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	Buffer header(4, 4);
	Buffer *packet = nullptr;
	Buffer *decrypted_header = nullptr;
	Buffer *decrypted_message = nullptr;

	return_status status = return_status_init();

	molch_message_type packet_type = NORMAL_MESSAGE;

	throw_on_invalid_buffer(header_key);
	throw_on_invalid_buffer(message_key);
	throw_on_invalid_buffer(public_identity_key);
	throw_on_invalid_buffer(public_ephemeral_key);
	throw_on_invalid_buffer(public_prekey);
	throw_on_invalid_buffer(extracted_public_identity_key);
	throw_on_invalid_buffer(extracted_public_ephemeral_key);
	throw_on_invalid_buffer(extracted_public_prekey);
	throw_on_invalid_buffer(header);

	if (sodium_init() == -1) {
		THROW(INIT_ERROR, "Failed to initialize libsodium.");
	}

	//generate keys and message
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
	THROW_on_error(CREATION_ERROR, "Failed to create and print normal message.");

	//now decrypt the packet
	molch_message_type extracted_packet_type;
	uint32_t extracted_current_protocol_version;
	uint32_t extracted_highest_supported_protocol_version;
	status = packet_decrypt(
			extracted_current_protocol_version,
			extracted_highest_supported_protocol_version,
			extracted_packet_type,
			decrypted_header,
			decrypted_message,
			*packet,
			header_key,
			message_key,
			nullptr,
			nullptr,
			nullptr);
	THROW_on_error(DECRYPT_ERROR, "Failed to decrypt the packet.");

	if ((packet_type != extracted_packet_type)
		|| (extracted_current_protocol_version != 0)
		|| (extracted_highest_supported_protocol_version != 0)) {
		THROW(DATA_FETCH_ERROR, "Failed to retrieve metadata.");
	}


	if (decrypted_header->content_length != header.content_length) {
		THROW(INVALID_VALUE, "Decrypted header isn't of the same length!");
	}
	printf("Decrypted header has the same length.\n");

	//compare headers
	if (header.compare(decrypted_header) != 0) {
		THROW(INVALID_VALUE, "Decrypted header doesn't match.");
	}
	printf("Decrypted header matches.\n\n");

	if (decrypted_message->content_length != message.content_length) {
		THROW(INVALID_VALUE, "Decrypted message isn't of the same length.");
	}
	printf("Decrypted message has the same length.\n");

	//compare messages
	if (message.compare(decrypted_message) != 0) {
		THROW(INVALID_VALUE, "Decrypted message doesn't match.");
	}
	printf("Decrypted message matches.\n");

	//PREKEY MESSAGE
	printf("PREKEY MESSAGE\n");
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

	buffer_destroy_from_heap_and_null_if_valid(decrypted_header);
	buffer_destroy_from_heap_and_null_if_valid(decrypted_message);
	buffer_destroy_from_heap_and_null_if_valid(packet);

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
	THROW_on_error(GENERIC_ERROR, "Failed to create and print prekey message.");

	//now decrypt the packet
	status = packet_decrypt(
			extracted_current_protocol_version,
			extracted_highest_supported_protocol_version,
			extracted_packet_type,
			decrypted_header,
			decrypted_message,
			*packet,
			header_key,
			message_key,
			&extracted_public_identity_key,
			&extracted_public_ephemeral_key,
			&extracted_public_prekey);
	THROW_on_error(DECRYPT_ERROR, "Failed to decrypt the packet.");

	if ((packet_type != extracted_packet_type)
			|| (extracted_current_protocol_version != 0)
			|| (extracted_highest_supported_protocol_version != 0)) {
		THROW(DATA_FETCH_ERROR, "Failed to retrieve metadata.");
	}

	if (decrypted_header->content_length != header.content_length) {
		THROW(INVALID_VALUE, "Decrypted header isn't of the same length.");
	}
	printf("Decrypted header has the same length!\n");

	//compare headers
	if (header.compare(decrypted_header) != 0) {
		THROW(INVALID_VALUE, "Decrypted header doesn't match.");
	}
	printf("Decrypted header matches!\n");

	if (decrypted_message->content_length != message.content_length) {
		THROW(INVALID_VALUE, "Decrypted message isn't of the same length.");
	}
	printf("Decrypted message has the same length.\n");

	//compare messages
	if (message.compare(decrypted_message) != 0) {
		THROW(INVALID_VALUE, "Decrypted message doesn't match.");
	}
	printf("Decrypted message matches.\n");

	//compare public keys
	if (public_identity_key.compare(&extracted_public_identity_key) != 0) {
		THROW(INVALID_VALUE, "Extracted public identity key doesn't match.");
	}
	printf("Extracted public identity key matches!\n");

	if (public_ephemeral_key.compare(&extracted_public_ephemeral_key) != 0) {
		THROW(INVALID_VALUE, "Extracted public ephemeral key doesn't match.");
	}
	printf("Extracted public ephemeral key matches!\n");

	if (public_prekey.compare(&extracted_public_prekey) != 0) {
		THROW(INVALID_VALUE, "Extracted public prekey doesn't match.");
	}
	printf("Extracted public prekey matches!\n");

cleanup:
	buffer_destroy_from_heap_and_null_if_valid(packet);
	buffer_destroy_from_heap_and_null_if_valid(decrypted_header);
	buffer_destroy_from_heap_and_null_if_valid(decrypted_message);

	on_error {
		print_errors(status);
	}
	return_status_destroy_errors(&status);

	return status.status;
}
