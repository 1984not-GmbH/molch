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
	//generate keys and message
	Buffer *header_key = Buffer::create(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	Buffer *message_key = Buffer::create(MESSAGE_KEY_SIZE, MESSAGE_KEY_SIZE);
	Buffer *public_identity_key = Buffer::create(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	Buffer *public_ephemeral_key = Buffer::create(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	Buffer *public_prekey = Buffer::create(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	Buffer *extracted_public_identity_key = Buffer::create(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	Buffer *extracted_public_ephemeral_key = Buffer::create(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	Buffer *extracted_public_prekey = Buffer::create(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	Buffer message("Hello world!\n");
	Buffer *header = Buffer::create(4, 4);
	Buffer *packet = nullptr;

	return_status status = return_status_init();

	molch_message_type packet_type = NORMAL_MESSAGE;

	if (sodium_init() == -1) {
		THROW(INIT_ERROR, "Failed to initialize libsodium.");
	}

	header->content[0] = 0x01;
	header->content[1] = 0x02;
	header->content[2] = 0x03;
	header->content[3] = 0x04;
	printf("Packet type: %02x\n", packet_type);
	putchar('\n');

	//A NORMAL MESSAGE
	printf("NORMAL MESSAGE:\n");
	status = create_and_print_message(
			&packet,
			header_key,
			message_key,
			packet_type,
			header,
			&message,
			nullptr,
			nullptr,
			nullptr);
	THROW_on_error(GENERIC_ERROR, "Failed to create and print message.");

	//now extract the metadata
	molch_message_type extracted_packet_type;
	uint32_t extracted_current_protocol_version;
	uint32_t extracted_highest_supported_protocol_version;
	status = packet_get_metadata_without_verification(
			extracted_current_protocol_version,
			extracted_highest_supported_protocol_version,
			extracted_packet_type,
			*packet,
			nullptr,
			nullptr,
			nullptr);
	THROW_on_error(DATA_FETCH_ERROR, "Couldn't extract metadata from the packet.");

	printf("extracted_packet_type = %u\n", extracted_packet_type);
	if (packet_type != extracted_packet_type) {
		THROW(INVALID_VALUE, "Extracted packet type doesn't match.");
	}
	printf("Packet type matches!\n");

	if (extracted_current_protocol_version != 0) {
		THROW(INVALID_VALUE, "Extracted current protocol version doesn't match.");
	}
	printf("Current protocol version matches!\n");

	if (extracted_highest_supported_protocol_version != 0) {
		THROW(INVALID_VALUE, "Extracted highest supported protocol version doesn't match.");
	}
	printf("Highest supoorted protocol version matches (%i)!\n", extracted_highest_supported_protocol_version);

	//NOW A PREKEY MESSAGE
	printf("PREKEY MESSAGE:\n");
	//create the keys
	{
		int status_int = public_identity_key->fillRandom(PUBLIC_KEY_SIZE);
		if (status_int != 0) {
			THROW(KEYGENERATION_FAILED, "Failed to generate public identity key.");
		}
	}
	{
		int status_int = public_ephemeral_key->fillRandom(PUBLIC_KEY_SIZE);
		if (status_int != 0) {
			THROW(KEYGENERATION_FAILED, "Failed to generate public ephemeral key.");
		}
	}
	{
		int status_int = public_prekey->fillRandom(PUBLIC_KEY_SIZE);
		if (status_int != 0) {
			THROW(KEYGENERATION_FAILED, "Failed to generate public prekey.");
		}
	}

	buffer_destroy_from_heap_and_null_if_valid(packet);

	packet_type = PREKEY_MESSAGE;
	status = create_and_print_message(
			&packet,
			header_key,
			message_key,
			packet_type,
			header,
			&message,
			public_identity_key,
			public_ephemeral_key,
			public_prekey);
	THROW_on_error(GENERIC_ERROR, "Failed to create and print message.");

	//now extract the metadata
	status = packet_get_metadata_without_verification(
			extracted_current_protocol_version,
			extracted_highest_supported_protocol_version,
			extracted_packet_type,
			*packet,
			extracted_public_identity_key,
			extracted_public_ephemeral_key,
			extracted_public_prekey);
	THROW_on_error(DATA_FETCH_ERROR, "Couldn't extract metadata from the packet.");

	printf("extracted_type = %u\n", extracted_packet_type);
	if (packet_type != extracted_packet_type) {
		THROW(INVALID_VALUE, "Extracted packet type doesn't match.");
	}
	printf("Packet type matches!\n");

	if (extracted_current_protocol_version != 0) {
		THROW(INVALID_VALUE, "Extracted current protocol version doesn't match.");
	}
	printf("Current protocol version matches!\n");

	if (extracted_highest_supported_protocol_version != 0) {
		THROW(INVALID_VALUE, "Extracted highest supported protocl version doesn't match.");
	}
	printf("Highest supoorted protocol version matches (%i)!\n", extracted_highest_supported_protocol_version);

	if (public_identity_key->compare(extracted_public_identity_key) != 0) {
		THROW(INVALID_VALUE, "Extracted public identity key doesn't match.");
	}
	printf("Extracted public identity key matches!\n");

	if (public_ephemeral_key->compare(extracted_public_ephemeral_key) != 0) {
		THROW(INVALID_VALUE, "Extratec public ephemeral key doesn't match.");
	}
	printf("Extracted public ephemeral key matches!\n");

	if (public_prekey->compare(extracted_public_prekey) != 0) {
		THROW(INVALID_VALUE, "Extracted public prekey doesn't match.");
	}
	printf("Extracted public prekey matches!\n");

cleanup:
	buffer_destroy_from_heap_and_null_if_valid(header_key);
	buffer_destroy_from_heap_and_null_if_valid(message_key);
	buffer_destroy_from_heap_and_null_if_valid(header);
	buffer_destroy_from_heap_and_null_if_valid(packet);
	buffer_destroy_from_heap_and_null_if_valid(public_identity_key);
	buffer_destroy_from_heap_and_null_if_valid(public_ephemeral_key);
	buffer_destroy_from_heap_and_null_if_valid(public_prekey);
	buffer_destroy_from_heap_and_null_if_valid(extracted_public_identity_key);
	buffer_destroy_from_heap_and_null_if_valid(extracted_public_ephemeral_key);
	buffer_destroy_from_heap_and_null_if_valid(extracted_public_prekey);

	on_error {
		print_errors(&status);
	}
	return_status_destroy_errors(&status);

	return status.status;
}
