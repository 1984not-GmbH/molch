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

int main(void) {
	//generate keys and message
	buffer_t *header_key = buffer_create_on_heap(HEADER_KEY_SIZE, HEADER_KEY_SIZE);
	buffer_t *message_key = buffer_create_on_heap(MESSAGE_KEY_SIZE, MESSAGE_KEY_SIZE);
	buffer_t *public_identity_key = buffer_create_on_heap(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	buffer_t *public_ephemeral_key = buffer_create_on_heap(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	buffer_t *public_prekey = buffer_create_on_heap(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	buffer_t *extracted_public_identity_key = buffer_create_on_heap(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	buffer_t *extracted_public_ephemeral_key = buffer_create_on_heap(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	buffer_t *extracted_public_prekey = buffer_create_on_heap(PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
	buffer_create_from_string(message, "Hello world!\n");
	buffer_t *header = buffer_create_on_heap(4, 4);
	buffer_t *packet = NULL;

	return_status status = return_status_init();

	if (sodium_init() == -1) {
		throw(INIT_ERROR, "Failed to initialize libsodium.");
	}

	header->content[0] = 0x01;
	header->content[1] = 0x02;
	header->content[2] = 0x03;
	header->content[3] = 0x04;
	molch_message_type packet_type = NORMAL_MESSAGE;
	printf("Packet type: %02x\n", packet_type);
	putchar('\n');

	//A NORMAL MESSAGE
	printf("NORMAL MESSAGE:\n");
	int status_int = 0;
	status = create_and_print_message(
			&packet,
			header_key,
			message_key,
			packet_type,
			header,
			message,
			NULL,
			NULL,
			NULL);
	throw_on_error(GENERIC_ERROR, "Failed to create and print message.");

	//now extract the metadata
	molch_message_type extracted_packet_type;
	uint32_t extracted_current_protocol_version;
	uint32_t extracted_highest_supported_protocol_version;
	status = packet_get_metadata_without_verification(
			&extracted_current_protocol_version,
			&extracted_highest_supported_protocol_version,
			&extracted_packet_type,
			packet,
			NULL,
			NULL,
			NULL);
	throw_on_error(DATA_FETCH_ERROR, "Couldn't extract metadata from the packet.");

	printf("extracted_packet_type = %u\n", extracted_packet_type);
	if (packet_type != extracted_packet_type) {
		throw(INVALID_VALUE, "Extracted packet type doesn't match.");
	}
	printf("Packet type matches!\n");

	if (extracted_current_protocol_version != 0) {
		throw(INVALID_VALUE, "Extracted current protocol version doesn't match.");
	}
	printf("Current protocol version matches!\n");

	if (extracted_highest_supported_protocol_version != 0) {
		throw(INVALID_VALUE, "Extracted highest supported protocol version doesn't match.");
	}
	printf("Highest supoorted protocol version matches (%i)!\n", extracted_highest_supported_protocol_version);

	//NOW A PREKEY MESSAGE
	printf("PREKEY MESSAGE:\n");
	//create the keys
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

	buffer_destroy_from_heap_and_null_if_valid(packet);

	packet_type = PREKEY_MESSAGE;
	status = create_and_print_message(
			&packet,
			header_key,
			message_key,
			packet_type,
			header,
			message,
			public_identity_key,
			public_ephemeral_key,
			public_prekey);
	throw_on_error(GENERIC_ERROR, "Failed to create and print message.");

	//now extract the metadata
	status = packet_get_metadata_without_verification(
			&extracted_current_protocol_version,
			&extracted_highest_supported_protocol_version,
			&extracted_packet_type,
			packet,
			extracted_public_identity_key,
			extracted_public_ephemeral_key,
			extracted_public_prekey);
	throw_on_error(DATA_FETCH_ERROR, "Couldn't extract metadata from the packet.");

	printf("extracted_type = %u\n", extracted_packet_type);
	if (packet_type != extracted_packet_type) {
		throw(INVALID_VALUE, "Extracted packet type doesn't match.");
	}
	printf("Packet type matches!\n");

	if (extracted_current_protocol_version != 0) {
		throw(INVALID_VALUE, "Extracted current protocol version doesn't match.");
	}
	printf("Current protocol version matches!\n");

	if (extracted_highest_supported_protocol_version != 0) {
		throw(INVALID_VALUE, "Extracted highest supported protocl version doesn't match.");
	}
	printf("Highest supoorted protocol version matches (%i)!\n", extracted_highest_supported_protocol_version);

	if (buffer_compare(public_identity_key, extracted_public_identity_key) != 0) {
		throw(INVALID_VALUE, "Extracted public identity key doesn't match.");
	}
	printf("Extracted public identity key matches!\n");

	if (buffer_compare(public_ephemeral_key, extracted_public_ephemeral_key) != 0) {
		throw(INVALID_VALUE, "Extratec public ephemeral key doesn't match.");
	}
	printf("Extracted public ephemeral key matches!\n");

	if (buffer_compare(public_prekey, extracted_public_prekey) != 0) {
		throw(INVALID_VALUE, "Extracted public prekey doesn't match.");
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
