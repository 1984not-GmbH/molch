/* Molch, an implementation of the axolotl ratchet based on libsodium
 *  Copyright (C) 2015-2016 1984not Security GmbH
 *  Author: Max Bruckner (FSMaxB)
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
#include "../lib/molch.h"
#include "../lib/constants.h"
#include "utils.h"
#include "packet-test-lib.h"
#include "tracing.h"

int main(void) {
	if (sodium_init() == -1) {
		return -1;
	}

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
	header->content[0] = 0x01;
	header->content[1] = 0x02;
	header->content[2] = 0x03;
	header->content[3] = 0x04;
	buffer_t *packet = buffer_create_on_heap(3 + crypto_aead_chacha20poly1305_NPUBBYTES + crypto_aead_chacha20poly1305_ABYTES + crypto_secretbox_NONCEBYTES + message->content_length + header->content_length + crypto_secretbox_MACBYTES + 255 + 3 * PUBLIC_KEY_SIZE, 3 + crypto_aead_chacha20poly1305_NPUBBYTES + crypto_aead_chacha20poly1305_ABYTES + crypto_secretbox_NONCEBYTES + message->content_length + header->content_length + crypto_secretbox_MACBYTES + 255 + 3 * PUBLIC_KEY_SIZE);
	unsigned char packet_type = NORMAL_MESSAGE;
	printf("Packet type: %02x\n", packet_type);
	const unsigned char current_protocol_version = 2;
	printf("Current protocol version: %02x\n", current_protocol_version);
	const unsigned char highest_supported_protocol_version = 3;
	printf("Highest supported protocol version: %02x\n", highest_supported_protocol_version);
	putchar('\n');

	//A NORMAL MESSAGE
	printf("NORMAL MESSAGE:\n");
	int status = create_and_print_message(
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
	if (status != 0) {
		goto cleanup;
	}

	//now extract the metadata
	unsigned char extracted_packet_type;
	unsigned char extracted_current_protocol_version;
	unsigned char extracted_highest_supported_protocol_version;
	unsigned char extracted_header_length;
	status = packet_get_metadata_without_verification(
			packet,
			&extracted_packet_type,
			&extracted_current_protocol_version,
			&extracted_highest_supported_protocol_version,
			&extracted_header_length,
			NULL,
			NULL,
			NULL);
	if (status != 0) {
		fprintf(stderr, "ERROR: Couldn't extract metadata from the packet. (%i)\n", status);
		goto cleanup;
	}

	if (packet_type != extracted_packet_type) {
		fprintf(stderr, "ERROR: Extracted packet type doesn't match (%i)!\n", extracted_packet_type);
		status = EXIT_FAILURE;
		goto cleanup;
	}
	printf("Packet type matches!\n");

	if (current_protocol_version != extracted_current_protocol_version) {
		fprintf(stderr, "ERROR: Extracted current protocol version doesn't match (%i)!\n", extracted_current_protocol_version);
		status = EXIT_FAILURE;
		goto cleanup;
	}
	printf("Current protocol version matches!\n");

	if (highest_supported_protocol_version != extracted_highest_supported_protocol_version) {
		fprintf(stderr, "ERROR: Extracted highest supported protocol version doesn't match (%i)!\n", extracted_highest_supported_protocol_version);
		status = EXIT_FAILURE;
		goto cleanup;
	}
	printf("Highest supoorted protocol version matches (%i)!\n", extracted_highest_supported_protocol_version);

	if (header->content_length != extracted_header_length) {
		fprintf(stderr, "ERROR: Extracted header length doesn't match (%i)!\n", extracted_header_length);
		status = EXIT_FAILURE;
		goto cleanup;
	}
	printf("Header length matches!\n");

	//NOW A PREKEY MESSAGE
	printf("PREKEY MESSAGE:\n");
	//create the keys
	status = buffer_fill_random(public_identity_key, PUBLIC_KEY_SIZE);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to generate public identity key. (%i)\n", status);
		goto cleanup;
	}
	status = buffer_fill_random(public_ephemeral_key, PUBLIC_KEY_SIZE);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to generate public ephemeral key. (%i)\n", status);
		goto cleanup;
	}
	status = buffer_fill_random(public_prekey, PUBLIC_KEY_SIZE);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to generate public prekey. (%i)\n", status);
		goto cleanup;
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
	if (status != 0) {
		goto cleanup;
	}

	//now extract the metadata
	status = packet_get_metadata_without_verification(
			packet,
			&extracted_packet_type,
			&extracted_current_protocol_version,
			&extracted_highest_supported_protocol_version,
			&extracted_header_length,
			extracted_public_identity_key,
			extracted_public_ephemeral_key,
			extracted_public_prekey);
	if (status != 0) {
		fprintf(stderr, "ERROR: Couldn't extract metadata from the packet. (%i)\n", status);
		goto cleanup;
	}

	if (packet_type != extracted_packet_type) {
		fprintf(stderr, "ERROR: Extracted packet type doesn't match (%i)!\n", extracted_packet_type);
		status = EXIT_FAILURE;
		goto cleanup;
	}
	printf("Packet type matches!\n");

	if (current_protocol_version != extracted_current_protocol_version) {
		fprintf(stderr, "ERROR: Extracted current protocol version doesn't match (%i)!\n", extracted_current_protocol_version);
		status = EXIT_FAILURE;
		goto cleanup;
	}
	printf("Current protocol version matches!\n");

	if (highest_supported_protocol_version != extracted_highest_supported_protocol_version) {
		fprintf(stderr, "ERROR: Extracted highest supported protocol version doesn't match (%i)!\n", extracted_highest_supported_protocol_version);
		status = EXIT_FAILURE;
		goto cleanup;
	}
	printf("Highest supoorted protocol version matches (%i)!\n", extracted_highest_supported_protocol_version);

	if (header->content_length != extracted_header_length) {
		fprintf(stderr, "ERROR: Extracted header length doesn't match (%i)!\n", extracted_header_length);
		status = EXIT_FAILURE;
		goto cleanup;
	}
	printf("Header length matches!\n");

	if (buffer_compare(public_identity_key, extracted_public_identity_key) != 0) {
		fprintf(stderr, "ERROR: Extracted public identity key doesn't match!\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	printf("Extracted public identity key matches!\n");

	if (buffer_compare(public_ephemeral_key, extracted_public_ephemeral_key) != 0) {
		fprintf(stderr, "ERROR: Extracted public ephemeral key doesn't match!\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	printf("Extracted public ephemeral key matches!\n");

	if (buffer_compare(public_prekey, extracted_public_prekey) != 0) {
		fprintf(stderr, "ERROR: Extracted public prekey doesn't match.\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	printf("Extracted public prekey matches!\n");

cleanup:
	buffer_destroy_from_heap(header_key);
	buffer_destroy_from_heap(message_key);
	buffer_destroy_from_heap(header);
	buffer_destroy_from_heap(packet);
	buffer_destroy_from_heap(public_identity_key);
	buffer_destroy_from_heap(public_ephemeral_key);
	buffer_destroy_from_heap(public_prekey);
	buffer_destroy_from_heap(extracted_public_identity_key);
	buffer_destroy_from_heap(extracted_public_ephemeral_key);
	buffer_destroy_from_heap(extracted_public_prekey);

	return status;
}
