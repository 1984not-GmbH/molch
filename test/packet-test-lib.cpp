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
#include "utils.h"
#include "packet-test-lib.h"

return_status create_and_print_message(
		//output
		Buffer*& packet,
		Buffer& header_key, //HEADER_KEY_SIZE
		Buffer& message_key, //MESSAGE_KEY_SIZE
		//inputs
		const molch_message_type packet_type,
		Buffer& header,
		Buffer& message,
		//optional inputs (prekey messages only)
		Buffer * const public_identity_key,
		Buffer * const public_ephemeral_key,
		Buffer * const public_prekey) noexcept {
	return_status status = return_status_init();

	//check input
	if ((header_key.getBufferLength() < HEADER_KEY_SIZE)
		|| (message_key.getBufferLength() < MESSAGE_KEY_SIZE)
		|| (packet_type == INVALID)) {
		THROW(INVALID_INPUT, "Invalid input to create_and_print_message.");
	}

	//create header key
	if (header_key.fillRandom(HEADER_KEY_SIZE) != 0) {
		THROW(KEYGENERATION_FAILED, "Failed to generate header key.");
	}
	printf("Header key (%zu Bytes):\n", header_key.content_length);
	print_hex(header_key);
	putchar('\n');

	//create message key
	if (message_key.fillRandom(MESSAGE_KEY_SIZE) != 0) {
		THROW(KEYGENERATION_FAILED, "Failed to generate message key.");
	}
	printf("Message key (%zu Bytes):\n", message_key.content_length);
	print_hex(message_key);
	putchar('\n');

	//print the header (as hex):
	printf("Header (%zu Bytes):\n", header.content_length);
	print_hex(header);
	putchar('\n');

	//print the message (as string):
	printf("Message (%zu Bytes):\n%.*s\n\n", message.content_length, (int)message.content_length, message.content);

	//now encrypt the message
	status = packet_encrypt(
			packet,
			packet_type,
			header,
			header_key,
			message,
			message_key,
			public_identity_key,
			public_ephemeral_key,
			public_prekey);
	THROW_on_error(ENCRYPT_ERROR, "Failed to encrypt message and header.");

	//print encrypted packet
	printf("Encrypted Packet (%zu Bytes):\n", packet->content_length);
	print_hex(*packet);
	putchar('\n');

cleanup:
	on_error {
		header_key.clear();
		message_key.clear();
	}

	return status;
}
