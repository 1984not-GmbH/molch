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
#include <iostream>
#include <exception>

#include "../lib/packet.hpp"
#include "../lib/constants.h"
#include "../lib/molch-exception.hpp"
#include "utils.hpp"
#include "packet-test-lib.hpp"

void create_and_print_message(
		//output
		std::unique_ptr<Buffer>& packet,
		Buffer& header_key, //HEADER_KEY_SIZE
		Buffer& message_key, //MESSAGE_KEY_SIZE
		//inputs
		const molch_message_type packet_type,
		const Buffer& header,
		const Buffer& message,
		//optional inputs (prekey messages only)
		Buffer * const public_identity_key,
		Buffer * const public_ephemeral_key,
		Buffer * const public_prekey) {
	//check input
	if (!header_key.fits(HEADER_KEY_SIZE)
		|| !message_key.fits(MESSAGE_KEY_SIZE)
		|| (packet_type == INVALID)) {
		throw MolchException(INVALID_INPUT, "Invalid input to create_and_print_message.");
	}

	//create header key
	header_key.fillRandom(HEADER_KEY_SIZE);
	printf("Header key (%zu Bytes):\n", header_key.size);
	header_key.printHex(std::cout);
	putchar('\n');

	//create message key
	message_key.fillRandom(MESSAGE_KEY_SIZE);
	printf("Message key (%zu Bytes):\n", message_key.size);
	message_key.printHex(std::cout);
	putchar('\n');

	//print the header (as hex):
	printf("Header (%zu Bytes):\n", header.size);
	header.printHex(std::cout);
	putchar('\n');

	//print the message (as string):
	printf("Message (%zu Bytes):\n%.*s\n\n", message.size, static_cast<int>(message.size), message.content);

	//now encrypt the message
	packet = packet_encrypt(
			packet_type,
			header,
			header_key,
			message,
			message_key,
			public_identity_key,
			public_ephemeral_key,
			public_prekey);

	//print encrypted packet
	printf("Encrypted Packet (%zu Bytes):\n", packet->size);
	packet->printHex(std::cout);
	putchar('\n');
}
