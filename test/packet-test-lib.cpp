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
#include <iostream>
#include <string_view>

#include "../lib/packet.hpp"
#include "molch/constants.h"
#include "../lib/gsl.hpp"
#include "utils.hpp"
#include "packet-test-lib.hpp"
#include "exception.hpp"

using namespace Molch;

void create_and_print_message(
		//output
		Buffer& packet,
		EmptyableHeaderKey& header_key,
		MessageKey& message_key,
		//inputs
		const molch_message_type packet_type,
		const Buffer& header,
		const Buffer& message,
		const std::optional<PrekeyMetadata>& prekey_metadata) {
	//check input
	Expects(packet_type != molch_message_type::INVALID);

	//create header key
	randombytes_buf(header_key);
	header_key.empty = false;
	std::cout << "Header key (" << header_key.size() << " Bytes):\n";
	std::cout << header_key;
	putchar('\n');

	//create message key
	randombytes_buf(message_key);
	std::cout << "Message key (" << message_key.size() << " Bytes):\n";
	std::cout << message_key;
	putchar('\n');

	//print the header (as hex):
	std::cout << "Header (" << header.size() << "%zu Bytes):\n";
	std::cout << header;
	putchar('\n');

	//print the message (as string):
	std::cout << "Message (" << message.size() << " Bytes):\n" << std::string_view(byte_to_char(message.data()), message.size()) << "\n\n";

	//now encrypt the message
	TRY_WITH_RESULT(packet_result, packet_encrypt(
			packet_type,
			header,
			header_key,
			message,
			message_key,
			prekey_metadata));
	packet = std::move(packet_result.value());

	//print encrypted packet
	std::cout << "Encrypted Packet (" << packet.size() << " Bytes):\n";
	std::cout << packet;
	putchar('\n');
}
