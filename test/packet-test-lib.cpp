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

#include "../lib/packet.hpp"
#include "../lib/constants.h"
#include "../lib/gsl.hpp"
#include "utils.hpp"
#include "packet-test-lib.hpp"

using namespace Molch;

MOLCH_PUBLIC(void) create_and_print_message(
		//output
		Buffer& packet,
		EmptyableHeaderKey& header_key,
		MessageKey& message_key,
		//inputs
		const molch_message_type packet_type,
		const Buffer& header,
		const Buffer& message,
		//optional inputs (prekey messages only)
		EmptyablePublicKey * const public_identity_key,
		EmptyablePublicKey * const public_ephemeral_key,
		EmptyablePublicKey * const public_prekey) {
	//check input
	Expects(packet_type != molch_message_type::INVALID);

	//create header key
	header_key.fillRandom();
	printf("Header key (%zu Bytes):\n", header_key.size());
	header_key.printHex(std::cout);
	putchar('\n');

	//create message key
	message_key.fillRandom();
	printf("Message key (%zu Bytes):\n", message_key.size());
	std::cout << message_key;
	putchar('\n');

	//print the header (as hex):
	printf("Header (%zu Bytes):\n", header.size());
	header.printHex(std::cout);
	putchar('\n');

	//print the message (as string):
	printf("Message (%zu Bytes):\n%.*s\n\n", message.size(), static_cast<int>(message.size()), byte_to_uchar(message.data()));

	std::optional<PrekeyMetadata> prekey_metadata;
	if ((public_identity_key != nullptr) and (not public_identity_key->empty)
			and (public_ephemeral_key != nullptr) and (not public_ephemeral_key->empty)
			and (public_prekey != nullptr) and (not public_prekey->empty)) {
		prekey_metadata = std::make_optional<PrekeyMetadata>();
		auto& metadata{prekey_metadata.value()};
		metadata.identity = *public_identity_key;
		metadata.ephemeral = *public_ephemeral_key;
		metadata.prekey = *public_prekey;
	}

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
	printf("Encrypted Packet (%zu Bytes):\n", packet.size());
	packet.printHex(std::cout);
	putchar('\n');
}
