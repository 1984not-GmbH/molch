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
#include <exception>
#include <iostream>

#include "../lib/packet.hpp"
#include "../lib/molch.h"
#include "../lib/constants.h"
#include "../lib/molch-exception.hpp"
#include "utils.hpp"
#include "packet-test-lib.hpp"

using namespace Molch;

int main(void) {
	try {
		if (sodium_init() == -1) {
			throw Molch::Exception{status_type::INIT_ERROR, "Failed to initialize libsodium."};
		}

		molch_message_type packet_type{molch_message_type::NORMAL_MESSAGE};
		Buffer header{4, 4};
		header[0] = uchar_to_byte(0x01);
		header[1] = uchar_to_byte(0x02);
		header[2] = uchar_to_byte(0x03);
		header[3] = uchar_to_byte(0x04);
		printf("Packet type: %02x\n\n", static_cast<int>(packet_type));

		//A NORMAL MESSAGE
		printf("NORMAL MESSAGE:\n");
		MessageKey message_key;
		HeaderKey header_key;
		Buffer message{"Hello world!\n"};
		Buffer packet;
		create_and_print_message(
			packet,
			header_key,
			message_key,
			packet_type,
			header,
			message,
			nullptr,
			nullptr,
			nullptr);

		//now extract the metadata
		molch_message_type extracted_packet_type;
		uint32_t extracted_current_protocol_version;
		uint32_t extracted_highest_supported_protocol_version;
		packet_get_metadata_without_verification(
			extracted_current_protocol_version,
			extracted_highest_supported_protocol_version,
			extracted_packet_type,
			packet.span(),
			nullptr,
			nullptr,
			nullptr);

		printf("extracted_packet_type = %u\n", static_cast<int>(extracted_packet_type));
		if (packet_type != extracted_packet_type) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Extracted packet type doesn't match."};
		}
		printf("Packet type matches!\n");

		if (extracted_current_protocol_version != 0) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Extracted current protocol version doesn't match."};
		}
		printf("Current protocol version matches!\n");

		if (extracted_highest_supported_protocol_version != 0) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Extracted highest supported protocol version doesn't match."};
		}
		printf("Highest supoorted protocol version matches (%i)!\n", extracted_highest_supported_protocol_version);

		//NOW A PREKEY MESSAGE
		printf("PREKEY MESSAGE:\n");
		//create the keys
		PublicKey public_identity_key;
		public_identity_key.fillRandom();
		PublicKey public_ephemeral_key;
		public_ephemeral_key.fillRandom();
		PublicKey public_prekey;
		public_prekey.fillRandom();

		packet.clear();

		packet_type = molch_message_type::PREKEY_MESSAGE;
		create_and_print_message(
			packet,
			header_key,
			message_key,
			packet_type,
			header,
			message,
			&public_identity_key,
			&public_ephemeral_key,
			&public_prekey);

		//now extract the metadata
		PublicKey extracted_public_identity_key;
		PublicKey extracted_public_ephemeral_key;
		PublicKey extracted_public_prekey;
		packet_get_metadata_without_verification(
			extracted_current_protocol_version,
			extracted_highest_supported_protocol_version,
			extracted_packet_type,
			packet.span(),
			&extracted_public_identity_key,
			&extracted_public_ephemeral_key,
			&extracted_public_prekey);

		printf("extracted_type = %u\n", static_cast<int>(extracted_packet_type));
		if (packet_type != extracted_packet_type) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Extracted packet type doesn't match."};
		}
		printf("Packet type matches!\n");

		if (extracted_current_protocol_version != 0) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Extracted current protocol version doesn't match."};
		}
		printf("Current protocol version matches!\n");

		if (extracted_highest_supported_protocol_version != 0) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Extracted highest supported protocl version doesn't match."};
		}
		printf("Highest supoorted protocol version matches (%i)!\n", extracted_highest_supported_protocol_version);

		if (public_identity_key != extracted_public_identity_key) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Extracted public identity key doesn't match."};
		}
		printf("Extracted public identity key matches!\n");

		if (public_ephemeral_key != extracted_public_ephemeral_key) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Extratec public ephemeral key doesn't match."};
		}
		printf("Extracted public ephemeral key matches!\n");

		if (public_prekey != extracted_public_prekey) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Extracted public prekey doesn't match."};
		}
		printf("Extracted public prekey matches!\n");
	} catch (const Molch::Exception& exception) {
		exception.print(std::cerr) << std::endl;
		return EXIT_FAILURE;
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
