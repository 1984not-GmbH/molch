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
#include "../lib/constants.h"
#include "utils.hpp"
#include "packet-test-lib.hpp"
#include "exception.hpp"

using namespace Molch;

int main() {
	try {
		TRY_VOID(Molch::sodium_init());

		//generate keys and message
		molch_message_type packet_type{molch_message_type::NORMAL_MESSAGE};
		Buffer header{4, 4};
		header[0] = uchar_to_byte(0x01);
		header[1] = uchar_to_byte(0x02);
		header[2] = uchar_to_byte(0x03);
		header[3] = uchar_to_byte(0x04);
		std::cout << "Packet type: " << static_cast<int>(packet_type) << '\n';
		putchar('\n');

		//NORMAL MESSAGE
		std::cout << "NORMAL MESSAGE\n";
		Buffer message{"Hello world!\n"};
		EmptyableHeaderKey header_key;
		MessageKey message_key;
		Buffer packet;
		create_and_print_message(
			packet,
			header_key,
			message_key,
			packet_type,
			header,
			message,
			std::nullopt);

		//now decrypt the packet
		TRY_WITH_RESULT(decrypted_normal_packet_result, packet_decrypt(packet, header_key, message_key));
		const auto& decrypted_normal_packet{decrypted_normal_packet_result.value()};

		if ((packet_type != decrypted_normal_packet.metadata.packet_type)
			|| (decrypted_normal_packet.metadata.current_protocol_version != 0)
			|| (decrypted_normal_packet.metadata.highest_supported_protocol_version != 0)) {
			throw Molch::Exception{status_type::DATA_FETCH_ERROR, "Failed to retrieve metadata."};
		}


		if (decrypted_normal_packet.header.size() != header.size()) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Decrypted header isn't of the same length!"};
		}
		std::cout << "Decrypted header has the same length.\n";

		//compare headers
		if (header != decrypted_normal_packet.header) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Decrypted header doesn't match."};
		}
		std::cout << "Decrypted header matches.\n\n";

		if (decrypted_normal_packet.message.size() != message.size()) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Decrypted message isn't of the same length."};
		}
		std::cout << "Decrypted message has the same length.\n";

		//compare messages
		if (message != decrypted_normal_packet.message) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Decrypted message doesn't match."};
		}
		std::cout << "Decrypted message matches.\n";

		//PREKEY MESSAGE
		std::cout << "PREKEY MESSAGE\n";
		//create the public keys
		auto prekey_metadata{std::make_optional<PrekeyMetadata>()};
		randombytes_buf(prekey_metadata.value().identity);
		randombytes_buf(prekey_metadata.value().ephemeral);
		randombytes_buf(prekey_metadata.value().prekey);

		packet.clear();

		packet_type = molch_message_type::PREKEY_MESSAGE;

		create_and_print_message(
			packet,
			header_key,
			message_key,
			packet_type,
			header,
			message,
			prekey_metadata);

		//now decrypt the packet
		TRY_WITH_RESULT(decrypted_prekey_packet_result, packet_decrypt(packet, header_key, message_key));
		const auto& decrypted_prekey_packet{decrypted_prekey_packet_result.value()};

		if ((packet_type != decrypted_prekey_packet.metadata.packet_type)
				|| (decrypted_prekey_packet.metadata.current_protocol_version != 0)
				|| (decrypted_prekey_packet.metadata.highest_supported_protocol_version != 0)) {
			throw Molch::Exception{status_type::DATA_FETCH_ERROR, "Failed to retrieve metadata."};
		}

		if (decrypted_prekey_packet.header.size() != header.size()) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Decrypted header isn't of the same length."};
		}
		std::cout << "Decrypted header has the same length!\n";

		//compare headers
		if (header != decrypted_prekey_packet.header) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Decrypted header doesn't match."};
		}
		std::cout << "Decrypted header matches!\n";

		if (decrypted_prekey_packet.message.size() != message.size()) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Decrypted message isn't of the same length."};
		}
		std::cout << "Decrypted message has the same length.\n";

		//compare messages
		if (message != decrypted_prekey_packet.message) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Decrypted message doesn't match."};
		}
		std::cout << "Decrypted message matches.\n";

		if (not decrypted_prekey_packet.metadata.prekey_metadata.has_value()) {
			throw Molch::Exception(status_type::INVALID_VALUE, "No prekey metadata found.");
		}
		const auto& decrypted_prekey_metadata{decrypted_prekey_packet.metadata.prekey_metadata.value()};
		//compare public keys
		if (prekey_metadata.value().identity != decrypted_prekey_metadata.identity) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Extracted public identity key doesn't match."};
		}
		std::cout << "Extracted public identity key matches!\n";

		if (prekey_metadata.value().ephemeral != decrypted_prekey_metadata.ephemeral) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Extracted public ephemeral key doesn't match."};
		}
		std::cout << "Extracted public ephemeral key matches!\n";

		if (prekey_metadata.value().prekey != decrypted_prekey_metadata.prekey) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Extracted public prekey doesn't match."};
		}
		std::cout << "Extracted public prekey matches!\n";
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
