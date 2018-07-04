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
		printf("Packet type: %02x\n", static_cast<int>(packet_type));
		putchar('\n');

		//NORMAL MESSAGE
		printf("NORMAL MESSAGE\n");
		Buffer message{"Hello world!\n"};
		HeaderKey header_key;
		MessageKey message_key;
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

		//now decrypt the packet
		molch_message_type extracted_packet_type;
		std::optional<Buffer> decrypted_header;
		std::optional<Buffer> decrypted_message;
		uint32_t extracted_current_protocol_version;
		uint32_t extracted_highest_supported_protocol_version;
		packet_decrypt(
			extracted_current_protocol_version,
			extracted_highest_supported_protocol_version,
			extracted_packet_type,
			decrypted_header,
			decrypted_message,
			packet,
			header_key,
			message_key,
			nullptr,
			nullptr,
			nullptr);

		if ((packet_type != extracted_packet_type)
			|| (extracted_current_protocol_version != 0)
			|| (extracted_highest_supported_protocol_version != 0)) {
			throw Molch::Exception{status_type::DATA_FETCH_ERROR, "Failed to retrieve metadata."};
		}


		if (decrypted_header.value().size() != header.size()) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Decrypted header isn't of the same length!"};
		}
		printf("Decrypted header has the same length.\n");

		//compare headers
		if (header != decrypted_header.value()) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Decrypted header doesn't match."};
		}
		printf("Decrypted header matches.\n\n");

		if (decrypted_message.value().size() != message.size()) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Decrypted message isn't of the same length."};
		}
		printf("Decrypted message has the same length.\n");

		//compare messages
		if (message != decrypted_message.value()) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Decrypted message doesn't match."};
		}
		printf("Decrypted message matches.\n");

		//PREKEY MESSAGE
		printf("PREKEY MESSAGE\n");
		//create the public keys
		PublicKey public_identity_key;
		public_identity_key.fillRandom();
		PublicKey public_ephemeral_key;
		public_ephemeral_key.fillRandom();
		PublicKey public_prekey;
		public_prekey.fillRandom();

		decrypted_header.value().clear();
		decrypted_message.value().clear();
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

		//now decrypt the packet
		PublicKey extracted_public_identity_key;
		PublicKey extracted_public_ephemeral_key;
		PublicKey extracted_public_prekey;
		packet_decrypt(
			extracted_current_protocol_version,
			extracted_highest_supported_protocol_version,
			extracted_packet_type,
			decrypted_header,
			decrypted_message,
			packet,
			header_key,
			message_key,
			&extracted_public_identity_key,
			&extracted_public_ephemeral_key,
			&extracted_public_prekey);

		if ((packet_type != extracted_packet_type)
				|| (extracted_current_protocol_version != 0)
				|| (extracted_highest_supported_protocol_version != 0)) {
			throw Molch::Exception{status_type::DATA_FETCH_ERROR, "Failed to retrieve metadata."};
		}

		if (decrypted_header.value().size() != header.size()) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Decrypted header isn't of the same length."};
		}
		printf("Decrypted header has the same length!\n");

		//compare headers
		if (header != decrypted_header.value()) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Decrypted header doesn't match."};
		}
		printf("Decrypted header matches!\n");

		if (decrypted_message.value().size() != message.size()) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Decrypted message isn't of the same length."};
		}
		printf("Decrypted message has the same length.\n");

		//compare messages
		if (message != decrypted_message.value()) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Decrypted message doesn't match."};
		}
		printf("Decrypted message matches.\n");

		//compare public keys
		if (public_identity_key != extracted_public_identity_key) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Extracted public identity key doesn't match."};
		}
		printf("Extracted public identity key matches!\n");

		if (public_ephemeral_key != extracted_public_ephemeral_key) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Extracted public ephemeral key doesn't match."};
		}
		printf("Extracted public ephemeral key matches!\n");

		if (public_prekey != extracted_public_prekey) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Extracted public prekey doesn't match."};
		}
		printf("Extracted public prekey matches!\n");
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
