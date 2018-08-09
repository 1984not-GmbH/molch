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

		//generate message
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
		Buffer packet;
		Buffer message{"Hello world!\n"};
		EmptyableHeaderKey header_key;
		MessageKey message_key;
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

		//now decrypt the header
		TRY_WITH_RESULT(normal_header_result, packet_decrypt_header(packet, header_key));
		const auto& normal_header{normal_header_result.value()};


		if (normal_header.size() != header.size()) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Decrypted header isn't of the same length."};
		}
		printf("Decrypted header has the same length.\n\n");

		//compare headers
		if (header != normal_header) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Decrypted header doesn't match."};
		}
		printf("Decrypted header matches.\n\n");

		//check if it decrypts manipulated packets (manipulated metadata)
		printf("Manipulating header length.\n");
		unsigned char manipulated_byte{byte_to_uchar(packet[2])};
		++manipulated_byte;
		packet[2] = uchar_to_byte(manipulated_byte);
		const auto manipulated_metadata_header = packet_decrypt_header(packet, header_key);
		if (manipulated_metadata_header.has_value()) {
			throw Molch::Exception{status_type::GENERIC_ERROR, "Manipulated packet was accepted."};
		}
		printf("Header manipulation detected.\n\n");

		//repair manipulation
		--manipulated_byte;
		packet[2] = uchar_to_byte(manipulated_byte);
		//check if it decrypts manipulated packets (manipulated header)
		printf("Manipulate header.\n");
		packet[3 + crypto_aead_chacha20poly1305_NPUBBYTES + 1] ^= uchar_to_byte(0x12);
		const auto manipulated_header_header = packet_decrypt_header(packet, header_key);
		if (manipulated_header_header.has_value()) {
			throw Molch::Exception{status_type::GENERIC_ERROR, "Manipulated packet was accepted."};
		}
		printf("Header manipulation detected!\n\n");

		//undo header manipulation
		packet[3 + crypto_aead_chacha20poly1305_NPUBBYTES + 1] ^= uchar_to_byte(0x12);

		//PREKEY MESSAGE
		printf("PREKEY_MESSAGE\n");
		//create the public keys
		EmptyablePublicKey public_identity_key;
		public_identity_key.fillRandom();
		EmptyablePublicKey public_ephemeral_key;
		public_ephemeral_key.fillRandom();
		EmptyablePublicKey public_prekey;
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

		//now decrypt the header
		TRY_WITH_RESULT(prekey_header_result, packet_decrypt_header(packet, header_key));
		const auto& prekey_header{prekey_header_result.value()};
		if (prekey_header.size() != header.size()) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Decrypted header isn't of the same length."};
		}
		printf("Decrypted header has the same length.\n\n");

		//compare headers
		if (header != prekey_header) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Decrypted header doesn't match."};
		}
		printf("Decrypted header matches.\n");
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
