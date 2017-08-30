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
		if(sodium_init() == -1) {
			throw Molch::Exception{status_type::INIT_ERROR, "Failed to initialize libsodium."};
		}

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
		HeaderKey header_key;
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
		auto decrypted_header{packet_decrypt_header(packet.span(), header_key)};


		if (!decrypted_header.value().contains(header.size())) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Decrypted header isn't of the same length."};
		}
		printf("Decrypted header has the same length.\n\n");

		//compare headers
		if (header != decrypted_header.value()) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Decrypted header doesn't match."};
		}
		printf("Decrypted header matches.\n\n");

		//check if it decrypts manipulated packets (manipulated metadata)
		printf("Manipulating header length.\n");
		unsigned char manipulated_byte{byte_to_uchar(packet[2])};
		++manipulated_byte;
		packet[2] = uchar_to_byte(manipulated_byte);
		auto decryption_failed{false};
		try {
			decrypted_header = packet_decrypt_header(packet.span(), header_key);
		} catch (const Molch::Exception& exception) {
			decryption_failed = true;
		}
		if (!decryption_failed) {
			throw Molch::Exception{status_type::GENERIC_ERROR, "Manipulated packet was accepted."};
		}

		printf("Header manipulation detected.\n\n");

		//repair manipulation
		--manipulated_byte;
		packet[2] = uchar_to_byte(manipulated_byte);
		//check if it decrypts manipulated packets (manipulated header)
		printf("Manipulate header.\n");
		packet[3 + crypto_aead_chacha20poly1305_NPUBBYTES + 1] ^= uchar_to_byte(0x12);
		try {
			decrypted_header = packet_decrypt_header(packet.span(), header_key);
		} catch (const Molch::Exception& exception) {
			decryption_failed = true;
		}
		if (!decryption_failed) {
			throw Molch::Exception{status_type::GENERIC_ERROR, "Manipulated packet was accepted."};
		}

		printf("Header manipulation detected!\n\n");

		//undo header manipulation
		packet[3 + crypto_aead_chacha20poly1305_NPUBBYTES + 1] ^= uchar_to_byte(0x12);

		//PREKEY MESSAGE
		printf("PREKEY_MESSAGE\n");
		//create the public keys
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

		//now decrypt the header
		decrypted_header = packet_decrypt_header(packet.span(), header_key);
		if (!decrypted_header.value().contains(header.size())) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Decrypted header isn't of the same length."};
		}
		printf("Decrypted header has the same length.\n\n");

		//compare headers
		if (header != decrypted_header.value()) {
			throw Molch::Exception{status_type::INVALID_VALUE, "Decrypted header doesn't match."};
		}
		printf("Decrypted header matches.\n");
	} catch (const Molch::Exception& exception) {
		exception.print(std::cerr) << std::endl;
		return EXIT_FAILURE;
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
