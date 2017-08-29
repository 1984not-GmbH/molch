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

#include "header.hpp"
#include "constants.h"
#include "molch-exception.hpp"
#include "protobuf.hpp"

namespace Molch {
	Buffer header_construct(
			//inputs
			const PublicKey& our_public_ephemeral, //PUBLIC_KEY_SIZE
			const uint32_t message_number,
			const uint32_t previous_message_number) {
		Expects(!our_public_ephemeral.empty);

		ProtobufCHeader header_struct;
		header__init(&header_struct);

		//create buffer for our public ephemeral
		ProtobufCBinaryData protobuf_our_public_ephemeral;
		protobuf_our_public_ephemeral.len = our_public_ephemeral.size();
		protobuf_our_public_ephemeral.data = const_cast<uint8_t*>(byte_to_uchar(our_public_ephemeral.data()));

		//fill the struct
		header_struct.message_number = message_number;
		header_struct.has_message_number = true;
		header_struct.previous_message_number = previous_message_number;
		header_struct.has_previous_message_number = true;
		header_struct.public_ephemeral_key = protobuf_our_public_ephemeral;
		header_struct.has_public_ephemeral_key = true;

		//allocate the header buffer
		auto header_length{header__get_packed_size(&header_struct)};
		Buffer header{header_length, header_length};

		//pack it
		auto packed_length{header__pack(&header_struct, byte_to_uchar(header.content))};
		if (packed_length != header_length) {
			throw Exception{status_type::PROTOBUF_PACK_ERROR, "Packed header has incorrect length."};
		}

		return header;
	}

	void header_extract(
			//outputs
			PublicKey& their_public_ephemeral, //PUBLIC_KEY_SIZE
			uint32_t& message_number,
			uint32_t& previous_message_number,
			//intput
			const gsl::span<const gsl::byte> header) {
		//unpack the message
		auto header_struct{std::unique_ptr<ProtobufCHeader,HeaderDeleter>(header__unpack(&protobuf_c_allocator, narrow(header.size()), byte_to_uchar(header.data())))};
		if (!header_struct) {
			throw Exception{status_type::PROTOBUF_UNPACK_ERROR, "Failed to unpack header."};
		}

		if (!header_struct->has_message_number || !header_struct->has_previous_message_number || !header_struct->has_public_ephemeral_key) {
			throw Exception{status_type::PROTOBUF_MISSING_ERROR, "Missing fields in header."};
		}

		if (header_struct->public_ephemeral_key.len != PUBLIC_KEY_SIZE) {
			throw Exception{status_type::INCORRECT_BUFFER_SIZE, "The public ephemeral key in the header has an incorrect size."};
		}

		message_number = header_struct->message_number;
		previous_message_number = header_struct->previous_message_number;

		their_public_ephemeral.set({
				uchar_to_byte(header_struct->public_ephemeral_key.data),
				narrow(header_struct->public_ephemeral_key.len)});
	}
}
