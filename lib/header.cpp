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
#include "zeroed_malloc.hpp"
#include "molch-exception.hpp"
#include "protobuf.hpp"

namespace Molch {
	Buffer header_construct(
			//inputs
			const Buffer& our_public_ephemeral, //PUBLIC_KEY_SIZE
			const uint32_t message_number,
			const uint32_t previous_message_number) {
		ProtobufCHeader header_struct;
		header__init(&header_struct);

		//check input
		if (our_public_ephemeral.size != PUBLIC_KEY_SIZE) {
			throw Exception(INVALID_INPUT, "Invalid input to header_construct.");
		}
		//create buffer for our public ephemeral
		ProtobufCBinaryData protobuf_our_public_ephemeral;
		protobuf_our_public_ephemeral.len = our_public_ephemeral.size;
		protobuf_our_public_ephemeral.data = our_public_ephemeral.content;

		//fill the struct
		header_struct.message_number = message_number;
		header_struct.has_message_number = true;
		header_struct.previous_message_number = previous_message_number;
		header_struct.has_previous_message_number = true;
		header_struct.public_ephemeral_key = protobuf_our_public_ephemeral;
		header_struct.has_public_ephemeral_key = true;

		//allocate the header buffer
		size_t header_length = header__get_packed_size(&header_struct);
		Buffer header(header_length, header_length);

		//pack it
		size_t packed_length = header__pack(&header_struct, header.content);
		if (packed_length != header_length) {
			throw Exception(PROTOBUF_PACK_ERROR, "Packed header has incorrect length.");
		}

		return header;
	}

	void header_extract(
			//outputs
			Buffer& their_public_ephemeral, //PUBLIC_KEY_SIZE
			uint32_t& message_number,
			uint32_t& previous_message_number,
			//intput
			const Buffer& header) {
		//check input
		if (!their_public_ephemeral.fits(PUBLIC_KEY_SIZE)) {
			throw Exception(INVALID_INPUT, "Invalid input to header_extract.");
		}

		//unpack the message
		auto header_struct = std::unique_ptr<ProtobufCHeader,HeaderDeleter>(header__unpack(&protobuf_c_allocators, header.size, header.content));
		if (!header_struct) {
			throw Exception(PROTOBUF_UNPACK_ERROR, "Failed to unpack header.");
		}

		if (!header_struct->has_message_number || !header_struct->has_previous_message_number || !header_struct->has_public_ephemeral_key) {
			throw Exception(PROTOBUF_MISSING_ERROR, "Missing fields in header.");
		}

		if (header_struct->public_ephemeral_key.len != PUBLIC_KEY_SIZE) {
			throw Exception(INCORRECT_BUFFER_SIZE, "The public ephemeral key in the header has an incorrect size.");
		}

		message_number = header_struct->message_number;
		previous_message_number = header_struct->previous_message_number;

		their_public_ephemeral.cloneFromRaw(header_struct->public_ephemeral_key.data, header_struct->public_ephemeral_key.len);
	}
}
