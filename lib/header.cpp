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

extern "C" {
	#include <header.pb-c.h>
}
#include "header.h"
#include "constants.h"
#include "zeroed_malloc.h"

return_status header_construct(
		//output
		buffer_t ** const header,
		//inputs
		const buffer_t * const our_public_ephemeral, //PUBLIC_KEY_SIZE
		const uint32_t message_number,
		const uint32_t previous_message_number) {
	return_status status = return_status_init();

	Header header_struct = HEADER__INIT;

	//check input
	if ((header == nullptr)
			|| (our_public_ephemeral == nullptr) || (our_public_ephemeral->content_length != PUBLIC_KEY_SIZE)) {
		THROW(INVALID_INPUT, "Invalid input to header_construct.");
	}

	//initialize the output buffer
	*header = nullptr;

	//create buffer for our public ephemeral
	ProtobufCBinaryData protobuf_our_public_ephemeral;
	protobuf_our_public_ephemeral.len = our_public_ephemeral->content_length;
	protobuf_our_public_ephemeral.data = our_public_ephemeral->content;

	//fill the struct
	header_struct.message_number = message_number;
	header_struct.has_message_number = true;
	header_struct.previous_message_number = previous_message_number;
	header_struct.has_previous_message_number = true;
	header_struct.public_ephemeral_key = protobuf_our_public_ephemeral;
	header_struct.has_public_ephemeral_key = true;

	//allocate the header buffer
	{
		size_t header_length = header__get_packed_size(&header_struct);
		*header = buffer_create_on_heap(header_length, header_length);
		THROW_on_failed_alloc(*header);

		//pack it
		size_t packed_length = header__pack(&header_struct, (*header)->content);
		if (packed_length != header_length) {
			THROW(PROTOBUF_PACK_ERROR, "Packed header has incorrect length.");
		}
	}

cleanup:
	on_error {
		if ((header != nullptr) && (*header != nullptr)) {
			buffer_destroy_from_heap_and_null_if_valid(*header);
		}
	}

	return status;
}

return_status header_extract(
		//outputs
		buffer_t * const their_public_ephemeral, //PUBLIC_KEY_SIZE
		uint32_t * const message_number,
		uint32_t * const previous_message_number,
		//intput
		const buffer_t * const header) {
	return_status status = return_status_init();

	Header *header_struct = nullptr;

	//check input
	if ((their_public_ephemeral == nullptr) || (their_public_ephemeral->buffer_length < PUBLIC_KEY_SIZE)
			|| (message_number == nullptr) || (previous_message_number == nullptr)
			|| (header == nullptr)) {
		THROW(INVALID_INPUT, "Invalid input to header_extract.");
	}

	//unpack the message
	header_struct = header__unpack(&protobuf_c_allocators, header->content_length, header->content);
	if (header_struct == nullptr) {
		THROW(PROTOBUF_UNPACK_ERROR, "Failed to unpack header.");
	}

	if (!header_struct->has_message_number || !header_struct->has_previous_message_number || !header_struct->has_public_ephemeral_key) {
		THROW(PROTOBUF_MISSING_ERROR, "Missing fields in header.");
	}

	if (header_struct->public_ephemeral_key.len != PUBLIC_KEY_SIZE) {
		THROW(INCORRECT_BUFFER_SIZE, "The public ephemeral key in the header has an incorrect size.");
	}

	*message_number = header_struct->message_number;
	*previous_message_number = header_struct->previous_message_number;

	if (buffer_clone_from_raw(their_public_ephemeral, header_struct->public_ephemeral_key.data, header_struct->public_ephemeral_key.len) != 0) {
		THROW(BUFFER_ERROR, "Failed to copy public ephemeral key.")
	}

cleanup:
	if (header_struct != nullptr) {
		header__free_unpacked(header_struct, &protobuf_c_allocators);
	}

	return status;
}
