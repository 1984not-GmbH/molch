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

/*! \file
 * This provides functions for serializing and deserializing Axolotl-Headers.
 * They contain current and previous message numbers as well as the senders
 * public ephemeral key.
 *
 * The header is constructed as described in header.proto.
 */

#ifndef LIB_HEADER_H
#define LIB_HEADER_H

#include <memory>

#include "buffer.hpp"
#include "return-status.hpp"
#include "key.hpp"
#include "gsl.hpp"
#include "result.hpp"

namespace Molch {
	/*!
	 * Constructs an Axolotl-Header into a buffer.
	 *
	 * \param our_public_ephemeral
	 *   The public ephemeral key of the sender (ours). Length has to be PUBLIC_KEY_SIZE.
	 * \param message_number
	 *   The number of the message in the current message chain.
	 * \param previous_message_number
	 *   The number of messages in the previous message chain.
	 *
	 * \return
	 *   The constructed header.
	 */
	result<Buffer> header_construct(
			const PublicKey& our_public_ephemeral, //PUBLIC_KEY_SIZE
			const uint32_t message_number,
			const uint32_t previous_message_number);


	struct ExtractedHeader {
		PublicKey their_public_ephemeral;
		uint32_t message_number;
		uint32_t previous_message_number;
	};

	/*!
	 * Extracts the data from an Axolotl-Header.
	 *
	 * \param header
	 *   A buffer containing the Axolotl-Header.
	 *
	 * \return extracted public ephemeral, message number and previous message number
	 */
	result<ExtractedHeader> header_extract(const span<const std::byte> header);
}

#endif
