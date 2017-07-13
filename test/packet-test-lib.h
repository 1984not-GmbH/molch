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

#ifndef TEST_PACKET_TEST_LIB_H
#define TEST_PACKET_TEST_LIB_H

#include "../lib/molch.h"

/*!
 * Create message and header keys, encrypt header and message
 * and print them.
 *
 * \param packet
 *   The resulting packet.
 * \param header_key
 *   A header key that will be generated. Has a length of HEADER_KEY_SIZE.
 * \param message_key
 *   A message key that will be generated. Has a length of MESSAGE_KEY_SIZE.
 * \param packet_type
 *   Prekey or normal packet?
 * \param header
 *   The header to encrypt.
 * \param message
 *   The message to encrypt.
 * \param public_identity_key
 *   Optional. Public identity key of the sender. For prekey messages only.
 * \param public_epheneral_key
 *   Optional. Public ephemeral key of the sender. For prekey messages only.
 * \param public_prekey
 *   Optional. Prekey of the receiver. For prekey messages only.
 *
 * \return
 *   Error status, destroy with return_status_destroy_errors if an error occurs.
 */
return_status create_and_print_message(
		//output
		Buffer ** const packet,
		Buffer * const header_key, //HEADER_KEY_SIZE
		Buffer * const message_key, //MESSAGE_KEY_SIZE
		//inputs
		const molch_message_type packet_type,
		const Buffer * const header,
		const Buffer * const message,
		//optional inputs (prekey messages only)
		const Buffer * const public_identity_key,
		const Buffer * const public_epehemeral_key,
		const Buffer * const public_prekey) __attribute__((warn_unused_result));

#endif
