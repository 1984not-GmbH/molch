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

#ifndef LIB_PACKET_H
#define LIB_PACKET_H

#include <memory>

#include "buffer.hpp"
#include "molch.h"
#include "key.hpp"
#include "optional.hpp"

/*! \file
 * Theses functions create a packet from a packet header, encryption keys, an azolotl header and a
 * message. Also the other way around extracting data from a packet and decrypting its contents.
 */

namespace Molch {
	/*!
	 * Construct and encrypt a packet given the keys and metadata.
	 *
	 * \param packet_type
	 *   The type of the packet (prekey message, normal message ...)
	 * \param axolotl_header
	 *   The axolotl header containing all the necessary information for the ratchet.
	 * \param axolotl_header_key
	 *   The header key with which the axolotl header is encrypted.
	 * \param message
	 *   The message that should be sent.
	 * \param message_key
	 *   The key to encrypt the message with.
	 * \param public_identity_key
	 *   The public identity key of the sender in case of prekey messages. Optional for normal messages.
	 * \param public_ephemeral_key
	 *   The public ephemeral key of the sender in case of prekey messages. Optional for normal messages.
	 * \param public_prekey
	 *   The prekey of the receiver that has been selected by the sender in case of prekey messages. Optional for normal messages.
	 *
	 * \return
	 *   The encrypted packet.
	 */
	Buffer packet_encrypt(
			//inputs
			const molch_message_type packet_type,
			const Buffer& axolotl_header,
			const HeaderKey& axolotl_header_key,
			const Buffer& message,
			const MessageKey& message_key,
			//optional inputs (prekey messages only)
			const PublicKey * const public_identity_key,
			const PublicKey * const public_ephemeral_key,
			const PublicKey * const public_prekey);

	/*!
	 * Extract and decrypt a packet and the metadata inside of it.
	 *
	 * \param current_protocol_version
	 *   The protocol version currently used.
	 * \param highest_supported_protocol_version
	 *   The highest protocol version the client supports.
	 * \param packet_type
	 *   The type of the packet (prekey message, normal message ...)
	 * \param axolotl_header
	 *   The axolotl header containing all the necessary information for the ratchet.
	 * \param message
	 *   The message that should be sent.
	 * \param packet
	 *   The encrypted packet.
	 * \param axolotl_header_key
	 *   The header key with which the axolotl header is encrypted.
	 * \param message_key
	 *   The key to encrypt the message with.
	 * \param public_identity_key
	 *   The public identity key of the sender in case of prekey messages. Optional for normal messages.
	 * \param public_ephemeral_key
	 *   The public ephemeral key of the sender in case of prekey messages. Optional for normal messages.
	 * \param public_prekey
	 *   The prekey of the receiver that has been selected by the sender in case of prekey messages. Optional for normal messages.
	 */
	void packet_decrypt(
			//outputs
			uint32_t& current_protocol_version,
			uint32_t& highest_supported_protocol_version,
			molch_message_type& packet_type,
			optional<Buffer>& axolotl_header,
			optional<Buffer>& message,
			//inputs
			const Buffer& packet,
			const HeaderKey& axolotl_header_key,
			const MessageKey& message_key,
			//optional outputs (prekey messages only)
			PublicKey * const public_identity_key,
			PublicKey * const public_ephemeral_key,
			PublicKey * const public_prekey);

	/*!
	 * Extracts the metadata from a packet without actually decrypting or verifying anything.
	 *
	 * \param current_protocol_version
	 *   The protocol version currently used.
	 * \param highest_supported_protocol_version
	 *   The highest protocol version the client supports.
	 * \param packet_type
	 *   The type of the packet (prekey message, normal message ...)
	 * \param packet
	 *   The entire packet.
	 * \param public_identity_key
	 *   The public identity key of the sender in case of prekey messages. Optional for normal messages.
	 * \param public_ephemeral_key
	 *   The public ephemeral key of the sender in case of prekey messages. Optional for normal messages.
	 * \param public_prekey
	 *   The prekey of the receiver that has been selected by the sender in case of prekey messages. Optional for normal messages.
	 */
	void packet_get_metadata_without_verification(
			//outputs
			uint32_t& current_protocol_version,
			uint32_t& highest_supported_protocol_version,
			molch_message_type& packet_type,
			//input
			const Buffer& packet,
			//optional outputs (prekey messages only)
			PublicKey * const public_identity_key,
			PublicKey * const public_ephemeral_key,
			PublicKey * const public_prekey);

	/*!
	 * Decrypt the axolotl header part of a packet and thereby authenticate other metadata.
	 *
	 * \param packet
	 *   The entire packet.
	 * \param axolotl_header_key
	 *   The key to decrypt the axolotl header with.
	 *
	 * \return
	 *   A buffer for the decrypted axolotl header.
	 */
	optional<Buffer> packet_decrypt_header(
			const Buffer& packet,
			const HeaderKey& axolotl_header_key);

	/*!
	 * Decrypt the message part of a packet.
	 *
	 * \param packet
	 *   The entire packet.
	 * \message_key
	 *   The key to decrypt the message with.
	 *
	 * \return
	 *   A buffer for the decrypted message.
	 */
	optional<Buffer> packet_decrypt_message(const Buffer& packet, const MessageKey& message_key);
}
#endif
