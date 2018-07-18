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
#include <optional>

#include "buffer.hpp"
#include "../include/molch.h"
#include "key.hpp"
#include "gsl.hpp"

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
	[[deprecated]]
	Buffer packet_encrypt(
			//inputs
			const molch_message_type packet_type,
			const span<const std::byte> axolotl_header,
			const HeaderKey& axolotl_header_key,
			const span<const std::byte> message,
			const MessageKey& message_key,
			//optional inputs (prekey messages only)
			const PublicKey * const public_identity_key,
			const PublicKey * const public_ephemeral_key,
			const PublicKey * const public_prekey);

	struct PrekeyMetadata {
		PublicKey identity;
		PublicKey ephemeral;
		PublicKey prekey;
	};

	struct Metadata {
		uint32_t current_protocol_version;
		uint32_t highest_supported_protocol_version;
		molch_message_type packet_type;
		std::optional<PrekeyMetadata> prekey_metadata;
	};

	struct DecryptedPacket {
		Buffer header;
		Buffer message;
		Metadata metadata;
	};

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
	 * \param prekey_metadata Optional prekey metadata (for prekey packets)
	 *
	 * \return
	 *   The encrypted packet.
	 */
	result<Buffer> packet_encrypt(
			const molch_message_type packet_type,
			const span<const std::byte> axolotl_header,
			const HeaderKey& axolotl_header_key,
			const span<const std::byte> message,
			const MessageKey& message_key,
			const std::optional<PrekeyMetadata>& prekey_metadata);

	/*!
	 * Extract and decrypt a packet and the metadata inside of it.
	 *
	 * \param packet
	 *   The encrypted packet.
	 * \param axolotl_header_key
	 *   The header key with which the axolotl header is encrypted.
	 * \param message_key
	 *   The key to encrypt the message with.
	 * \return decrypted packet with metadata
	 */
	result<DecryptedPacket> packet_decrypt(
			const span<const std::byte> packet,
			const HeaderKey& axolotl_header_key,
			const MessageKey& message_key);

	/*!
	 * Extracts the metadata from a packet without actually decrypting or verifying anything.
	 */
	result<Metadata> packet_get_metadata_without_verification(const span<const std::byte> packet);

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
	result<Buffer> packet_decrypt_header(
			const span<const std::byte> packet,
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
	result<Buffer> packet_decrypt_message(const span<const std::byte> packet, const MessageKey& message_key);
}
#endif
