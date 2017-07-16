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

#include "buffer.h"
#include "common.h"
#include "molch.h"

/*! \file
 * Theses functions create a packet from a packet header, encryption keys, an azolotl header and a
 * message. Also the other way around extracting data from a packet and decrypting its contents.
 */

/*!
 * Construct and encrypt a packet given the keys and metadata.
 *
 * \param packet
 *   The encrypted packet.
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
 *   Error status, destroy with return_status_destroy_errors if an error occurs.
 */
return_status packet_encrypt(
		//output
		Buffer ** const packet,
		//inputs
		const molch_message_type packet_type,
		Buffer * const axolotl_header,
		Buffer * const axolotl_header_key, //HEADER_KEY_SIZE
		Buffer * const message,
		Buffer * const message_key, //MESSAGE_KEY_SIZE
		//optional inputs (prekey messages only)
		Buffer * const public_identity_key,
		Buffer * const public_ephemeral_key,
		Buffer * const public_prekey) noexcept __attribute__((warn_unused_result));

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
 *
 * \return
 *   Error status, destroy with return_status_destroy_errors if an error occurs.
 */
return_status packet_decrypt(
		//outputs
		uint32_t * const current_protocol_version,
		uint32_t * const highest_supported_protocol_version,
		molch_message_type * const packet_type,
		Buffer ** const axolotl_header,
		Buffer ** const message,
		//inputs
		Buffer * const packet,
		Buffer * const axolotl_header_key, //HEADER_KEY_SIZE
		Buffer * const message_key, //MESSAGE_KEY_SIZE
		//optional outputs (prekey messages only)
		Buffer * const public_identity_key,
		Buffer * const public_ephemeral_key,
		Buffer * const public_prekey) noexcept __attribute__((warn_unused_result));

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
 *
 * \return
 *   Error status, destroy with return_status_destroy_errors if an error occurs.
 */
return_status packet_get_metadata_without_verification(
		//outputs
		uint32_t * const current_protocol_version,
		uint32_t * const highest_supported_protocol_version,
		molch_message_type * const packet_type,
		//input
		Buffer * const packet,
		//optional outputs (prekey messages only)
		Buffer * const public_identity_key, //PUBLIC_KEY_SIZE
		Buffer * const public_ephemeral_key, //PUBLIC_KEY_SIZE
		Buffer * const public_prekey //PUBLIC_KEY_SIZE
		) noexcept __attribute__((warn_unused_result));

/*!
 * Decrypt the axolotl header part of a packet and thereby authenticate other metadata.
 *
 * \param axolotl_header
 *   A buffer for the decrypted axolotl header.
 * \param packet
 *   The entire packet.
 * \param axolotl_header_key
 *   The key to decrypt the axolotl header with.
 *
 * \return
 *   Error status, destroy with return_status_destroy_errors if an error occurs.
 */
return_status packet_decrypt_header(
		//output
		Buffer ** const axolotl_header,
		//inputs
		Buffer * const packet,
		Buffer * const axolotl_header_key //HEADER_KEY_SIZE
		) noexcept __attribute__((warn_unused_result));

/*!
 * Decrypt the message part of a packet.
 *
 * \param message
 *   A buffer for the decrypted message.
 * \param packet
 *   The entire packet.
 * \message_key
 *   The key to decrypt the message with.
 *
 * \return
 *   Error status, destroy with return_status_destroy_errors if an error occurs.
 */
return_status packet_decrypt_message(
		//output
		Buffer ** const message,
		//inputs
		Buffer * const packet,
		Buffer * const message_key
		) noexcept __attribute__((warn_unused_result));
#endif
