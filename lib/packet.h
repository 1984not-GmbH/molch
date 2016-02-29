/* Molch, an implementation of the axolotl ratchet based on libsodium
 *  Copyright (C) 2015  Max Bruckner (FSMaxB)
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "../buffer/buffer.h"

#ifndef LIB_MESSAGE_H
#define LIB_MESSAGE_H

/*
 * Encrypt a message and header with a symmetric key and a nonce.
 *
 * For the header, AEAD is used (authenticated encryption with
 * additional data) to authenticate the header length, version
 * and packet type.
 *
 * packet has to have at least the following length:
 *
 * The packet has the following format:
 * packet = {
 *   protocol_version(1), //4MSB: current version; 4LSB: highest supported version
 *   packet_type(1),
 *   header_length(1),
 *   our_public_identity_key(PUBLIC_KEY_SIZE), //optional, only prekey messages
 *   our_public_ephemeral_key(PUBLIC_KEY_SIZE), //optional, only prekey messages
 *   public_prekey(PUBLIC_KEY_SIZE), //optional, only prekey messages
 *   header_nonce(HEADER_NONCE_SIZE),
 *   header {
 *       axolotl_header(?),
 *       message_nonce(MESSAGE_NONCE_SIZE)
 *   },
 *   header_and_additional_data_MAC(crypto_aead_chacha20poly1305_ABYTES),
 *   authenticated_encrypted_message {
 *       message(?),
 *       MAC(crypto_secretbox_MACBYTES)
 *   }
 * }
 */
int packet_encrypt(
		buffer_t * const packet, //output, has to be long enough, see format above
		const unsigned char packet_type,
		const unsigned char current_protocol_version, //this can't be larger than 0xF = 15
		const unsigned char highest_supported_protocol_version, //this can't be larger than 0xF = 15
		const buffer_t * const header,
		const buffer_t * const header_key, //HEADER_KEY_SIZE
		const buffer_t * const message,
		const buffer_t * const message_key, //MESSAGE_KEY_SIZE
		const buffer_t * const public_identity_key, //optional, can be NULL, for prekey messages only
		const buffer_t * const public_ephemeral_key, //otpional, can be NULL, for prekey messages only
		const buffer_t * const public_prekey //optional, can be NULL, for prekey messages only
		) __attribute__((warn_unused_result));

/*
 * Decrypt and authenticate a packet.
 */
int packet_decrypt(
		const buffer_t * const packet,
		unsigned char * const packet_type, //1 Byte, no array
		unsigned char * const current_protocol_version, //1 Byte, no array
		unsigned char * const highest_supported_protocol_version, //1 Byte, no array
		buffer_t * const header, //output, As long as the packet or at most 255 bytes
		const buffer_t * const header_key, //HEADER_KEY_SIZE
		buffer_t * const message, //output, should be as long as the packet
		const buffer_t * const message_key, //MESSAGE_KEY_SIZE
		buffer_t * const public_identity_key, //optional, can be NULL, for prekey messages only
		buffer_t * const public_ephemeral_key, //optional, can be NULL, for prekey messages only
		buffer_t * const public_prekey //optional, can be NULL, for prekey messages only
		) __attribute__((warn_unused_result));

/*
 * Get the metadata of a packet (without verifying it's authenticity).
 */
int packet_get_metadata_without_verification(
		const buffer_t * const packet,
		unsigned char * const packet_type, //1 Byte, no array
		unsigned char * const current_protocol_version, //1 Byte, no array
		unsigned char * const highest_supported_protocol_version, //1 Byte, no array
		unsigned char * const header_length, //this is the raw header length, without the authenticator
		buffer_t * const public_identity_key, //output, optional, can be NULL, only works with prekey messages
		buffer_t * const public_ephemeral_key, //output, optional, can be NULL, only works with prekey messages
		buffer_t * const public_prekey //output, optional, can be NULL, only works with prekey messages
		) __attribute__((warn_unused_result));

/*
 * Decrypt the header of a packet. (This also authenticates the metadata!)
 */
int packet_decrypt_header(
		const buffer_t * const packet,
		buffer_t * const header, //As long as the packet or at most 255 bytes
		buffer_t * const message_nonce, //output, MESSAGE_KEY_SIZE
		const buffer_t * const header_key, //HEADER_KEY_SIZE
		buffer_t * const public_identity_key, //output, optional, can be NULL, for prekey messages only
		buffer_t * const public_ephemeral_key, //output, optional, can be NULL, for prekey messages only
		buffer_t * const public_prekey //output, optional, can be NULL, for prekey messages only
		) __attribute__((warn_unused_result));

/*
 * Decrypt the message inside a packet.
 * (only do this if the packet metadata is already
 * verified)
 */
int packet_decrypt_message(
		const buffer_t * const packet,
		buffer_t * const message, //This buffer should be as large as the packet
		const buffer_t * const message_nonce,
		const buffer_t * const message_key) __attribute__((warn_unused_result)); //MESSAGE_KEY_SIZE

#endif
