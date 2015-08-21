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

#ifndef LIB_MESSAGE_H
#define LIB_MESSAGE_H

//FIXME: Consider little and big endian architectures!

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
 *   header_nonce(crypto_aead_chacha20poly1305_NPUBBYTES),
 *   header {
 *       axolotl_header(?),
 *       message_nonce(crypto_secretbox_NONCEBYTES)
 *   },
 *   header_and_additional_data_MAC(crypto_aead_chacha20poly1305_ABYTES),
 *   authenticated_encrypted_message {
 *       message(?),
 *       MAC(crypto_secretbox_MACBYTES)
 *   }
 * }
 */
int packet_encrypt(
		unsigned char * const packet, //output, has to be long enough, see format above
		size_t * const packet_length, //length of the output
		const unsigned char packet_type,
		const unsigned char current_protocol_version, //this can't be larger than 0xF = 15
		const unsigned char highest_supported_protocol_version, //this can't be larger than 0xF = 15
		const unsigned char * const header_nonce, //crypto_aead_chacha20poly1305_NPUBBYTES
		const unsigned char * const header,
		const size_t header_length,
		const unsigned char * const header_key, //crypto_aead_chacha20poly1305_KEYBYTES
		const unsigned char * const message,
		const size_t message_length,
		const unsigned char * const message_nonce, //crypto_secretbox_NONCEBYTES
		const unsigned char * const message_key); //crypto_secretbox_KEYBYTES

/*
 * Decrypt a message with a symmetric key and verify the headers integrity.
 *
 * The message and header buffers should be as long as the packet buffer.
 */
int decrypt_message(
		unsigned char * const message,
		size_t * const message_length, //return length of the message
		unsigned char* const header,
		size_t * const header_length, //return length of the header
		const unsigned char * const packet,
		const size_t packet_length,
		const unsigned char * const key); //crypto_secretbox_KEYBYTES

/*
 * Get the metadata of a packet (without verifying it's authenticity).
 */
int packet_get_metadata_without_verification(
		const unsigned char * const packet,
		const size_t packet_length,
		unsigned char * const packet_type, //1 Byte, no array
		unsigned char * const current_protocol_version, //1 Byte, no array
		unsigned char * const highest_supported_protocol_version, //1 Byte, no array
		unsigned char * const header_length); //this is the raw header length, without the authenticator

/*
 * Extract the header from a packet without verifying it's integrity.
 * This is required to get the message number before actually being
 * able to derive the message key that's needed to verify it.
 *
 * The header buffer should be as long as the packet buffer.
 */
int extract_header_without_verifying(
		unsigned char * const header, //buffer to put the header into
		size_t * const header_length,
		const unsigned char * const packet,
		const size_t packet_length);

#endif
