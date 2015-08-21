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
		const unsigned char * const header,
		const size_t header_length,
		const unsigned char * const header_key, //crypto_aead_chacha20poly1305_KEYBYTES
		const unsigned char * const message,
		const size_t message_length,
		const unsigned char * const message_key); //crypto_secretbox_KEYBYTES

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
 * Decrypt the header of a packet. (This also authenticates the metadata!)
 */
int packet_decrypt_header(
		const unsigned char * const packet,
		const size_t packet_length,
		unsigned char * const header, //As long as the packet or at most 255 bytes
		size_t * const header_length, //output
		unsigned char * const message_nonce, //output
		const unsigned char * const header_key); //crypto_aead_chacha20poly1305_KEYBYTES

/*
 * Decrypt the message inside a packet.
 */
int packet_decrypt_message(
		const unsigned char * const packet,
		const size_t packet_length,
		unsigned char * const message, //This buffer should be as large as the packet
		size_t * const message_length, //output
		const unsigned char * const message_nonce,
		const unsigned char * const message_key); //crypto_secretbox_KEYBYTES

#endif
