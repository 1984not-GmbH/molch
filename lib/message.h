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

/*
 * Encrypt a message and header with a symmetric key and a nonce.
 *
 * packet has to have at least the following length:
 *   header_length + crypto_box_NONCEBYTES + crypto_onetimeauth_BYTES
 *   + message_length + crypto_secretbox_MACBYTES + 256
 *
 * encrypted_message =
 *     header_length (1Byte) || header || nonce || MAC (header and nonce) || authenticated ciphertext
 */
int encrypt_message(
		unsigned char * const packet, //output
		size_t * const packet_length, //length of the output
		const unsigned char * const message,
		const size_t message_length,
		const unsigned char * const header, //additional (plaintext) header data
		const size_t header_length,
		const unsigned char * const nonce, //crypto_secretbox_NONCEBYTES
		const unsigned char * const key); //crypto_secretbox_KEYBYTES

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
