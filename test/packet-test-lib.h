/* Molch, an implementation of the axolotl ratchet based on libsodium
 *  Copyright (C) 2015-2016 1984not Security GmbH
 *  Author: Max Bruckner (FSMaxB)
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

#include "../lib/packet.h"

/*
 * Create message and header keys, encrypt header and message
 * and print them.
 *
 * Don't forget to destroy the return status with return_status_destroy_errors()
 * if an error has occurred.
 */
return_status create_and_print_message(
		buffer_t * const packet, //needs to be 3 + crypto_aead_chacha20poly1305_NPUBBYTES + crypto_secretbox_NONCEBYTES + message_length + header_length + crypto_secretbox_MACBYTES
		const unsigned char packet_type,
		const unsigned char current_protocol_version,
		const unsigned char highest_supported_protocol_version,
		const buffer_t * const message,
		buffer_t * const message_key, //output, crypto_secretbox_KEYBYTES
		const buffer_t * const header,
		buffer_t * const header_key, //output, crypto_secretbox_KEYBYTES
		const buffer_t * const public_identity_key, //optional, can be NULL, for prekey messages
		const buffer_t * const public_epehemeral_key, //optional, can be NULL, for prekey messages
		const buffer_t * const public_prekey); //optional, can be NULL, for prekey messages
