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
#include <sodium.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "packet.h"

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
		const unsigned char * const message_key) { //crypto_secretbox_KEYBYTES
	//make sure that the length assumptions are correct
	assert(crypto_onetimeauth_KEYBYTES == crypto_secretbox_KEYBYTES);

	//protocol version has to be equal or less than 0xF
	assert(current_protocol_version <= 0x0f);
	assert(highest_supported_protocol_version <= 0x0f);

	//make sure the header length fits into one byte
	assert(header_length <= (0xff - crypto_aead_chacha20poly1305_ABYTES));

	//put packet type and protocol version into the packet
	packet[0] = header_length + crypto_aead_chacha20poly1305_ABYTES; //header length with authenticator
	packet[1] = packet_type;
	packet[2] = 0xf0 & (current_protocol_version << 4); //put current version into 4MSB
	packet[2] |= (0x0f & highest_supported_protocol_version); //put highest version into 4LSB

	//copy the header nonce
	memcpy(packet + 3, header_nonce, crypto_aead_chacha20poly1305_NPUBBYTES);

	//create buffer for the encrypted part of the header
	unsigned char header_buffer[header_length + crypto_secretbox_NONCEBYTES];

	//encrypt the header and authenticate the additional data (1st 3 Bytes)
	int status;
	unsigned long long header_ciphertext_length;
	status = crypto_aead_chacha20poly1305_encrypt(
			packet + 3 + crypto_aead_chacha20poly1305_NPUBBYTES, //ciphertext
			&header_ciphertext_length, //ciphertext length
			header, //plaintext
			header_length, //message length
			packet,
			3 + crypto_aead_chacha20poly1305_NPUBBYTES,
			NULL,
			header_nonce,
			header_key);
	sodium_memzero(header_buffer, sizeof(header_buffer));
	if (status != 0) {
		return status;
	}

	//make sure the header_length property in the packet is correct
	assert((header_length + crypto_aead_chacha20poly1305_ABYTES) == header_ciphertext_length);

	//now encrypt the message

	//calculate amount of padding (PKCS7 padding to 255 byte blocks, see RFC5652 section 6.3)
	unsigned char padding = 255 - (message_length % 255);

	//allocate buffer for the message + padding
	unsigned char plaintext_buffer[message_length + padding];

	//copy message to plaintext buffer
	memcpy(plaintext_buffer, message, message_length);

	//add padding to the end of the buffer
	memset(plaintext_buffer + message_length, padding, padding);

	//length of everything in front of the ciphertext
	const size_t PRE_CIPHERTEXT_LENGTH = 3 + crypto_aead_chacha20poly1305_NPUBBYTES + header_ciphertext_length;

	//encrypt the message
	status = crypto_secretbox_easy(
			packet + PRE_CIPHERTEXT_LENGTH, //ciphertext
			plaintext_buffer, //message
			message_length + padding, //message length
			message_nonce,
			message_key);
	sodium_memzero(plaintext_buffer, sizeof(plaintext_buffer));
	if (status != 0) {
		return status;
	}

	//set length of entire encrypted message
	*packet_length = PRE_CIPHERTEXT_LENGTH + message_length + padding + crypto_secretbox_MACBYTES;
	return 0;
}

/*
 * Extract the header, nonce and mac from a packet without verifying it's
 * integrity.
 *
 * This is only used internally.
 */
int extract_header_nonce_and_mac_without_verifying(
		unsigned char * const header,
		size_t * const header_length,
		unsigned char * const nonce, //crypto_secretbox_NONCEBYTES
		unsigned char * const mac, //crypto_onetimeauth_BYTES
		const unsigned char * const packet,
		const size_t packet_length) {
	//first byte of the header is it's length
	const size_t HEADER_LENGTH = packet[0];

	const size_t PRE_CIPHERTEXT_LENGTH = 1 + HEADER_LENGTH + crypto_secretbox_NONCEBYTES + crypto_onetimeauth_BYTES;

	if ((PRE_CIPHERTEXT_LENGTH + crypto_secretbox_MACBYTES + 255) > packet_length) {
		//packet isn't long enough (header field probably has incorrect value)
		return -10;
	}

	//copy the header
	memcpy(header, packet + 1, HEADER_LENGTH);

	//copy the nonce
	memcpy(nonce, packet + 1 + HEADER_LENGTH, crypto_secretbox_NONCEBYTES);

	//copy the MAC
	memcpy(mac, packet + 1 + HEADER_LENGTH + crypto_secretbox_NONCEBYTES, crypto_onetimeauth_BYTES);

	*header_length = HEADER_LENGTH;

	return 0;
}

/*
 * Decrypt a message with a symmetric key and verify the headers integrity.
 *
 * The message and header buffers should be as long as the packet buffer.
 */
int decrypt_message(
		unsigned char * const message,
		size_t * const message_length, //return length of the message
		unsigned char * const header,
		size_t * const header_length, //return length of the header
		const unsigned char * const packet,
		const size_t packet_length,
		const unsigned char * const key) { //crypto_secretbox_KEYBYTES
	//buffers for the header components
	unsigned char header_buffer[packet_length];
	unsigned char nonce[crypto_secretbox_NONCEBYTES];
	unsigned char mac[crypto_onetimeauth_BYTES];

	int status;
	status = extract_header_nonce_and_mac_without_verifying(
			header_buffer,
			header_length,
			nonce,
			mac,
			packet,
			packet_length);
	if (status != 0) {
		*header_length = 0;
		return status;
	}

	const size_t PRE_CIPHERTEXT_LENGTH = 1 + *header_length + crypto_secretbox_NONCEBYTES + crypto_onetimeauth_BYTES;

	//authenticate header and nonce
	status = crypto_onetimeauth_verify(
			mac, //MAC
			packet, //input
			1 + *header_length + crypto_secretbox_NONCEBYTES, //input_length
			key);
	if (status != 0) {
		*header_length = 0;
		return status;
	}

	//copy header
	memcpy(header, header_buffer, *header_length);

	const size_t CIPHERTEXT_LENGTH = packet_length - PRE_CIPHERTEXT_LENGTH;

	//buffer to store decrypted message into
	unsigned char plaintext_buffer[CIPHERTEXT_LENGTH - crypto_secretbox_MACBYTES];

	//decrypt the message
	status = crypto_secretbox_open_easy(
			plaintext_buffer, //output
			packet + PRE_CIPHERTEXT_LENGTH,
			CIPHERTEXT_LENGTH,
			packet + 1 + *header_length, //nonce
			key);
	if (status != 0) {
		sodium_memzero(plaintext_buffer, sizeof(plaintext_buffer));
		return status;
	}

	//get amount of padding (from last byte of the plaintext buffer
	const unsigned char padding = plaintext_buffer[sizeof(plaintext_buffer) - 1];

	//make sure the amount of padding is actually possible
	if (padding > sizeof(plaintext_buffer)) {
		sodium_memzero(plaintext_buffer, sizeof(plaintext_buffer));
		return -10;
	}

	//calculate length of the message
	*message_length = sizeof(plaintext_buffer) - padding;

	//copy plaintext to message (output)
	memcpy(message, plaintext_buffer, *message_length);
	sodium_memzero(plaintext_buffer, sizeof(plaintext_buffer));

	return 0;
}

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
		const size_t packet_length) {
	unsigned char nonce[crypto_secretbox_NONCEBYTES];
	unsigned char mac[crypto_secretbox_MACBYTES];

	return extract_header_nonce_and_mac_without_verifying(
			header,
			header_length,
			nonce,
			mac,
			packet,
			packet_length);
}
