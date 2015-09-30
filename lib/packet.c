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
		unsigned char * const packet, //output, has to be long enough, see format above TODO: Be more specific
		size_t * const packet_length, //length of the output
		const unsigned char packet_type,
		const unsigned char current_protocol_version, //this can't be larger than 0xF = 15
		const unsigned char highest_supported_protocol_version, //this can't be larger than 0xF = 15
		const unsigned char * const header,
		const size_t header_length,
		const unsigned char * const header_key, //crypto_aead_chacha20poly1305_KEYBYTES
		const unsigned char * const message,
		const size_t message_length,
		const unsigned char * const message_key) { //crypto_secretbox_KEYBYTES
	//make sure that the length assumptions are correct
	assert(crypto_onetimeauth_KEYBYTES == crypto_secretbox_KEYBYTES);

	//protocol version has to be equal or less than 0xF
	assert(current_protocol_version <= 0x0f);
	assert(highest_supported_protocol_version <= 0x0f);

	//make sure the header length fits into one byte
	assert(header_length <= (0xff - crypto_aead_chacha20poly1305_ABYTES - crypto_secretbox_NONCEBYTES));

	//put packet type and protocol version into the packet
	packet[0] = packet_type;
	packet[1] = 0xf0 & (current_protocol_version << 4); //put current version into 4MSB
	packet[1] |= (0x0f & highest_supported_protocol_version); //put highest version into 4LSB
	packet[2] = header_length + crypto_aead_chacha20poly1305_ABYTES + crypto_secretbox_NONCEBYTES; //header length with authenticator and message nonce

	//create the header nonce
	unsigned char * const header_nonce = packet + 3;
	randombytes_buf(header_nonce, crypto_aead_chacha20poly1305_NPUBBYTES);

	//create buffer for the encrypted part of the header
	unsigned char header_buffer[header_length + crypto_secretbox_NONCEBYTES];
	//copy header
	memcpy(header_buffer, header, header_length);
	//create message nonce
	unsigned char * const message_nonce = header_buffer + header_length;
	randombytes_buf(message_nonce, crypto_secretbox_NONCEBYTES);

	//encrypt the header and authenticate the additional data (1st 3 Bytes)
	int status;
	unsigned long long header_ciphertext_length;
	status = crypto_aead_chacha20poly1305_encrypt(
			packet + 3 + crypto_aead_chacha20poly1305_NPUBBYTES, //ciphertext
			&header_ciphertext_length, //ciphertext length
			header_buffer, //plaintext
			sizeof(header_buffer), //message length
			packet,
			3 + crypto_aead_chacha20poly1305_NPUBBYTES,
			NULL,
			header_nonce,
			header_key);
	if (status != 0) {
		sodium_memzero(header_buffer, sizeof(header_buffer));
		return status;
	}

	//make sure the header_length property in the packet is correct
	assert((header_length + crypto_aead_chacha20poly1305_ABYTES + crypto_secretbox_NONCEBYTES) == header_ciphertext_length);

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
	sodium_memzero(header_buffer, sizeof(header_buffer));
	if (status != 0) {
		return status;
	}

	//set length of entire encrypted message
	*packet_length = PRE_CIPHERTEXT_LENGTH + message_length + padding + crypto_secretbox_MACBYTES;
	return 0;
}

/*
 * Decrypt and authenticate a packet.
 */
int packet_decrypt(
		const unsigned char * const packet,
		const size_t packet_length,
		unsigned char * const packet_type, //1 Byte, no array
		unsigned char * const current_protocol_version, //1 Byte, no array
		unsigned char * const highest_supported_protocol_version, //1 Byte, no array
		unsigned char * const header, //As long as the packet or at most 255 bytes
		size_t *header_length, //output
		const unsigned char * const header_key, //crypto_aead_chacha20poly1305_KEYBYTES
		unsigned char * const message, //should be as long as the packet
		size_t *message_length, //output
		const unsigned char * const message_key) { //crypto_secretbox_KEYBYTES
	//FIXME remove this once packet.c is moved over to buffer_t
	buffer_t *packet_buffer = buffer_create_with_existing_array((unsigned char*)packet, packet_length);
	//get the packet metadata
	unsigned char purported_header_length;
	int status = packet_get_metadata_without_verification(
			packet_buffer,
			packet_type,
			current_protocol_version,
			highest_supported_protocol_version,
			&purported_header_length);
	if (status != 0) {
		return status;
	}

	//decrypt the header
	unsigned char message_nonce[crypto_secretbox_NONCEBYTES];
	status = packet_decrypt_header(
			packet,
			packet_length,
			header,
			header_length,
			message_nonce,
			header_key);
	if (status != 0) {
		sodium_memzero(message_nonce, sizeof(message_nonce));
		return status;
	}

	//decrypt the message
	status = packet_decrypt_message(
			packet,
			packet_length,
			message,
			message_length,
			message_nonce,
			message_key);
	sodium_memzero(message_nonce, sizeof(message_nonce));
	if (status != 0) {
		return status;
	}

	return 0;
}

/*
 * Get the metadata of a packet (without verifying it's authenticity).
 */
int packet_get_metadata_without_verification(
		const buffer_t * const packet,
		unsigned char * const packet_type,
		unsigned char * const current_protocol_version,
		unsigned char * const highest_supported_protocol_version,
		unsigned char * const header_length) { //this is the raw header length, without the authenticator
	//check if packet_length is long enough to get the header length
	if (packet->content_length < 3) {
		return -10;
	}
	//check if packet is long enough to get the rest of the metadata
	if (packet->content_length < (3 + packet->content[2] +  crypto_aead_chacha20poly1305_NPUBBYTES)) {
		return -10;
	}

	*packet_type = packet->content[0];
	*current_protocol_version = (0xf0 & packet->content[1]) >> 4;
	*highest_supported_protocol_version = 0x0f & packet->content[1];
	*header_length = packet->content[2] - crypto_aead_chacha20poly1305_ABYTES - crypto_secretbox_NONCEBYTES;
	return 0;
}

/*
 * Decrypt the header of a packet. (This also authenticates the metadata)
 */
int packet_decrypt_header(
		const unsigned char * const packet,
		const size_t packet_length,
		unsigned char * const header, //As long as the packet or at most 255 bytes
		size_t * const header_length,
		unsigned char * const message_nonce,
		const unsigned char * const header_key) {
	//FIXME remove this once packet.c is ported over to buffer_t
	buffer_t *packet_buffer = buffer_create_with_existing_array((unsigned char*)packet, packet_length);
	//extract the purported header length from the packet
	unsigned char irrelevant_metadata;
	unsigned char purported_header_length;
	int status = packet_get_metadata_without_verification(
			packet_buffer,
			&irrelevant_metadata,
			&irrelevant_metadata,
			&irrelevant_metadata,
			&purported_header_length);
	if (status != 0) {
		return status;
	}

	//encrypt the header
	unsigned char header_buffer[purported_header_length + crypto_secretbox_NONCEBYTES];
	unsigned long long decrypted_length;
	status = crypto_aead_chacha20poly1305_decrypt(
			header_buffer,
			&decrypted_length,
			NULL,
			packet + 3 + crypto_aead_chacha20poly1305_NPUBBYTES, //ciphertext of header
			purported_header_length + crypto_secretbox_NONCEBYTES + crypto_aead_chacha20poly1305_ABYTES, //ciphertext length
			packet, //additional data
			3 + crypto_aead_chacha20poly1305_NPUBBYTES, //additional data length
			packet + 3, //nonce
			header_key);
	if (status != 0) {
		sodium_memzero(header_buffer, sizeof(header_buffer));
		return status;
	}

	assert(purported_header_length == decrypted_length - crypto_secretbox_NONCEBYTES);

	//copy the header
	memcpy(header, header_buffer, purported_header_length);
	//copy the message nonce
	memcpy(message_nonce, header_buffer + purported_header_length, crypto_secretbox_NONCEBYTES);

	*header_length = purported_header_length;

	sodium_memzero(header_buffer, sizeof(header_buffer));
	return 0;
}

/*
 * Decrypt the message inside a packet.
 */
int packet_decrypt_message(
		const unsigned char * const packet,
		const size_t packet_length,
		unsigned char * const message, //This buffer should be as large as the packet
		size_t * const message_length, //output
		const unsigned char * const message_nonce,
		const unsigned char * const message_key) { //crypto_secretbox_KEYBYTES
	//FIXME: remove this once packet.c is ported over to buffer_t
	buffer_t *packet_buffer = buffer_create_with_existing_array((unsigned char*)packet, packet_length);
	//get the header length
	unsigned char irrelevant_metadata;
	unsigned char purported_header_length;
	int status = packet_get_metadata_without_verification(
			packet_buffer,
			&irrelevant_metadata,
			&irrelevant_metadata,
			&irrelevant_metadata,
			&purported_header_length);
	if (status != 0) {
		return status;
	}

	//length of message and padding
	const size_t purported_plaintext_length = packet_length - 3 - purported_header_length - crypto_aead_chacha20poly1305_NPUBBYTES - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES - crypto_aead_chacha20poly1305_ABYTES;
	if (purported_plaintext_length >= packet_length) {
		return -10;
	}

	//decrypt the message (padding included)
	unsigned char plaintext[purported_plaintext_length];
	status = crypto_secretbox_open_easy(
			plaintext,
			packet + (packet_length - purported_plaintext_length) - crypto_secretbox_MACBYTES,
			purported_plaintext_length + crypto_secretbox_MACBYTES,
			message_nonce,
			message_key);
	if (status != 0) {
		sodium_memzero(plaintext, sizeof(plaintext));
		return status;
	}

	//get amount of padding from last byte (pkcs7)
	const unsigned char padding = plaintext[purported_plaintext_length - 1];
	if (padding > purported_plaintext_length) { //check if pdding is valid
		sodium_memzero(plaintext, sizeof(plaintext));
		return -10;
	}

	//copy the message from the plaintext
	memcpy(message, plaintext, purported_plaintext_length - padding);

	//set the message length
	*message_length = purported_plaintext_length - padding;

	sodium_memzero(plaintext, sizeof(plaintext));
	return 0;
}
