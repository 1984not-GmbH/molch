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

#include "message.h"

/*
 * Encrypt a message and header with a symmetric key and a nonce.
 *
 * packet = header || nonce || MAC (header and nonce) || authenticated ciphertext
 */
int encrypt_message(
		unsigned char * const packet, //output
		size_t * const packet_length, //length of the output
		const unsigned char * const message,
		const size_t message_length,
		const unsigned char * const header, //additional (plaintext) header data
		const size_t header_length,
		const unsigned char * const nonce,
		const unsigned char * const key) {
	//make sure that the length assumptions are correct
	assert(crypto_onetimeauth_KEYBYTES == crypto_secretbox_KEYBYTES);

	//make sure the header length fits into one byte
	if (header_length > 0xff) {
		return -10;
	}

	//calculate amount of padding (PKCS7 padding to 255 byte blocks, see RFC5652 section 6.3)
	unsigned char padding = 255 - (message_length % 255);

	//allocate buffer for the message + padding
	unsigned char * const plaintext_buffer = malloc(message_length + padding);
	if (plaintext_buffer == NULL) {
		return -10;
	}

	//copy message to plaintext buffer
	memcpy(plaintext_buffer, message, message_length);

	//add padding to the end of the buffer
	memset(plaintext_buffer + message_length, padding, padding);

	//length of everything in front of the ciphertext
	const size_t PRE_CIPHERTEXT_LENGTH = 1 + header_length +
		crypto_secretbox_NONCEBYTES + crypto_onetimeauth_BYTES;

	//encrypt the message
	int status;
	status = crypto_secretbox_easy(
			packet + PRE_CIPHERTEXT_LENGTH, //ciphertext
			plaintext_buffer, //message
			message_length + padding, //message length
			nonce,
			key);
	sodium_memzero(plaintext_buffer, message_length + padding);
	free(plaintext_buffer);
	if (status != 0) {
		return status;
	}

	//copy header to output
	memcpy(packet + 1, header, header_length);

	//set first byte of output to header_length
	packet[0] = header_length;

	//copy nonce to output (after header)
	memcpy(packet + header_length + 1, nonce, crypto_secretbox_NONCEBYTES);

	//create authentication tag for header and nonce and add it after header and nonce
	//TODO is it cryptographically secure to use the same key to authenticate the header
	//as is used to encrypt the plaintext?
	status = crypto_onetimeauth(
			packet + header_length + crypto_secretbox_NONCEBYTES + 1, //output
			packet, //input
			header_length + crypto_secretbox_NONCEBYTES + 1, //input length
			key);

	//set length of entire encrypted message
	*packet_length = PRE_CIPHERTEXT_LENGTH + message_length + padding  + crypto_secretbox_MACBYTES;
	return status;
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
	unsigned char * const header_buffer = malloc(packet_length);
	unsigned char nonce[crypto_secretbox_NONCEBYTES];
	unsigned char mac[crypto_onetimeauth_BYTES];

	int status;
	status = extract_header_nonce_and_mac_without_verifying(
			header,
			header_length,
			nonce,
			mac,
			packet,
			packet_length);
	if (status != 0) {
		*header_length = 0;
		free(header_buffer);
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
		free(header_buffer);
		return status;
	}

	//copy header
	memcpy(header, header_buffer, *header_length);
	free(header_buffer);

	const size_t CIPHERTEXT_LENGTH = packet_length - PRE_CIPHERTEXT_LENGTH;

	//buffer to store decrypted message into
	const size_t PLAINTEXT_LENGTH = CIPHERTEXT_LENGTH - crypto_secretbox_MACBYTES;
	unsigned char * const plaintext_buffer = malloc(PLAINTEXT_LENGTH);

	//decrypt the message
	status = crypto_secretbox_open_easy(
			plaintext_buffer, //output
			packet + PRE_CIPHERTEXT_LENGTH,
			CIPHERTEXT_LENGTH,
			packet + 1 + *header_length, //nonce
			key);
	if (status != 0) {
		sodium_memzero(plaintext_buffer, PLAINTEXT_LENGTH);
		free(plaintext_buffer);
		return status;
	}

	//get amount of padding (from last byte of the plaintext buffer
	const unsigned char padding = plaintext_buffer[PLAINTEXT_LENGTH - 1];

	//make sure the amount of padding is actually possible
	if (padding > PLAINTEXT_LENGTH) {
		sodium_memzero(plaintext_buffer, PLAINTEXT_LENGTH);
		free(plaintext_buffer);
		return -10;
	}

	//calculate length of the message
	*message_length = PLAINTEXT_LENGTH - padding;

	//copy plaintext to message (output)
	memcpy(message, plaintext_buffer, *message_length);
	sodium_memzero(plaintext_buffer, PLAINTEXT_LENGTH);
	free(plaintext_buffer);

	return 0;
}
