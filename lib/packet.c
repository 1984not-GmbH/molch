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

#include "constants.h"
#include "packet.h"
#include "molch.h"

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
 *   our_public_identity_key(PUBLIC_KEY_SIZE), //optional, only prekey messages
 *   our_public_ephemeral_key(PUBLIC_KEY_SIZE, //optional, only prekey messages
 *   public_prekey(PUBLIC_KEY_SIZE), //optional, only prekey messages
 *   header_length(1),
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
		buffer_t * const packet, //output, has to be long enough, see format above TODO: Be more specific
		const unsigned char packet_type,
		const unsigned char current_protocol_version, //this can't be larger than 0xF = 15
		const unsigned char highest_supported_protocol_version, //this can't be larger than 0xF = 15
		const buffer_t * const header,
		const buffer_t * const header_key, //HEADER_KEY_SIZE
		const buffer_t * const message,
		const buffer_t * const message_key, //MESSAGE_KEY_SIZE
		const buffer_t * const public_identity_key, //optional, can be NULL, for prekey messages only
		const buffer_t * const public_ephemeral_key, //optional, can be NULL, for prekey messages only
		const buffer_t * const public_prekey) { //optional, can be NULL, for prekey messages only
	//check buffer sizes
	if ((header_key->content_length != HEADER_KEY_SIZE)
			|| (message_key->content_length != MESSAGE_KEY_SIZE)
			|| (packet == NULL) || (packet->buffer_length < 3 + HEADER_NONCE_SIZE + (packet_type == PREKEY_MESSAGE) * 2 * PUBLIC_KEY_SIZE + MESSAGE_NONCE_SIZE + header->content_length + crypto_aead_chacha20poly1305_ABYTES + crypto_secretbox_MACBYTES + message->content_length + 255)) {
		return -6;
	}

	if ((packet_type == PREKEY_MESSAGE) && (
				(public_identity_key == NULL) || (public_identity_key->content_length != PUBLIC_KEY_SIZE)
				|| (public_ephemeral_key == NULL) || (public_ephemeral_key->content_length != PUBLIC_KEY_SIZE)
				|| (public_prekey == NULL) || (public_prekey->content_length != PUBLIC_KEY_SIZE))) {
		return -7;
	}

	if ((packet_type != PREKEY_MESSAGE) && ((public_identity_key != NULL) || (public_prekey != NULL) || (public_ephemeral_key != NULL))) {
		return -7;
	}

	//make sure that the length assumptions are correct
	assert(crypto_onetimeauth_KEYBYTES == crypto_secretbox_KEYBYTES);

	//protocol version has to be equal or less than 0xF
	if ((current_protocol_version > 0x0f)
			|| (highest_supported_protocol_version > 0x0f)) {
		return -8;
	}

	//make sure the header length fits into one byte
	if (header->content_length > (0xff - crypto_aead_chacha20poly1305_ABYTES - MESSAGE_NONCE_SIZE)) {
		return -9;
	}

	//check if the packet buffer is long enough (only roughly) FIXME correct numbers here!
	if (packet->buffer_length < (3 + crypto_aead_chacha20poly1305_ABYTES + MESSAGE_NONCE_SIZE + HEADER_NONCE_SIZE + message->content_length + crypto_secretbox_MACBYTES + (packet_type == PREKEY_MESSAGE) * 3 * PUBLIC_KEY_SIZE)) {
		return -6;
	}

	//put packet type and protocol version into the packet
	packet->content[0] = packet_type;
	packet->content[1] = 0xf0 & (current_protocol_version << 4); //put current version into 4MSB
	packet->content[1] |= (0x0f & highest_supported_protocol_version); //put highest version into 4LSB
	packet->content[2] = header->content_length + crypto_aead_chacha20poly1305_ABYTES + MESSAGE_NONCE_SIZE; //header length with authenticator and message nonce
	packet->content_length = 3;

	int status;

	off_t header_offset = 3;
	if (packet_type == PREKEY_MESSAGE) {
		header_offset += 3 * PUBLIC_KEY_SIZE;

		//copy our public identity key
		status = buffer_copy(
				packet,
				3,
				public_identity_key,
				0,
				PUBLIC_KEY_SIZE);
		if (status != 0) {
			return -10;
		}

		//copy our public ephemeral key
		status = buffer_copy(
				packet,
				3 + PUBLIC_KEY_SIZE,
				public_ephemeral_key,
				0,
				PUBLIC_KEY_SIZE);
		if (status != 0) {
			return -10;
		}

		//copy the public prekey of the receiver
		status = buffer_copy(
				packet,
				3 + 2 * PUBLIC_KEY_SIZE,
				public_prekey,
				0,
				PUBLIC_KEY_SIZE);
		if (status != 0) {
			return -10;
		}
	}

	//create the header nonce
	buffer_create_with_existing_array(header_nonce, packet->content + header_offset, HEADER_NONCE_SIZE);
	status = buffer_fill_random(header_nonce, header_nonce->buffer_length);
	if (status != 0) {
		return status;
	}

	//create buffer for the encrypted part of the header
	buffer_t *header_buffer = buffer_create_on_heap(header->content_length + MESSAGE_NONCE_SIZE, header->content_length + MESSAGE_NONCE_SIZE);
	//copy header
	status = buffer_copy(header_buffer, 0, header, 0, header->content_length);
	if (status != 0) {
		buffer_destroy_from_heap(header_buffer);
		return status;
	}
	//create message nonce
	buffer_create_with_existing_array(message_nonce, header_buffer->content + header->content_length, MESSAGE_NONCE_SIZE);
	status = buffer_fill_random(message_nonce, message_nonce->buffer_length);
	if (status != 0) {
		buffer_destroy_from_heap(header_buffer);
		return status;
	}

	//buffer that points to the part of the packet where the header ciphertext will be stored
	buffer_create_with_existing_array(header_ciphertext, packet->content + header_offset + header_nonce->content_length, header_buffer->content_length + crypto_aead_chacha20poly1305_ABYTES);
	//same for the additional data
	buffer_create_with_existing_array(additional_data, packet->content, 3 + header_nonce->content_length + (packet_type == PREKEY_MESSAGE) * 3 * PUBLIC_KEY_SIZE);

	//encrypt the header and authenticate the additional data (1st 3 Bytes)
	unsigned long long header_ciphertext_length;
	status = crypto_aead_chacha20poly1305_encrypt(
			header_ciphertext->content, //ciphertext
			&header_ciphertext_length, //ciphertext length
			header_buffer->content, //plaintext
			header_buffer->content_length, //message length
			additional_data->content,
			additional_data->content_length,
			NULL,
			header_nonce->content,
			header_key->content);
	assert(header_ciphertext->content_length == header_ciphertext_length);
	if (status != 0) {
		buffer_destroy_from_heap(header_buffer);
		return status;
	}

	//make sure the header_length property in the packet is correct
	assert((header->content_length + crypto_aead_chacha20poly1305_ABYTES + MESSAGE_NONCE_SIZE) == header_ciphertext_length);

	//now encrypt the message

	//calculate amount of padding (PKCS7 padding to 255 byte blocks, see RFC5652 section 6.3)
	unsigned char padding = 255 - (message->content_length % 255);

	//allocate buffer for the message + padding
	buffer_t *plaintext_buffer = buffer_create_on_heap(message->content_length + padding, message->content_length + padding);

	//copy message to plaintext buffer
	status = buffer_copy(plaintext_buffer, 0, message, 0, message->content_length);
	if (status != 0) {
		buffer_destroy_from_heap(plaintext_buffer);
		buffer_destroy_from_heap(header_buffer);
		return status;
	}
	assert(plaintext_buffer->content_length == (message->content_length + padding));

	//add padding to the end of the buffer
	memset(plaintext_buffer->content + message->content_length, padding, padding);

	//length of everything in front of the ciphertext
	const size_t PRE_CIPHERTEXT_LENGTH = additional_data->content_length + header_ciphertext_length;

	//buffer that points to the message ciphertext position in the packet
	buffer_create_with_existing_array(message_ciphertext, packet->content + PRE_CIPHERTEXT_LENGTH, message->content_length + padding + crypto_secretbox_MACBYTES);
	//encrypt the message
	status = crypto_secretbox_easy(
			message_ciphertext->content, //ciphertext
			plaintext_buffer->content, //message
			plaintext_buffer->content_length, //message length
			message_nonce->content,
			message_key->content);
	buffer_destroy_from_heap(plaintext_buffer);
	buffer_destroy_from_heap(header_buffer);
	if (status != 0) {
		buffer_clear(packet);
		return status;
	}

	//set length of entire encrypted message
	packet->content_length = PRE_CIPHERTEXT_LENGTH + message->content_length + padding + crypto_secretbox_MACBYTES;
	return 0;
}

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
		const buffer_t * const message_key) { //MESSAGE_KEY_SIZE
	//check the buffer sizes
	if ((header_key->content_length != HEADER_KEY_SIZE)
			|| (message_key->content_length != MESSAGE_KEY_SIZE)) {
		return -6;
	}

	//get the packet metadata
	unsigned char purported_header_length;
	int status = packet_get_metadata_without_verification(
			packet,
			packet_type,
			current_protocol_version,
			highest_supported_protocol_version,
			&purported_header_length);
	if (status != 0) {
		return status;
	}

	//decrypt the header
	buffer_t *message_nonce = buffer_create_on_heap(MESSAGE_NONCE_SIZE, MESSAGE_NONCE_SIZE);
	status = packet_decrypt_header(
			packet,
			header,
			message_nonce,
			header_key);
	if (status != 0) {
		buffer_destroy_from_heap(message_nonce);
		return status;
	}

	//decrypt the message
	status = packet_decrypt_message(
			packet,
			message,
			message_nonce,
			message_key);
	buffer_destroy_from_heap(message_nonce);
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
	if (packet->content_length < (3 + packet->content[2] +  HEADER_NONCE_SIZE)) {
		return -10;
	}

	unsigned char local_packet_type = packet->content[0];
	*packet_type = local_packet_type;
	*current_protocol_version = (0xf0 & packet->content[1]) >> 4;
	*highest_supported_protocol_version = 0x0f & packet->content[1];
	*header_length = packet->content[2] - crypto_aead_chacha20poly1305_ABYTES - MESSAGE_NONCE_SIZE;
	return 0;
}

/*
 * Decrypt the header of a packet. (This also authenticates the metadata)
 */
int packet_decrypt_header(
		const buffer_t * const packet,
		buffer_t * const header, //As long as the packet or at most 255 bytes
		buffer_t * const message_nonce,
		const buffer_t * const header_key) {
	//check sizes of the buffers
	if ((message_nonce->buffer_length < MESSAGE_NONCE_SIZE)
			|| (header_key->content_length != HEADER_KEY_SIZE)) {
		return -6;
	}

	//extract the purported header length from the packet
	unsigned char packet_type;
	unsigned char current_protocol_version;
	unsigned char highest_supported_protocol_version;
	unsigned char purported_header_length;
	int status = packet_get_metadata_without_verification(
			packet,
			&packet_type,
			&current_protocol_version,
			&highest_supported_protocol_version,
			&purported_header_length);
	if (status != 0) {
		return status;
	}

	//buffer that points to different parts of the header
	buffer_create_with_existing_array(header_nonce, packet->content + 3, HEADER_NONCE_SIZE);
	buffer_create_with_existing_array(additional_data, packet->content, 3 + header_nonce->content_length);
	buffer_create_with_existing_array(header_ciphertext, packet->content + additional_data->content_length, purported_header_length + MESSAGE_NONCE_SIZE + crypto_aead_chacha20poly1305_ABYTES);
	//encrypt the header
	buffer_t *header_buffer = buffer_create_on_heap(purported_header_length + MESSAGE_NONCE_SIZE, purported_header_length + MESSAGE_NONCE_SIZE);
	unsigned long long decrypted_length;
	status = crypto_aead_chacha20poly1305_decrypt(
			header_buffer->content,
			&decrypted_length,
			NULL,
			header_ciphertext->content, //ciphertext of header
			header_ciphertext->content_length, //ciphertext length
			additional_data->content,
			additional_data->content_length,
			header_nonce->content, //nonce
			header_key->content);
	if (status != 0) {
		goto cleanup;
	}

	assert(purported_header_length == decrypted_length - MESSAGE_NONCE_SIZE);

	//copy the header
	status = buffer_copy(header, 0, header_buffer, 0, purported_header_length);
	if (status != 0) {
		buffer_clear(header);
		goto cleanup;
	}
	//copy the message nonce
	status = buffer_copy(message_nonce, 0, header_buffer, purported_header_length, MESSAGE_NONCE_SIZE);
	if (status != 0) {
		buffer_clear(header);
		buffer_clear(message_nonce);
	}
	header->content_length = purported_header_length;

cleanup:
	buffer_destroy_from_heap(header_buffer);

	return status;
}

/*
 * Decrypt the message inside a packet.
 * (only do this if the packet metadata is already
 * verified)
 */
int packet_decrypt_message(
		const buffer_t * const packet,
		buffer_t * const message, //This buffer should be as large as the packet
		const buffer_t * const message_nonce,
		const buffer_t * const message_key) { //MESSAGE_KEY_SIZE
	//check buffer sizes
	if ((message_nonce->content_length != MESSAGE_NONCE_SIZE)
			|| (message_key->content_length != MESSAGE_KEY_SIZE)) {
		return -6;
	}
	//set message length to 0
	message->content_length = 0;

	//get the header length
	unsigned char irrelevant_metadata;
	unsigned char purported_header_length;
	int status = packet_get_metadata_without_verification(
			packet,
			&irrelevant_metadata,
			&irrelevant_metadata,
			&irrelevant_metadata,
			&purported_header_length);
	if (status != 0) {
		return status;
	}

	//length of message and padding
	const size_t purported_plaintext_length = packet->content_length - 3 - purported_header_length - HEADER_NONCE_SIZE - MESSAGE_NONCE_SIZE- crypto_secretbox_MACBYTES - crypto_aead_chacha20poly1305_ABYTES;
	if (purported_plaintext_length >= packet->content_length) {
		return -10;
	}

	if (purported_plaintext_length > message->buffer_length) {
		return -6;
	}

	//buffer pointing to the message ciphertext
	buffer_create_with_existing_array(message_ciphertext, packet->content + (packet->content_length - purported_plaintext_length) - crypto_secretbox_MACBYTES, purported_plaintext_length + crypto_secretbox_MACBYTES);

	//decrypt the message (padding included)
	buffer_t *plaintext = buffer_create_on_heap(purported_plaintext_length, purported_plaintext_length);
	status = crypto_secretbox_open_easy(
			plaintext->content,
			message_ciphertext->content,
			message_ciphertext->content_length,
			message_nonce->content,
			message_key->content);
	if (status != 0) {
		buffer_destroy_from_heap(plaintext);
		return status;
	}

	//get amount of padding from last byte (pkcs7)
	const unsigned char padding = plaintext->content[purported_plaintext_length - 1];
	if (padding > purported_plaintext_length) { //check if pdding is valid
		buffer_destroy_from_heap(plaintext);
		return -10;
	}

	//copy the message from the plaintext
	status = buffer_copy(message, 0, plaintext, 0, purported_plaintext_length - padding);
	buffer_destroy_from_heap(plaintext);
	if (status != 0) {
		buffer_clear(message);
		return status;
	}

	return 0;
}
