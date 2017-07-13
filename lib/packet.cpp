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

extern "C" {
	#include <packet.pb-c.h>
}
#include <cstring>
#include "packet.h"
#include "constants.h"
#include "zeroed_malloc.h"

/*!
 * Convert molch_message_type to PacketHeader__PacketType.
 */
static PacketHeader__PacketType to_packet_header_packet_type(const molch_message_type packet_type) {
	switch (packet_type) {
		case PREKEY_MESSAGE:
			return PACKET_HEADER__PACKET_TYPE__PREKEY_MESSAGE;
		case NORMAL_MESSAGE:
			return PACKET_HEADER__PACKET_TYPE__NORMAL_MESSAGE;
		default:
			//fallback to normal message
			return PACKET_HEADER__PACKET_TYPE__NORMAL_MESSAGE;
	}
}

/*!
 * Convert PacketHeader__PacketType to molch_message_type.
 */
static molch_message_type to_molch_message_type(const PacketHeader__PacketType packet_type) {
	switch (packet_type) {
		case PACKET_HEADER__PACKET_TYPE__NORMAL_MESSAGE:
			return NORMAL_MESSAGE;
		case PACKET_HEADER__PACKET_TYPE__PREKEY_MESSAGE:
			return PREKEY_MESSAGE;
		default:
			return INVALID;
	}
}

/*!
 * Unpacks a packet via Protobuf-C into a struct and verifies that all the necessary
 * fields exist.
 *
 * \param packet_struct
 *   The unpacket struct.
 * \param packet
 *   The binary packet.
 *
 * \return
 *   Error status, destroy with return_status_destroy_errors if an error occurs.
 */
return_status packet_unpack(Packet ** const packet_struct, Buffer * const packet) __attribute__((warn_unused_result));
return_status packet_unpack(Packet ** const packet_struct, Buffer * const packet) {
	return_status status = return_status_init();

	//check input
	if ((packet_struct == nullptr) || (packet == nullptr)) {
		THROW(INVALID_INPUT, "Invalid input to packet_unpack.");
	}

	//unpack the packet
	*packet_struct = packet__unpack(&protobuf_c_allocators, packet->content_length, packet->content);
	if (*packet_struct == nullptr) {
		THROW(PROTOBUF_UNPACK_ERROR, "Failed to unpack packet.");
	}

	if ((*packet_struct)->packet_header->current_protocol_version != 0) {
		THROW(UNSUPPORTED_PROTOCOL_VERSION, "The packet has an unsuported protocol version.");
	}

	//check if the packet contains the necessary fields
	if (!(*packet_struct)->has_encrypted_axolotl_header
		|| !(*packet_struct)->has_encrypted_message
		|| !(*packet_struct)->packet_header->has_packet_type
		|| !(*packet_struct)->packet_header->has_header_nonce
		|| !(*packet_struct)->packet_header->has_message_nonce) {
		THROW(PROTOBUF_MISSING_ERROR, "Some fields are missing in the packet.");
	}

	//check the size of the nonces
	if (((*packet_struct)->packet_header->header_nonce.len != HEADER_NONCE_SIZE)
		|| ((*packet_struct)->packet_header->message_nonce.len != MESSAGE_NONCE_SIZE)) {
		THROW(INCORRECT_BUFFER_SIZE, "At least one of the nonces has an incorrect length.");
	}

	if ((*packet_struct)->packet_header->packet_type == PACKET_HEADER__PACKET_TYPE__PREKEY_MESSAGE) {
		//check if the public keys for prekey messages are there
		if (!(*packet_struct)->packet_header->has_public_identity_key
			|| !(*packet_struct)->packet_header->has_public_ephemeral_key
			|| !(*packet_struct)->packet_header->has_public_prekey) {
			THROW(PROTOBUF_MISSING_ERROR, "The prekey packet misses at least one public key.");
		}

		//check the sizes of the public keys
		if (((*packet_struct)->packet_header->public_identity_key.len != PUBLIC_KEY_SIZE)
			|| ((*packet_struct)->packet_header->public_ephemeral_key.len != PUBLIC_KEY_SIZE)
			|| ((*packet_struct)->packet_header->public_prekey.len != PUBLIC_KEY_SIZE)) {
			THROW(INCORRECT_BUFFER_SIZE, "At least one of the public keys of the prekey packet has an incorrect length.");
		}
	}

cleanup:
	on_error {
		if ((packet_struct != nullptr) && (*packet_struct != nullptr)) {
			packet__free_unpacked(*packet_struct, &protobuf_c_allocators);
			*packet_struct = nullptr;
		}
	}

	return status;
}

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
		Buffer * const public_prekey) {
	return_status status = return_status_init();

	//initialize the protobuf structs
	Packet packet_struct = PACKET__INIT;
	PacketHeader packet_header_struct = PACKET_HEADER__INIT;
	packet_struct.packet_header = &packet_header_struct;

	//buffers
	Buffer *header_nonce = nullptr;
	Buffer *message_nonce = nullptr;
	Buffer *encrypted_axolotl_header = nullptr;
	Buffer *padded_message = nullptr;
	Buffer *encrypted_message = nullptr;

	//check the input
	if ((packet == nullptr)
		|| (packet_type == INVALID)
		|| (axolotl_header == nullptr)
		|| (axolotl_header_key == nullptr) || (axolotl_header_key->content_length != HEADER_KEY_SIZE)
		|| (message == nullptr)
		|| (message_key == nullptr) || (message_key->content_length != MESSAGE_KEY_SIZE)) {
		THROW(INVALID_INPUT, "Invalid input to packet_encrypt.");
	}

	//set the protocol version
	packet_header_struct.current_protocol_version = 0;
	packet_header_struct.highest_supported_protocol_version = 0;

	//set the packet type
	packet_header_struct.has_packet_type = true;
	packet_header_struct.packet_type = to_packet_header_packet_type(packet_type);

	if (packet_type == PREKEY_MESSAGE) {
		//check input
		if ((public_identity_key == nullptr) || (public_identity_key->content_length != PUBLIC_KEY_SIZE)
			|| (public_ephemeral_key == nullptr) || (public_ephemeral_key->content_length != PUBLIC_KEY_SIZE )
			|| (public_prekey == nullptr) || (public_prekey->content_length != PUBLIC_KEY_SIZE)) {
			THROW(INVALID_INPUT, "Invalid public key to packet_encrypt for prekey message.");
		}

		//set the public identity key
		packet_header_struct.has_public_identity_key = true;
		packet_header_struct.public_identity_key.data = public_identity_key->content;
		packet_header_struct.public_identity_key.len = public_identity_key->content_length;

		//set the public ephemeral key
		packet_header_struct.has_public_ephemeral_key = true;
		packet_header_struct.public_ephemeral_key.data = public_ephemeral_key->content;
		packet_header_struct.public_ephemeral_key.len = public_ephemeral_key->content_length;

		//set the public prekey
		packet_header_struct.has_public_prekey = true;
		packet_header_struct.public_prekey.data = public_prekey->content;
		packet_header_struct.public_prekey.len = public_prekey->content_length;
	}

	//generate the header nonce and add it to the packet header
	header_nonce = buffer_create_on_heap(HEADER_NONCE_SIZE, 0);
	THROW_on_failed_alloc(header_nonce);
	if (buffer_fill_random(header_nonce, HEADER_NONCE_SIZE) != 0) {
		THROW(BUFFER_ERROR, "Failed to generate header nonce.");
	}
	packet_header_struct.has_header_nonce = true;
	packet_header_struct.header_nonce.data = header_nonce->content;
	packet_header_struct.header_nonce.len = header_nonce->content_length;

	//encrypt the header
	encrypted_axolotl_header = buffer_create_on_heap(
			axolotl_header->content_length + crypto_secretbox_MACBYTES,
			axolotl_header->content_length + crypto_secretbox_MACBYTES);
	THROW_on_failed_alloc(encrypted_axolotl_header);
	{
		int status_int = crypto_secretbox_easy(
				encrypted_axolotl_header->content,
				axolotl_header->content,
				axolotl_header->content_length,
				header_nonce->content,
				axolotl_header_key->content);
		if (status_int != 0) {
			THROW(ENCRYPT_ERROR, "Failed to encrypt header.");
		}
	}

	//add the encrypted header to the protobuf struct
	packet_struct.has_encrypted_axolotl_header = true;
	packet_struct.encrypted_axolotl_header.data = encrypted_axolotl_header->content;
	packet_struct.encrypted_axolotl_header.len = encrypted_axolotl_header->content_length;

	//generate the message nonce and add it to the packet header
	message_nonce = buffer_create_on_heap(MESSAGE_NONCE_SIZE, 0);
	THROW_on_failed_alloc(message_nonce);
	if (buffer_fill_random(message_nonce, MESSAGE_NONCE_SIZE) != 0) {
		THROW(BUFFER_ERROR, "Failed to generate message nonce.");
	}
	packet_header_struct.has_message_nonce = true;
	packet_header_struct.message_nonce.data = message_nonce->content;
	packet_header_struct.message_nonce.len = message_nonce->content_length;

	//pad the message (PKCS7 padding to 255 byte blocks, see RFC5652 section 6.3)
	{
		unsigned char padding = (unsigned char)(255 - (message->content_length % 255));
		padded_message = buffer_create_on_heap(message->content_length + padding, 0);
		THROW_on_failed_alloc(padded_message);
		//copy the message
		if (buffer_clone(padded_message, message) != 0) {
			THROW(BUFFER_ERROR, "Failed to clone message.");
		}
		//pad it
		memset(padded_message->content + padded_message->content_length, padding, padding);
		padded_message->content_length += padding;
	}

	//encrypt the message
	encrypted_message = buffer_create_on_heap(
			padded_message->content_length + crypto_secretbox_MACBYTES,
			padded_message->content_length + crypto_secretbox_MACBYTES);
	THROW_on_failed_alloc(encrypted_message);
	{
		int status_int = crypto_secretbox_easy(
				encrypted_message->content,
				padded_message->content,
				padded_message->content_length,
				message_nonce->content,
				message_key->content);
		if (status_int != 0) {
			THROW(ENCRYPT_ERROR, "Failed to encrypt message.");
		}
	}

	//add the encrypted message to the protobuf struct
	packet_struct.has_encrypted_message = true;
	packet_struct.encrypted_message.data = encrypted_message->content;
	packet_struct.encrypted_message.len = encrypted_message->content_length;

	//calculate the required length
	{
		const size_t packed_length = packet__get_packed_size(&packet_struct);

		//pack the packet
		*packet = buffer_create_on_heap(packed_length, 0);
		THROW_on_failed_alloc(*packet);
		(*packet)->content_length = packet__pack(&packet_struct, (*packet)->content);
		if ((*packet)->content_length != packed_length) {
			THROW(PROTOBUF_PACK_ERROR, "Packet packet has incorrect length.");
		}
	}

cleanup:
	on_error {
		if (packet != nullptr) {
			buffer_destroy_from_heap_and_null_if_valid(*packet);
		}
	}

	buffer_destroy_from_heap_and_null_if_valid(header_nonce);
	buffer_destroy_from_heap_and_null_if_valid(message_nonce);
	buffer_destroy_from_heap_and_null_if_valid(encrypted_axolotl_header);
	buffer_destroy_from_heap_and_null_if_valid(padded_message);
	buffer_destroy_from_heap_and_null_if_valid(encrypted_message);

	return status;
}

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
		Buffer * const public_prekey) {
	return_status status = return_status_init();

	//initialize outputs that have to be allocated
	if (axolotl_header != nullptr) {
		*axolotl_header = nullptr;
	}
	if (message != nullptr) {
		*message = nullptr;
	}

	//get metadata
	status = packet_get_metadata_without_verification(
			current_protocol_version,
			highest_supported_protocol_version,
			packet_type,
			packet,
			public_identity_key,
			public_ephemeral_key,
			public_prekey);
	THROW_on_error(DATA_FETCH_ERROR, "Failed to get metadata from the packet.");

	//decrypt the header
	status = packet_decrypt_header(
			axolotl_header,
			packet,
			axolotl_header_key);
	THROW_on_error(DECRYPT_ERROR, "Failed to decrypt header.");

	//decrypt the message
	status = packet_decrypt_message(
			message,
			packet,
			message_key);
	THROW_on_error(DECRYPT_ERROR, "Failed to decrypt message.");

cleanup:
	on_error {
		if (packet_type != nullptr) {
			*packet_type = INVALID;
		}

		if (axolotl_header != nullptr) {
			buffer_destroy_from_heap_and_null_if_valid(*axolotl_header);
		}

		if (message != nullptr) {
			buffer_destroy_from_heap_and_null_if_valid(*message);
		}

		if (public_identity_key != nullptr) {
			public_identity_key->clear();
		}

		if (public_ephemeral_key != nullptr) {
			public_ephemeral_key->clear();
		}

		if (public_prekey != nullptr) {
			public_prekey->clear();
		}
	}

	return status;
}

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
		) {
	return_status status = return_status_init();

	Packet *packet_struct = nullptr;

	//check input
	if ((current_protocol_version == nullptr) || (highest_supported_protocol_version == nullptr)
			|| (packet_type == nullptr)
			|| (packet == nullptr)) {
		THROW(INVALID_INPUT, "Invalid input to packet_get_metadata_without_verification.");
	}

	status = packet_unpack(&packet_struct, packet);
	THROW_on_error(PROTOBUF_UNPACK_ERROR, "Failed to unpack packet.");

	if (packet_struct->packet_header->packet_type == PACKET_HEADER__PACKET_TYPE__PREKEY_MESSAGE) {
		//copy the public keys
		if (public_identity_key != nullptr) {
			if (buffer_clone_from_raw(public_identity_key, packet_struct->packet_header->public_identity_key.data, packet_struct->packet_header->public_identity_key.len) != 0) {
				THROW(BUFFER_ERROR, "Failed to copy public identity key.");
			}
		}
		if (public_ephemeral_key != nullptr) {
			if (buffer_clone_from_raw(public_ephemeral_key, packet_struct->packet_header->public_ephemeral_key.data, packet_struct->packet_header->public_ephemeral_key.len) != 0) {
				THROW(BUFFER_ERROR, "Failed to copy public ephemeral key.");
			}
		}
		if (public_prekey != nullptr) {
			if (buffer_clone_from_raw(public_prekey, packet_struct->packet_header->public_prekey.data, packet_struct->packet_header->public_prekey.len) != 0) {
				THROW(BUFFER_ERROR, "Failed to copy public prekey.");
			}
		}
	}

	*current_protocol_version = packet_struct->packet_header->current_protocol_version;
	*highest_supported_protocol_version = packet_struct->packet_header->highest_supported_protocol_version;
	*packet_type = to_molch_message_type(packet_struct->packet_header->packet_type);

cleanup:
	if (packet_struct != nullptr) {
		packet__free_unpacked(packet_struct, &protobuf_c_allocators);
	}

	on_error {
		//make sure that incomplete data can't be accidentally used
		if (public_identity_key != nullptr) {
			public_identity_key->clear();
		}

		if (public_ephemeral_key != nullptr) {
			public_ephemeral_key->clear();
		}

		if (public_prekey != nullptr) {
			public_prekey->clear();
		}

		if (packet_type != nullptr) {
			*packet_type = INVALID;
		}
	}

	return status;
}

return_status packet_decrypt_header(
		//output
		Buffer ** const axolotl_header,
		//inputs
		Buffer * const packet,
		Buffer * const axolotl_header_key //HEADER_KEY_SIZE
		) {
	return_status status = return_status_init();

	Packet *packet_struct = nullptr;

	//check input
	if ((axolotl_header == nullptr)
			|| (packet == nullptr)
			|| (axolotl_header_key == nullptr) || (axolotl_header_key->content_length != HEADER_KEY_SIZE)) {
		THROW(INVALID_INPUT, "Invalid input to packet_decrypt_header.");
	}

	status = packet_unpack(&packet_struct, packet);
	THROW_on_error(PROTOBUF_UNPACK_ERROR, "Failed to unpack packet.");

	if (packet_struct->encrypted_axolotl_header.len < crypto_secretbox_MACBYTES) {
		THROW(INCORRECT_BUFFER_SIZE, "The ciphertext of the axolotl header is too short.")
	}

	{
		const size_t axolotl_header_length = packet_struct->encrypted_axolotl_header.len - crypto_secretbox_MACBYTES;
		*axolotl_header = buffer_create_on_heap(axolotl_header_length, axolotl_header_length);
		THROW_on_failed_alloc(*axolotl_header);
	}

	{
		int status_int = crypto_secretbox_open_easy(
				(*axolotl_header)->content,
				packet_struct->encrypted_axolotl_header.data,
				packet_struct->encrypted_axolotl_header.len,
				packet_struct->packet_header->header_nonce.data,
				axolotl_header_key->content);
		if (status_int != 0) {
			THROW(DECRYPT_ERROR, "Failed to decrypt axolotl header.");
		}
	}

cleanup:
	if (packet_struct != nullptr) {
		packet__free_unpacked(packet_struct, &protobuf_c_allocators);
	}

	on_error {
		if (axolotl_header != nullptr) {
			buffer_destroy_from_heap_and_null_if_valid(*axolotl_header);
		}
	}

	return status;
}

return_status packet_decrypt_message(
		//output
		Buffer ** const message,
		//inputs
		Buffer * const packet,
		Buffer * const message_key
		) {
	return_status status = return_status_init();
	unsigned char padding;

	Packet *packet_struct = nullptr;

	Buffer *padded_message = nullptr;

	//check input
	if ((message == nullptr)
		|| (packet == nullptr)
		|| (message_key == nullptr) || (message_key->content_length != MESSAGE_KEY_SIZE)) {
		THROW(INVALID_INPUT, "Invalid input to packet_decrypt_message.")
	}

	status = packet_unpack(&packet_struct, packet);
	THROW_on_error(PROTOBUF_UNPACK_ERROR, "Failed to unpack packet.");

	if (packet_struct->encrypted_message.len < crypto_secretbox_MACBYTES) {
		THROW(INCORRECT_BUFFER_SIZE, "The ciphertext of the message is too short.");
	}

	{
		const size_t padded_message_length = packet_struct->encrypted_message.len - crypto_secretbox_MACBYTES;
		if (padded_message_length < 255) {
			THROW(INCORRECT_BUFFER_SIZE, "The padded message is too short.")
		}
		padded_message = buffer_create_on_heap(padded_message_length, padded_message_length);
		THROW_on_failed_alloc(padded_message);
	}

	{
		int status_int = crypto_secretbox_open_easy(
				padded_message->content,
				packet_struct->encrypted_message.data,
				packet_struct->encrypted_message.len,
				packet_struct->packet_header->message_nonce.data,
				message_key->content);
		if (status_int != 0) {
			THROW(DECRYPT_ERROR, "Failed to decrypt message.");
		}
	}

	//get the padding (last byte)
	padding = padded_message->content[padded_message->content_length - 1];
	if (padding > padded_message->content_length) {
		THROW(INCORRECT_BUFFER_SIZE, "The padded message is too short.")
	}

	//extract the message
	{
		const size_t message_length = padded_message->content_length - padding;
		*message = buffer_create_on_heap(message_length, 0);
		THROW_on_failed_alloc(*message);
		//TODO this doesn't need to be copied, setting the length should be enough
		if (buffer_copy(*message, 0, padded_message, 0, message_length) != 0) {
			THROW(BUFFER_ERROR, "Failed to copy message from padded message.");
		}
	}

cleanup:
	if (packet_struct != nullptr) {
		packet__free_unpacked(packet_struct, &protobuf_c_allocators);
	}

	buffer_destroy_from_heap_and_null_if_valid(padded_message);

	on_error {
		if (message != nullptr) {
			buffer_destroy_from_heap_and_null_if_valid(*message);
		}
	}

	return status;
}
