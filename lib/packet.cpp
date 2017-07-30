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
#include <algorithm>
#include <exception>

#include "packet.h"
#include "constants.h"
#include "zeroed_malloc.h"
#include "molch-exception.h"
#include "protobuf-deleters.h"

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
 * \param packet
 *   The binary packet.
 *
 * \return
 *   The unpacked struct.
 */
static std::unique_ptr<Packet,PacketDeleter> packet_unpack(const Buffer& packet) {
	//unpack the packet
	auto packet_struct = std::unique_ptr<Packet,PacketDeleter>(packet__unpack(&protobuf_c_allocators, packet.content_length, packet.content));
	if (!packet_struct) {
		throw MolchException(PROTOBUF_UNPACK_ERROR, "Failed to unpack packet.");
	}

	if (packet_struct->packet_header->current_protocol_version != 0) {
		throw MolchException(UNSUPPORTED_PROTOCOL_VERSION, "The packet has an unsuported protocol version.");
	}

	//check if the packet contains the necessary fields
	if (!packet_struct->has_encrypted_axolotl_header
		|| !packet_struct->has_encrypted_message
		|| !packet_struct->packet_header->has_packet_type
		|| !packet_struct->packet_header->has_header_nonce
		|| !packet_struct->packet_header->has_message_nonce) {
		throw MolchException(PROTOBUF_MISSING_ERROR, "Some fields are missing in the packet.");
	}

	//check the size of the nonces
	if ((packet_struct->packet_header->header_nonce.len != HEADER_NONCE_SIZE)
		|| (packet_struct->packet_header->message_nonce.len != MESSAGE_NONCE_SIZE)) {
		throw MolchException(INCORRECT_BUFFER_SIZE, "At least one of the nonces has an incorrect length.");
	}

	if (packet_struct->packet_header->packet_type == PACKET_HEADER__PACKET_TYPE__PREKEY_MESSAGE) {
		//check if the public keys for prekey messages are there
		if (!packet_struct->packet_header->has_public_identity_key
			|| !packet_struct->packet_header->has_public_ephemeral_key
			|| !packet_struct->packet_header->has_public_prekey) {
			throw MolchException(PROTOBUF_MISSING_ERROR, "The prekey packet misses at least one public key.");
		}

		//check the sizes of the public keys
		if ((packet_struct->packet_header->public_identity_key.len != PUBLIC_KEY_SIZE)
			|| (packet_struct->packet_header->public_ephemeral_key.len != PUBLIC_KEY_SIZE)
			|| (packet_struct->packet_header->public_prekey.len != PUBLIC_KEY_SIZE)) {
			throw MolchException(INCORRECT_BUFFER_SIZE, "At least one of the public keys of the prekey packet has an incorrect length.");
		}
	}

	return packet_struct;
}

std::unique_ptr<Buffer> packet_encrypt(
		//inputs
		const molch_message_type packet_type,
		const Buffer& axolotl_header,
		const Buffer& axolotl_header_key, //HEADER_KEY_SIZE
		const Buffer& message,
		const Buffer& message_key, //MESSAGE_KEY_SIZE
		//optional inputs (prekey messages only)
		const Buffer * const public_identity_key,
		const Buffer * const public_ephemeral_key,
		const Buffer * const public_prekey) {
	//initialize the protobuf structs
	Packet packet_struct = PACKET__INIT;
	PacketHeader packet_header_struct = PACKET_HEADER__INIT;
	packet_struct.packet_header = &packet_header_struct;

	//check the input
	if ((packet_type == INVALID)
		|| !axolotl_header_key.contains(HEADER_KEY_SIZE)
		|| !message_key.contains(MESSAGE_KEY_SIZE)) {
		throw MolchException(INVALID_INPUT, "Invalid input to packet_encrypt.");
	}

	//set the protocol version
	packet_header_struct.current_protocol_version = 0;
	packet_header_struct.highest_supported_protocol_version = 0;

	//set the packet type
	packet_header_struct.has_packet_type = true;
	packet_header_struct.packet_type = to_packet_header_packet_type(packet_type);

	if (packet_type == PREKEY_MESSAGE) {
		//check input
		if ((public_identity_key == nullptr) || !public_identity_key->contains(PUBLIC_KEY_SIZE)
			|| (public_ephemeral_key == nullptr) || !public_ephemeral_key->contains(PUBLIC_KEY_SIZE )
			|| (public_prekey == nullptr) || !public_prekey->contains(PUBLIC_KEY_SIZE)) {
			throw MolchException(INVALID_INPUT, "Invalid public key to packet_encrypt for prekey message.");
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
	Buffer header_nonce(HEADER_NONCE_SIZE, 0);
	exception_on_invalid_buffer(header_nonce);
	if (header_nonce.fillRandom(HEADER_NONCE_SIZE) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to generate header nonce.");
	}
	packet_header_struct.has_header_nonce = true;
	packet_header_struct.header_nonce.data = header_nonce.content;
	packet_header_struct.header_nonce.len = header_nonce.content_length;

	//encrypt the header
	Buffer encrypted_axolotl_header(
			axolotl_header.content_length + crypto_secretbox_MACBYTES,
			axolotl_header.content_length + crypto_secretbox_MACBYTES);
	exception_on_invalid_buffer(encrypted_axolotl_header);
	int status = crypto_secretbox_easy(
			encrypted_axolotl_header.content,
			axolotl_header.content,
			axolotl_header.content_length,
			header_nonce.content,
			axolotl_header_key.content);
	if (status != 0) {
		throw MolchException(ENCRYPT_ERROR, "Failed to encrypt header.");
	}

	//add the encrypted header to the protobuf struct
	packet_struct.has_encrypted_axolotl_header = true;
	packet_struct.encrypted_axolotl_header.data = encrypted_axolotl_header.content;
	packet_struct.encrypted_axolotl_header.len = encrypted_axolotl_header.content_length;

	//generate the message nonce and add it to the packet header
	Buffer message_nonce(MESSAGE_NONCE_SIZE, 0);
	exception_on_invalid_buffer(message_nonce);
	if (message_nonce.fillRandom(MESSAGE_NONCE_SIZE) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to generate message nonce.");
	}
	packet_header_struct.has_message_nonce = true;
	packet_header_struct.message_nonce.data = message_nonce.content;
	packet_header_struct.message_nonce.len = message_nonce.content_length;

	//pad the message (PKCS7 padding to 255 byte blocks, see RFC5652 section 6.3)
	unsigned char padding = (unsigned char)(255 - (message.content_length % 255));
	Buffer padded_message(message.content_length + padding, 0);
	exception_on_invalid_buffer(padded_message);
	//copy the message
	if (padded_message.cloneFrom(&message) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to clone message.");
	}
	//pad it
	std::fill(padded_message.content + padded_message.content_length, padded_message.content + padded_message.content_length + padding, padding);
	padded_message.content_length += padding;

	//encrypt the message
	Buffer encrypted_message(
			padded_message.content_length + crypto_secretbox_MACBYTES,
			padded_message.content_length + crypto_secretbox_MACBYTES);
	exception_on_invalid_buffer(encrypted_message);
	status = crypto_secretbox_easy(
			encrypted_message.content,
			padded_message.content,
			padded_message.content_length,
			message_nonce.content,
			message_key.content);
	if (status != 0) {
		throw MolchException(ENCRYPT_ERROR, "Failed to encrypt message.");
	}

	//add the encrypted message to the protobuf struct
	packet_struct.has_encrypted_message = true;
	packet_struct.encrypted_message.data = encrypted_message.content;
	packet_struct.encrypted_message.len = encrypted_message.content_length;

	//calculate the required length
	const size_t packed_length = packet__get_packed_size(&packet_struct);
	//pack the packet
	auto packet = std::make_unique<Buffer>(packed_length, 0);
	exception_on_invalid_buffer(*packet);
	packet->content_length = packet__pack(&packet_struct, packet->content);
	if (packet->content_length != packed_length) {
		throw MolchException(PROTOBUF_PACK_ERROR, "Packet packet has incorrect length.");
	}

	return packet;
}

void packet_decrypt(
		//outputs
		uint32_t& current_protocol_version,
		uint32_t& highest_supported_protocol_version,
		molch_message_type& packet_type,
		std::unique_ptr<Buffer>& axolotl_header,
		std::unique_ptr<Buffer>& message,
		//inputs
		const Buffer& packet,
		const Buffer& axolotl_header_key, //HEADER_KEY_SIZE
		const Buffer& message_key, //MESSAGE_KEY_SIZE
		//optional outputs (prekey messages only)
		Buffer * const public_identity_key,
		Buffer * const public_ephemeral_key,
		Buffer * const public_prekey) {
	//get metadata
	packet_get_metadata_without_verification(
		current_protocol_version,
		highest_supported_protocol_version,
		packet_type,
		packet,
		public_identity_key,
		public_ephemeral_key,
		public_prekey);

	//decrypt the header
	axolotl_header = packet_decrypt_header(packet, axolotl_header_key);

	//decrypt the message
	message = packet_decrypt_message(packet, message_key);
}

void packet_get_metadata_without_verification(
		//outputs
		uint32_t& current_protocol_version,
		uint32_t& highest_supported_protocol_version,
		molch_message_type& packet_type,
		//input
		const Buffer& packet,
		//optional outputs (prekey messages only)
		Buffer * const public_identity_key, //PUBLIC_KEY_SIZE
		Buffer * const public_ephemeral_key, //PUBLIC_KEY_SIZE
		Buffer * const public_prekey //PUBLIC_KEY_SIZE
		) {
	std::unique_ptr<Packet,PacketDeleter> packet_struct = packet_unpack(packet);

	if (packet_struct->packet_header->packet_type == PACKET_HEADER__PACKET_TYPE__PREKEY_MESSAGE) {
		//copy the public keys
		if (public_identity_key != nullptr) {
			if (public_identity_key->cloneFromRaw(packet_struct->packet_header->public_identity_key.data, packet_struct->packet_header->public_identity_key.len) != 0) {
				throw MolchException(BUFFER_ERROR, "Failed to copy public identity key.");
			}
		}
		if (public_ephemeral_key != nullptr) {
			if (public_ephemeral_key->cloneFromRaw(packet_struct->packet_header->public_ephemeral_key.data, packet_struct->packet_header->public_ephemeral_key.len) != 0) {
				throw MolchException(BUFFER_ERROR, "Failed to copy public ephemeral key.");
			}
		}
		if (public_prekey != nullptr) {
			if (public_prekey->cloneFromRaw(packet_struct->packet_header->public_prekey.data, packet_struct->packet_header->public_prekey.len) != 0) {
				throw MolchException(BUFFER_ERROR, "Failed to copy public prekey.");
			}
		}
	}

	current_protocol_version = packet_struct->packet_header->current_protocol_version;
	highest_supported_protocol_version = packet_struct->packet_header->highest_supported_protocol_version;
	packet_type = to_molch_message_type(packet_struct->packet_header->packet_type);
}

std::unique_ptr<Buffer> packet_decrypt_header(
		const Buffer& packet,
		const Buffer& axolotl_header_key) { //HEADER_KEY_SIZE
	std::unique_ptr<Packet,PacketDeleter> packet_struct;

	//check input
	if (!axolotl_header_key.contains(HEADER_KEY_SIZE)) {
		throw MolchException(INVALID_INPUT, "Invalid input to packet_decrypt_header.");
	}

	packet_struct = packet_unpack(packet);

	if (packet_struct->encrypted_axolotl_header.len < crypto_secretbox_MACBYTES) {
		throw MolchException(INCORRECT_BUFFER_SIZE, "The ciphertext of the axolotl header is too short.");
	}

	const size_t axolotl_header_length = packet_struct->encrypted_axolotl_header.len - crypto_secretbox_MACBYTES;
	auto axolotl_header = std::make_unique<Buffer>(axolotl_header_length, axolotl_header_length);
	exception_on_invalid_buffer(*axolotl_header);

	int status = crypto_secretbox_open_easy(
			axolotl_header->content,
			packet_struct->encrypted_axolotl_header.data,
			packet_struct->encrypted_axolotl_header.len,
			packet_struct->packet_header->header_nonce.data,
			axolotl_header_key.content);
	if (status != 0) {
		throw MolchException(DECRYPT_ERROR, "Failed to decrypt axolotl header.");
	}

	return axolotl_header;
}

std::unique_ptr<Buffer> packet_decrypt_message(const Buffer& packet, const Buffer& message_key) {
	//check input
	if (!message_key.contains(MESSAGE_KEY_SIZE)) {
		throw MolchException(INVALID_INPUT, "Invalid input to packet_decrypt_message.");
	}

	std::unique_ptr<Packet,PacketDeleter> packet_struct = packet_unpack(packet);

	if (packet_struct->encrypted_message.len < crypto_secretbox_MACBYTES) {
		throw MolchException(INCORRECT_BUFFER_SIZE, "The ciphertext of the message is too short.");
	}

	const size_t padded_message_length = packet_struct->encrypted_message.len - crypto_secretbox_MACBYTES;
	if (padded_message_length < 255) {
		throw MolchException(INCORRECT_BUFFER_SIZE, "The padded message is too short.");
	}
	Buffer padded_message(padded_message_length, padded_message_length);
	exception_on_invalid_buffer(padded_message);

	int status = crypto_secretbox_open_easy(
			padded_message.content,
			packet_struct->encrypted_message.data,
			packet_struct->encrypted_message.len,
			packet_struct->packet_header->message_nonce.data,
			message_key.content);
	if (status != 0) {
		throw MolchException(DECRYPT_ERROR, "Failed to decrypt message.");
	}

	//get the padding (last byte)
	unsigned char padding = padded_message.content[padded_message.content_length - 1];
	if (padding > padded_message.content_length) {
		throw MolchException(INCORRECT_BUFFER_SIZE, "The padded message is too short.");
	}

	//extract the message
	const size_t message_length = padded_message.content_length - padding;
	auto message = std::make_unique<Buffer>(message_length, 0);
	exception_on_invalid_buffer(*message);
	//TODO this doesn't need to be copied, setting the length should be enough
	if (message->copyFrom(0, &padded_message, 0, message_length) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy message from padded message.");
	}

	return message;
}
