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

#include <algorithm>
#include <exception>

#include "packet.hpp"
#include "constants.h"
#include "molch-exception.hpp"
#include "protobuf.hpp"

namespace Molch {
	/*!
	 * Convert molch_message_type to PacketHeader__PacketType.
	 */
	static constexpr PacketHeader__PacketType to_packet_header_packet_type(const molch_message_type packet_type) {
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
	static constexpr molch_message_type to_molch_message_type(const PacketHeader__PacketType packet_type) {
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
	static std::unique_ptr<ProtobufCPacket,PacketDeleter> packet_unpack(const Buffer& packet) {
		//unpack the packet
		auto packet_struct{std::unique_ptr<ProtobufCPacket,PacketDeleter>(packet__unpack(&protobuf_c_allocator, packet.size, packet.content))};
		if (!packet_struct) {
			throw Exception(PROTOBUF_UNPACK_ERROR, "Failed to unpack packet.");
		}

		if (packet_struct->packet_header->current_protocol_version != 0) {
			throw Exception(UNSUPPORTED_PROTOCOL_VERSION, "The packet has an unsuported protocol version.");
		}

		//check if the packet contains the necessary fields
		if (!packet_struct->has_encrypted_axolotl_header
			|| !packet_struct->has_encrypted_message
			|| !packet_struct->packet_header->has_packet_type
			|| !packet_struct->packet_header->has_header_nonce
			|| !packet_struct->packet_header->has_message_nonce) {
			throw Exception(PROTOBUF_MISSING_ERROR, "Some fields are missing in the packet.");
		}

		//check the size of the nonces
		if ((packet_struct->packet_header->header_nonce.len != HEADER_NONCE_SIZE)
			|| (packet_struct->packet_header->message_nonce.len != MESSAGE_NONCE_SIZE)) {
			throw Exception(INCORRECT_BUFFER_SIZE, "At least one of the nonces has an incorrect length.");
		}

		if (packet_struct->packet_header->packet_type == PACKET_HEADER__PACKET_TYPE__PREKEY_MESSAGE) {
			//check if the public keys for prekey messages are there
			if (!packet_struct->packet_header->has_public_identity_key
				|| !packet_struct->packet_header->has_public_ephemeral_key
				|| !packet_struct->packet_header->has_public_prekey) {
				throw Exception(PROTOBUF_MISSING_ERROR, "The prekey packet misses at least one public key.");
			}

			//check the sizes of the public keys
			if ((packet_struct->packet_header->public_identity_key.len != PUBLIC_KEY_SIZE)
				|| (packet_struct->packet_header->public_ephemeral_key.len != PUBLIC_KEY_SIZE)
				|| (packet_struct->packet_header->public_prekey.len != PUBLIC_KEY_SIZE)) {
				throw Exception(INCORRECT_BUFFER_SIZE, "At least one of the public keys of the prekey packet has an incorrect length.");
			}
		}

		return packet_struct;
	}

	Buffer packet_encrypt(
			//inputs
			const molch_message_type packet_type,
			const Buffer& axolotl_header,
			const HeaderKey& axolotl_header_key,
			const Buffer& message,
			const MessageKey& message_key,
			//optional inputs (prekey messages only)
			const PublicKey * const public_identity_key,
			const PublicKey * const public_ephemeral_key,
			const PublicKey * const public_prekey) {
		//initialize the protobuf structs
		ProtobufCPacket packet_struct;
		packet__init(&packet_struct);
		ProtobufCPacketHeader packet_header_struct;
		packet_header__init(&packet_header_struct);
		packet_struct.packet_header = &packet_header_struct;

		//check the input
		if ((packet_type == INVALID)
			|| axolotl_header_key.empty
			|| message_key.empty) {
			throw Exception(INVALID_INPUT, "Invalid input to packet_encrypt.");
		}

		//set the protocol version
		packet_header_struct.current_protocol_version = 0;
		packet_header_struct.highest_supported_protocol_version = 0;

		//set the packet type
		packet_header_struct.has_packet_type = true;
		packet_header_struct.packet_type = to_packet_header_packet_type(packet_type);

		if (packet_type == PREKEY_MESSAGE) {
			//check input
			if ((public_identity_key == nullptr) || public_identity_key->empty
				|| (public_ephemeral_key == nullptr) || public_ephemeral_key->empty
				|| (public_prekey == nullptr) || public_prekey->empty) {
				throw Exception(INVALID_INPUT, "Invalid public key to packet_encrypt for prekey message.");
			}

			//set the public identity key
			packet_header_struct.has_public_identity_key = true;
			packet_header_struct.public_identity_key.data = const_cast<uint8_t*>(public_identity_key->data());
			packet_header_struct.public_identity_key.len = public_identity_key->size();

			//set the public ephemeral key
			packet_header_struct.has_public_ephemeral_key = true;
			packet_header_struct.public_ephemeral_key.data = const_cast<uint8_t*>(public_ephemeral_key->data());
			packet_header_struct.public_ephemeral_key.len = public_ephemeral_key->size();

			//set the public prekey
			packet_header_struct.has_public_prekey = true;
			packet_header_struct.public_prekey.data = const_cast<uint8_t*>(public_prekey->data());
			packet_header_struct.public_prekey.len = public_prekey->size();
		}

		//generate the header nonce and add it to the packet header
		Buffer header_nonce{HEADER_NONCE_SIZE, 0};
		header_nonce.fillRandom(HEADER_NONCE_SIZE);
		packet_header_struct.has_header_nonce = true;
		packet_header_struct.header_nonce.data = header_nonce.content;
		packet_header_struct.header_nonce.len = header_nonce.size;

		//encrypt the header
		Buffer encrypted_axolotl_header{
			axolotl_header.size + crypto_secretbox_MACBYTES,
			axolotl_header.size + crypto_secretbox_MACBYTES};
		auto status{crypto_secretbox_easy(
				encrypted_axolotl_header.content,
				axolotl_header.content,
				axolotl_header.size,
				header_nonce.content,
				axolotl_header_key.data())};
		if (status != 0) {
			throw Exception(ENCRYPT_ERROR, "Failed to encrypt header.");
		}

		//add the encrypted header to the protobuf struct
		packet_struct.has_encrypted_axolotl_header = true;
		packet_struct.encrypted_axolotl_header.data = encrypted_axolotl_header.content;
		packet_struct.encrypted_axolotl_header.len = encrypted_axolotl_header.size;

		//generate the message nonce and add it to the packet header
		Buffer message_nonce{MESSAGE_NONCE_SIZE, 0};
		message_nonce.fillRandom(MESSAGE_NONCE_SIZE);
		packet_header_struct.has_message_nonce = true;
		packet_header_struct.message_nonce.data = message_nonce.content;
		packet_header_struct.message_nonce.len = message_nonce.size;

		//pad the message (PKCS7 padding to 255 byte blocks, see RFC5652 section 6.3)
		auto padding{static_cast<unsigned char>(255 - (message.size % 255))};
		Buffer padded_message{message.size + padding, 0};
		//copy the message
		padded_message.cloneFrom(message);
		//pad it
		std::fill(padded_message.content + padded_message.size, padded_message.content + padded_message.size + padding, padding);
		padded_message.size += padding;

		//encrypt the message
		Buffer encrypted_message{
			padded_message.size + crypto_secretbox_MACBYTES,
			padded_message.size + crypto_secretbox_MACBYTES};
		status = crypto_secretbox_easy(
				encrypted_message.content,
				padded_message.content,
				padded_message.size,
				message_nonce.content,
				message_key.data());
		if (status != 0) {
			throw Exception(ENCRYPT_ERROR, "Failed to encrypt message.");
		}

		//add the encrypted message to the protobuf struct
		packet_struct.has_encrypted_message = true;
		packet_struct.encrypted_message.data = encrypted_message.content;
		packet_struct.encrypted_message.len = encrypted_message.size;

		//calculate the required length
		const auto packed_length{packet__get_packed_size(&packet_struct)};
		//pack the packet
		Buffer packet{packed_length, 0};
		packet.size = packet__pack(&packet_struct, packet.content);
		if (packet.size != packed_length) {
			throw Exception(PROTOBUF_PACK_ERROR, "Packet packet has incorrect length.");
		}

		return packet;
	}

	void packet_decrypt(
			//outputs
			uint32_t& current_protocol_version,
			uint32_t& highest_supported_protocol_version,
			molch_message_type& packet_type,
			Buffer& axolotl_header,
			Buffer& message,
			//inputs
			const Buffer& packet,
			const HeaderKey& axolotl_header_key,
			const MessageKey& message_key, //MESSAGE_KEY_SIZE
			//optional outputs (prekey messages only)
			PublicKey * const public_identity_key,
			PublicKey * const public_ephemeral_key,
			PublicKey * const public_prekey) {
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
			PublicKey * const public_identity_key,
			PublicKey * const public_ephemeral_key,
			PublicKey * const public_prekey) {
		std::unique_ptr<ProtobufCPacket,PacketDeleter> packet_struct{packet_unpack(packet)};

		if (packet_struct->packet_header->packet_type == PACKET_HEADER__PACKET_TYPE__PREKEY_MESSAGE) {
			//copy the public keys
			if (public_identity_key != nullptr) {
				public_identity_key->set(packet_struct->packet_header->public_identity_key.data, packet_struct->packet_header->public_identity_key.len);
			}
			if (public_ephemeral_key != nullptr) {
				public_ephemeral_key->set(packet_struct->packet_header->public_ephemeral_key.data, packet_struct->packet_header->public_ephemeral_key.len);
			}
			if (public_prekey != nullptr) {
				public_prekey->set(packet_struct->packet_header->public_prekey.data, packet_struct->packet_header->public_prekey.len);
			}
		}

		current_protocol_version = packet_struct->packet_header->current_protocol_version;
		highest_supported_protocol_version = packet_struct->packet_header->highest_supported_protocol_version;
		packet_type = to_molch_message_type(packet_struct->packet_header->packet_type);
	}

	Buffer packet_decrypt_header(
			const Buffer& packet,
			const HeaderKey& axolotl_header_key) {
		std::unique_ptr<ProtobufCPacket,PacketDeleter> packet_struct;

		//check input
		if (axolotl_header_key.empty) {
			throw Exception(INVALID_INPUT, "Invalid input to packet_decrypt_header.");
		}

		packet_struct = packet_unpack(packet);

		if (packet_struct->encrypted_axolotl_header.len < crypto_secretbox_MACBYTES) {
			throw Exception(INCORRECT_BUFFER_SIZE, "The ciphertext of the axolotl header is too short.");
		}

		const size_t axolotl_header_length{packet_struct->encrypted_axolotl_header.len - crypto_secretbox_MACBYTES};
		Buffer axolotl_header{axolotl_header_length, axolotl_header_length};

		auto status{crypto_secretbox_open_easy(
				axolotl_header.content,
				packet_struct->encrypted_axolotl_header.data,
				packet_struct->encrypted_axolotl_header.len,
				packet_struct->packet_header->header_nonce.data,
				axolotl_header_key.data())};
		if (status != 0) {
			throw Exception(DECRYPT_ERROR, "Failed to decrypt axolotl header.");
		}

		return axolotl_header;
	}

	Buffer packet_decrypt_message(const Buffer& packet, const MessageKey& message_key) {
		//check input
		if (message_key.empty) {
			throw Exception(INVALID_INPUT, "Invalid input to packet_decrypt_message.");
		}

		std::unique_ptr<ProtobufCPacket,PacketDeleter> packet_struct{packet_unpack(packet)};

		if (packet_struct->encrypted_message.len < crypto_secretbox_MACBYTES) {
			throw Exception(INCORRECT_BUFFER_SIZE, "The ciphertext of the message is too short.");
		}

		const size_t padded_message_length{packet_struct->encrypted_message.len - crypto_secretbox_MACBYTES};
		if (padded_message_length < 255) {
			throw Exception(INCORRECT_BUFFER_SIZE, "The padded message is too short.");
		}
		Buffer padded_message{padded_message_length, padded_message_length};

		auto status{crypto_secretbox_open_easy(
				padded_message.content,
				packet_struct->encrypted_message.data,
				packet_struct->encrypted_message.len,
				packet_struct->packet_header->message_nonce.data,
				message_key.data())};
		if (status != 0) {
			throw Exception(DECRYPT_ERROR, "Failed to decrypt message.");
		}

		//get the padding (last byte)
		auto padding{padded_message.content[padded_message.size - 1]};
		if (padding > padded_message.size) {
			throw Exception(INCORRECT_BUFFER_SIZE, "The padded message is too short.");
		}

		//extract the message
		const size_t message_length{padded_message.size - padding};
		Buffer message{message_length, 0};
		//TODO this doesn't need to be copied, setting the length should be enough
		message.copyFrom(0, padded_message, 0, message_length);

		return message;
	}
}
