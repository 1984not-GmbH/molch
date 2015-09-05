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

#ifndef LIB_MOLCH_H
#define LIB_MOLCH_H

/*
 * Create a new user. The user is identified by the public key.
 *
 * Get's random input (can be in any format and doesn't have
 * to be uniformly distributed) and uses it in combination
 * with the OS's random number generator to generate an
 * identity keypair for the user.
 *
 * IMPORTANT: Don't put random numbers provided by the operating
 * system in there.
 *
 * This also creates a signed list of prekeys to be uploaded to
 * the server.
 *
 * Returns 0 on success.
 */
int molch_create_user(
		unsigned char * const public_identity_key, //output, crypto_box_PUBLICKEYBYTES
		unsigned char * const prekey_list, //output, needs to be 100 * crypto_box_PUBLICKEYBYTES + crypto_onetimeauth_BYTES
		const unsigned char * const random_data,
		const size_t random_data_length) __attribute__((warn_unused_result));

//TODO: Get a list of users

typedef enum molch_message_type { PREKEY_MESSAGE, NORMAL_MESSAGE } molch_message_type;
/*
 * Get the type of a message.
 *
 * This is either a normal message or a prekey message.
 * Prekey messages mark the start of a new conversation.
 */
molch_message_type molch_get_message_type(
		const unsigned char * const packet,
		const size_t packet_length);

/*
 * Encrypt a message and create a packet that can be sent to the receiver.
 *
 * Returns 0 on success.
 */
int molch_encrypt_message(
		unsigned char * const packet, //output, has to be 362 + message_length Bytes long
		size_t *packet_length, //output, length of the packet
		const unsigned char * const message,
		const size_t message_length,
		molch_conversation conversation) __attribute__((warn_unused_result));

/*
 * Decrypt a message.
 *
 * Returns 0 on success.
 */
int molch_decrypt_message(
		unsigned char * const message, //output, buffer should be as long as the received packet
		size_t *message_length, //output
		const unsigned char * const packet, //received packet
		const size_t packet_length,
		molch_conversation conversation) __attribute__((warn_unused_result));


/*
 * Start a new conversation. (sending)
 *
 * This requires a new set of prekeys from the receiver.
 */
molch_conversation molch_create_send_conversation(
		unsigned char * const packet, //output, buffer should be 500 Bytes + message_length (TODO: specify exact size)
		size_t *packet_length, //output
		const unsigned char * const message,
		const size_t message_length
		const unsigned char * const prekey_list, //prekey list of the receiver
		const unsigned char * const sender_public_identity, //identity of the sender (user)
		const unsigned char * const receiver_public_identity) __attribute__((warn_unused_result)); //identity of the receiver

/*
 * Start a new conversation. (receiving)
 *
 * This also generates a new set of prekeys to be uploaded to the server.
 *
 * This function is called after receiving a prekey message.
 */
molch_conversation molch_create_receive_conversation(
		unsigned char * const message, //output, buffer should be as long as the received packet
		size_t * const message_length, //output
		const unsigned char * const packet, //received prekey packet
		const size_t packet_length,
		const unsigned char * const prekey_list, //output, needs to be 100 * crypto_box_PUBLICKEYBYTES + crypto_onetimeauth_BYTES
		const unsigned char * const public_identity) __attribute__((warn_unused_result)); //identity key of the receiver (user)

#endif
