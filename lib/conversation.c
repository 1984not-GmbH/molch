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
#include <assert.h>

#include "conversation.h"
#include "header.h"
#include "packet.h"

/*
 * Start new conversation.
 *
 * returns NULL in case of failures.
 */
ratchet_state* conversation_create(
		const buffer_t * const our_private_identity,
		const buffer_t * const our_public_identity,
		const buffer_t * const their_public_identity,
		const buffer_t * const our_private_ephemeral,
		const buffer_t * const our_public_ephemeral,
		const buffer_t * const their_public_ephemeral) {
	//check buffer sizes
	if ((our_private_identity->content_length != crypto_box_SECRETKEYBYTES)
		|| (our_public_identity->content_length != crypto_box_PUBLICKEYBYTES)
		|| (their_public_identity->content_length != crypto_box_PUBLICKEYBYTES)
		|| (our_private_ephemeral->content_length != crypto_box_SECRETKEYBYTES)
		|| (our_public_ephemeral->content_length != crypto_box_PUBLICKEYBYTES)
		|| (their_public_ephemeral->content_length != crypto_box_PUBLICKEYBYTES)) {
	    return NULL;
	}

	//decide if alice or bob by comparing their and our public key
	bool am_i_alice;
	//TODO Move this comparison to ratchet_create?
	int comparison = memcmp(our_public_identity->content, their_public_identity->content, our_public_identity->content_length);
	if (comparison > 0) {
		am_i_alice = true;
	} else if (comparison < 0) {
		am_i_alice = false;
	} else {
		return NULL;
	}

	return ratchet_create(
			our_private_identity,
			our_public_identity,
			their_public_identity,
			our_private_ephemeral,
			our_public_ephemeral,
			their_public_ephemeral,
			am_i_alice);
}

/*
 * Send a message.
 *
 * FIXME: Better handle buffer lengths
 * The buffer for the packet (ciphertext) has to be 362 Bytes + message_length
 */
int conversation_send_message(
		buffer_t * ciphertext,
		const buffer_t * const message,
		ratchet_state * const state) {
	//check buffer sizes
	if ((ciphertext->buffer_length < message->content_length + 362)) {
		//FIXME: Programmatically get the packet length
		return -6;
	}

	//get send keys
	buffer_t *message_key = buffer_create(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	buffer_t *header_key = buffer_create(crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
	int status = ratchet_next_send_keys(
			message_key,
			header_key,
			state);
	if (status != 0) {
		buffer_clear(message_key);
		buffer_clear(header_key);
		return status;
	}

	//create the header
	//TODO: move this to ratchet.h?
	uint32_t message_number = state->send_message_number;
	uint32_t previous_message_number = state->previous_message_number;
	buffer_t *header = buffer_create(crypto_box_PUBLICKEYBYTES + 8, crypto_box_PUBLICKEYBYTES + 8);
	status = header_construct(
			header,
			state->our_public_ephemeral,
			message_number,
			previous_message_number);
	if (status != 0) {
		buffer_clear(message_key);
		buffer_clear(header_key);
		buffer_clear(header);
		message_number = 0;
		previous_message_number = 0;
		return status;
	}

	//create the ciphertext
	status = packet_encrypt(
			ciphertext,
			0, //TODO: Specify packet types somewhere.
			0, //current protocol version
			0, //highest supported protocol version
			header,
			header_key,
			message,
			message_key);
	if (status != 0) {
		buffer_clear(message_key);
		buffer_clear(header_key);
		buffer_clear(header);
		return status;
	}

	buffer_clear(message_key);
	buffer_clear(header_key);
	buffer_clear(header);
	return 0;
}

/*
 * Receive a message.
 *
 * FIXME: Better handle buffer lengths
 * TODO: Handle skipped messages
 * The buffer for the message has to be ciphertext_length - 100
 */
int conversation_receive_message(
		buffer_t * const message,
		const buffer_t * const ciphertext,
		ratchet_state * const state) {
	int status;
	//possible receive header keys
    buffer_t *current_header_key = buffer_create(crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
    buffer_t *next_header_key = buffer_create(crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
    status = ratchet_get_receive_header_keys(
            current_header_key,
            next_header_key,
			state);
	if (status != 0) {
		buffer_clear(current_header_key);
		buffer_clear(next_header_key);
		return status;
	}

	//try to decrypt the header
	buffer_t *header = buffer_create(255, 0);
	buffer_t *message_nonce = buffer_create(crypto_secretbox_NONCEBYTES, crypto_secretbox_NONCEBYTES);
	ratchet_header_decryptability decryptable = NOT_TRIED;
	if (packet_decrypt_header( //test current header key
				ciphertext,
				header,
				message_nonce,
				current_header_key) == 0) {
		decryptable = CURRENT_DECRYPTABLE;
	} else if (packet_decrypt_header( //test next header key
				ciphertext,
				header,
				message_nonce,
				next_header_key) == 0) {
		decryptable = NEXT_DECRYPTABLE;
	} else {
		decryptable = UNDECRYPTABLE;
	}

	//check the header length
	if (header->content_length != crypto_box_PUBLICKEYBYTES + 8) {
		buffer_clear(header);
		buffer_clear(message_nonce);
		return -10;
	}

	//set decryptability
	status = ratchet_set_header_decryptability(
			decryptable,
			state);
	if (status != 0) {
		buffer_clear(header);
		buffer_clear(message_nonce);
	}

	//extract information from the header
	buffer_t *their_public_ephemeral = buffer_create(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	uint32_t message_number;
	uint32_t previous_message_number;
	status = header_extract(
			header,
			their_public_ephemeral,
			&message_number,
			&previous_message_number);
	if (status != 0) {
		buffer_clear(header);
		buffer_clear(message_nonce);
		return status;
	}

	//get the message key
	buffer_t *message_key = buffer_create(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	status = ratchet_receive(
			message_key,
			their_public_ephemeral,
			message_number,
			previous_message_number,
			state);
	if (status != 0) {
		buffer_clear(header);
		message_number = 0;
		previous_message_number = 0;
		buffer_clear(message_nonce);
		buffer_clear(message_key);
		buffer_clear(their_public_ephemeral);
		return -10;
	}
	buffer_clear(header);
	message_number = 0;
	previous_message_number = 0;
	buffer_clear(their_public_ephemeral);

	//finally decrypt the message
	buffer_t *plaintext = buffer_create(ciphertext->content_length, 0);
	status = packet_decrypt_message(
			ciphertext,
			plaintext,
			message_nonce,
			message_key);
	buffer_clear(message_nonce);
	buffer_clear(message_key);
	if (status != 0) {
		buffer_clear(plaintext);
		return status;
	}

	//copy the message
	status = buffer_clone(message, plaintext);
	if (status != 0) {
		buffer_clear(plaintext);
		buffer_clear(message);
		return status;
	}
	buffer_clear(plaintext);

	return 0;
}

/*
 * End and destroy a running conversation.
 */
void conversation_destroy(ratchet_state *state) {
	ratchet_destroy(state);
}
