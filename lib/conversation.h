/*  Molch, an implementation of the axolotl ratchet based on libsodium
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

#include "ratchet.h"

#ifndef LIB_CONVERSATION_H
#define LIB_CONVERSATION_H

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
		const buffer_t * const their_public_ephemeral) __attribute__((warn_unused_result));

/*
 * Send a message.
 *
 * FIXME: Better handle buffer lengths
 * The buffer for the packet (ciphertext) has to be 362 Bytes + message_length
 */
int conversation_send_message(
		buffer_t * ciphertext,
		const buffer_t * const message,
		ratchet_state * const state) __attribute__((warn_unused_result));

/*
 * Receive a message.
 *
 * FIXME: Better handle buffer lengths
 * TODO: Handle skipped messages.
 * The buffer for the message has to be ciphertext_length - 100
 */
int conversation_receive_message(
		buffer_t * const message,
		const buffer_t * const ciphertext,
		ratchet_state * const state) __attribute__((warn_unused_result));

/*
 * End and destroy a running conversation.
 */
void conversation_destroy(ratchet_state *state);

#endif
