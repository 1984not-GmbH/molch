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

#include "constants.h"
#include "ratchet.h"

#ifndef LIB_CONVERSATION_H
#define LIB_CONVERSATION_H

typedef struct conversation_t {
	buffer_t id[1]; //unique id of a conversation, generated randomly
	unsigned char id_storage[CONVERSATION_ID_SIZE];
	ratchet_state *ratchet;
} conversation_t;

/*
 * Create a new conversation
 */
int conversation_init(
		conversation_t * const conversation,
		const buffer_t * const our_private_identity,
		const buffer_t * const our_public_identity,
		const buffer_t * const their_public_identity,
		const buffer_t * const our_private_ephemeral,
		const buffer_t * const our_public_ephemeral,
		const buffer_t * const their_public_ephemeral) __attribute__((warn_unused_result));

/*
 * Destroy a conversation.
 */
void conversation_deinit(conversation_t * const conversation);

/*
 * Serialise a conversation into JSON. It get#s a mempool_t buffer and stores a tree of
 * mcJSON objects into the buffer starting at pool->position.
 *
 * Returns NULL in case of failure.
 */
mcJSON *conversation_json_export(const conversation_t * const conversation, mempool_t * const pool) __attribute__((warn_unused_result));

/*
 * Deserialize a conversation (import from JSON)
 */
int conversation_json_import(
		conversation_t * const conversation,
		const mcJSON * const json) __attribute__((warn_unused_result));
#endif
