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

#include "conversation.h"

/*
 * Create a new conversation struct and initialise the buffer pointer.
 */
conversation *create_struct() {
	conversation *conv= sodium_malloc(sizeof(conversation));
	if (conv == NULL) {
		return NULL;
	}

	buffer_init_with_pointer(conv->id, conv->id_storage, CONVERSATION_ID_SIZE, CONVERSATION_ID_SIZE);

	return conv;
}

/*
 * Create a new conversation
 */
conversation *conversation_create(
		const buffer_t * const our_private_identity,
		const buffer_t * const our_public_identity,
		const buffer_t * const their_public_identity,
		const buffer_t * const our_private_ephemeral,
		const buffer_t * const our_public_ephemeral,
		const buffer_t * const their_public_ephemeral) {
	conversation *conv = create_struct();
	if (conv == NULL) {
		return NULL;
	}

	//create random id
	if (buffer_fill_random(conv->id, CONVERSATION_ID_SIZE) != 0) {
		sodium_free(conv);
		return NULL;
	}

	ratchet_state *ratchet = ratchet_create(
			our_private_identity,
			our_public_identity,
			their_public_identity,
			our_private_ephemeral,
			our_public_ephemeral,
			their_public_ephemeral);
	if (ratchet == NULL) {
		sodium_free(conv);
	}

	conv->ratchet = ratchet;

	return conv;
}

/*
 * Destroy a conversation.
 */
void conversation_destroy(conversation * const conv) {
	ratchet_destroy(conv->ratchet);
	sodium_free(conv);
}

/*
 * Serialise a conversation into JSON. It get#s a mempool_t buffer and stores a tree of
 * mcJSON objects into the buffer starting at pool->position.
 *
 * Returns NULL in case of failure.
 */
mcJSON *conversation_json_export(const conversation * const conv, mempool_t * const pool) {
	if ((conv == NULL) || (pool == NULL)) {
		return NULL;
	}

	mcJSON *json = mcJSON_CreateObject(pool);
	if (json == NULL) {
		return NULL;
	}

	mcJSON *id = mcJSON_CreateHexString(conv->id, pool);
	if (id == NULL) {
		return NULL;
	}
	mcJSON *ratchet = ratchet_json_export(conv->ratchet, pool);
	if (ratchet == NULL) {
		return NULL;
	}

	mcJSON_AddItemToObject(json, buffer_create_from_string("id"), id, pool);
	mcJSON_AddItemToObject(json, buffer_create_from_string("ratchet"), ratchet, pool);

	return json;
}
