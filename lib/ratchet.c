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

#include "ratchet.h"
#include "diffie-hellman.h"
#include "hkdf.h"

/*
 * Start a new ratchet chain. This derives an initial root key and returns a new ratchet state.
 *
 * All the keys will be copied so you can free the buffers afterwards. (private identity get's
 * immediately deleted after deriving the initial root key though!)
 *
 * The return value is a valid ratchet state or NULL if an error occured.
 */
ratchet_state* ratchet_create(
		const unsigned char * const our_private_identity,
		const unsigned char * const our_public_identity,
		const unsigned char * const their_public_identity,
		const unsigned char * const our_private_ephemeral,
		const unsigned char * const our_public_ephemeral,
		const unsigned char * const their_public_ephemeral,
		bool am_i_alice) {
	ratchet_state *state = malloc(sizeof(ratchet_state));

	//derive pre root key to later derive the initial root key
	//and the first send chain key from
	//pre_root_key = HASH( DH(A,B0) || DH(A0,B) || DH(A0,B0) )
	assert(crypto_secretbox_KEYBYTES == crypto_auth_BYTES);
	unsigned char * const pre_root_key = malloc(crypto_secretbox_KEYBYTES);
	int status = triple_diffie_hellman(
			pre_root_key,
			our_private_identity,
			our_public_identity,
			our_private_ephemeral,
			our_public_ephemeral,
			their_public_identity,
			their_public_ephemeral,
			am_i_alice);
	if (status != 0) {
		sodium_memzero(state->root_key, crypto_secretbox_KEYBYTES);
		free(pre_root_key);
		free(state);
		return NULL;
	}

	//derive chain and root key from pre_root_key via HKDF
	unsigned char * const hkdf_buffer = malloc(crypto_secretbox_KEYBYTES * 2);
	const unsigned char salt[] = "molch--libsodium-crypto-library"; //TODO: Maybe use better salt?
	assert(sizeof(salt) == crypto_auth_KEYBYTES);
	const unsigned char info[] = "molch"; //TODO use another info string
	status = hkdf(
			hkdf_buffer,
			2 * crypto_secretbox_KEYBYTES,
			salt,
			pre_root_key,
			crypto_secretbox_KEYBYTES,
			info,
			sizeof(info));
	sodium_memzero(pre_root_key, crypto_secretbox_KEYBYTES);
	free(pre_root_key);
	if (status != 0) {
		sodium_memzero(hkdf_buffer, crypto_secretbox_KEYBYTES * 2);
		free(hkdf_buffer);
		return NULL;
	}
	//initialise chain and root key
	state->root_key = malloc(crypto_secretbox_KEYBYTES);
	state->send_chain_key = malloc(crypto_secretbox_KEYBYTES);
	state->receive_chain_key = malloc(crypto_secretbox_KEYBYTES);
	//copy hkdf buffer to actual root/chain key
	//TODO This kind of deviates from axolotl because the first chain key is identical for
	//send/receive, only one of them is used though
	memcpy(state->root_key, hkdf_buffer, crypto_secretbox_KEYBYTES);
	memcpy(state->send_chain_key, hkdf_buffer + crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	memcpy(state->receive_chain_key, state->send_chain_key, crypto_secretbox_KEYBYTES);
	sodium_memzero(hkdf_buffer, crypto_secretbox_KEYBYTES * 2);
	free(hkdf_buffer);

	//copy keys into state
	//our public identity
	state->our_public_identity = malloc(crypto_box_PUBLICKEYBYTES);
	memcpy(state->our_public_identity, our_public_identity, crypto_box_PUBLICKEYBYTES);
	//their_public_identity
	state->their_public_identity = malloc(crypto_box_PUBLICKEYBYTES);
	memcpy(state->their_public_identity, their_public_identity, crypto_box_PUBLICKEYBYTES);
	//our_private_ephemeral
	state->our_private_ephemeral = malloc(crypto_box_SECRETKEYBYTES);
	memcpy(state->our_private_ephemeral, our_private_ephemeral, crypto_box_SECRETKEYBYTES);
	//our_public_ephemeral
	state->our_public_ephemeral = malloc(crypto_box_PUBLICKEYBYTES);
	memcpy(state->our_public_ephemeral, our_public_ephemeral, crypto_box_PUBLICKEYBYTES);
	//their_public_ephemeral
	state->their_public_ephemeral = malloc(crypto_box_PUBLICKEYBYTES);
	memcpy(state->their_public_ephemeral, their_public_ephemeral, crypto_box_PUBLICKEYBYTES);

	//initialise message keystore for skipped messages
	state->skipped_message_keys = message_keystore_init();

	//set other state
	state->ratchet_flag = am_i_alice;
	state->send_message_number = 0;
	state->receive_message_number = 0;
	state->previous_message_number = 0;

	return state;

}

/*
 * End the ratchet chain and free the memory.
 */
void ratchet_destroy(ratchet_state *state) {
	//free keys
	//root key
	sodium_memzero(state->root_key, crypto_secretbox_KEYBYTES);
	free(state->root_key);
	//our public identity
	free(state->our_public_identity);
	//their_public_identity
	free(state->their_public_identity);
	//our private ephemeral
	sodium_memzero(state->our_private_ephemeral, crypto_box_SECRETKEYBYTES);
	free(state->our_private_ephemeral);
	//our public ephemeral
	free(state->our_public_ephemeral);
	//their public ephemeral
	free(state->their_public_ephemeral);

	//chain keys
	sodium_memzero(state->send_chain_key, crypto_secretbox_KEYBYTES);
	free(state->send_chain_key);
	sodium_memzero(state->receive_chain_key, crypto_secretbox_KEYBYTES);
	free(state->receive_chain_key);

	free(state);
}

