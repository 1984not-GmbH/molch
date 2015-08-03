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

#include "ratchet.h"
#include "diffie-hellman.h"

/*
 * Start a new ratchet chain. This derives an initial root key and returns a new ratchet state.
 *
 * All the keys will be copied so you can free the buffers afterwards.
 * TODO: This probably isn't a good idea for the private identity key. I need some better way to deal with this.
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

	//derive initial root key via triple diffie Hellman
	//RK = HASH( DH(A,B0) || DH(A0,B) || DH(A0,B0) )
	state->root_key = malloc(crypto_secretbox_KEYBYTES);
	int status = triple_diffie_hellman(
			state->root_key,
			our_private_identity,
			our_public_identity,
			our_private_ephemeral,
			our_public_ephemeral,
			their_public_identity,
			their_public_ephemeral,
			am_i_alice);
	if (status != 0) {
		sodium_memzero(state->root_key, crypto_secretbox_KEYBYTES);
		free(state->root_key);
		free(state);
		return NULL;
	}

	//copy keys into state
	//our private identity
	state->our_private_identity = malloc(crypto_box_SECRETKEYBYTES);
	memcpy(state->our_private_identity, our_private_identity, crypto_box_SECRETKEYBYTES);
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

	//initialise chain key buffers
	state->send_chain_key = malloc(crypto_secretbox_KEYBYTES);
	state->receive_chain_key = malloc(crypto_secretbox_KEYBYTES);

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
	//our private identity
	sodium_memzero(state->our_private_identity, crypto_box_SECRETKEYBYTES);
	free(state->our_private_identity);
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

