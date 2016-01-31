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
#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>
#include <string.h>
#include <assert.h>

#include "../lib/ratchet.h"
#include "../lib/json.h"
#include "utils.h"
#include "common.h"
#include "tracing.h"

int main(void) {
	if (sodium_init() == -1) {
		return -1;
	}

	int status;

	//create all the buffers
	//alice keys
	buffer_t *alice_private_identity = buffer_create_on_heap(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	buffer_t *alice_public_identity = buffer_create_on_heap(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	buffer_t *alice_private_ephemeral = buffer_create_on_heap(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	buffer_t *alice_public_ephemeral = buffer_create_on_heap(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	//bob keys
	buffer_t *bob_private_identity = buffer_create_on_heap(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	buffer_t *bob_public_identity = buffer_create_on_heap(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	buffer_t *bob_private_ephemeral = buffer_create_on_heap(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	buffer_t *bob_public_ephemeral = buffer_create_on_heap(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	//alice send message and header keys
	buffer_t *alice_send_message_key1 = buffer_create_on_heap(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	buffer_t *alice_send_header_key1 = buffer_create_on_heap(crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
	buffer_t *alice_send_ephemeral1 = buffer_create_on_heap(PUBLIC_KEY_SIZE, 0);
	buffer_t *alice_send_message_key2 = buffer_create_on_heap(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	buffer_t *alice_send_header_key2 = buffer_create_on_heap(crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
	buffer_t *alice_send_ephemeral2 = buffer_create_on_heap(PUBLIC_KEY_SIZE, 0);
	buffer_t *alice_send_message_key3 = buffer_create_on_heap(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	buffer_t *alice_send_header_key3 = buffer_create_on_heap(crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
	buffer_t *alice_send_ephemeral3 = buffer_create_on_heap(PUBLIC_KEY_SIZE, 0);
	//bobs receive keys
	buffer_t *bob_current_receive_header_key = buffer_create_on_heap(crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
	buffer_t *bob_next_receive_header_key = buffer_create_on_heap(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	buffer_t *bob_receive_key1 = buffer_create_on_heap(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	buffer_t *bob_receive_key2 = buffer_create_on_heap(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	buffer_t *bob_receive_key3 = buffer_create_on_heap(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	//bobs śend message and header keys
	buffer_t *bob_send_message_key1 = buffer_create_on_heap(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	buffer_t *bob_send_header_key1 = buffer_create_on_heap(crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
	buffer_t *bob_send_ephemeral1 = buffer_create_on_heap(PUBLIC_KEY_SIZE, 0);
	buffer_t *bob_send_message_key2 = buffer_create_on_heap(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	buffer_t *bob_send_header_key2 = buffer_create_on_heap(crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
	buffer_t *bob_send_ephemeral2 = buffer_create_on_heap(PUBLIC_KEY_SIZE, 0);
	buffer_t *bob_send_message_key3 = buffer_create_on_heap(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	buffer_t *bob_send_header_key3 = buffer_create_on_heap(crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
	buffer_t *bob_send_ephemeral3 = buffer_create_on_heap(PUBLIC_KEY_SIZE, 0);
	//alice receive keys
	buffer_t *alice_current_receive_header_key = buffer_create_on_heap(crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
	buffer_t *alice_next_receive_header_key = buffer_create_on_heap(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	buffer_t *alice_receive_message_key1 = buffer_create_on_heap(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	buffer_t *alice_receive_message_key2 = buffer_create_on_heap(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	buffer_t *alice_receive_message_key3 = buffer_create_on_heap(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	buffer_t *alice_receive_header_key2 = buffer_create_on_heap(crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);

	//creating Alice's identity keypair
	buffer_create_from_string(alice_string, "Alice");
	buffer_create_from_string(identity_string, "identity");
	status = generate_and_print_keypair(
			alice_public_identity,
			alice_private_identity,
			alice_string,
			identity_string);
	if (status != 0) {
		goto cleanup;
	}

	//creating Alice's ephemeral keypair
	buffer_create_from_string(ephemeral_string, "ephemeral");
	status = generate_and_print_keypair(
			alice_public_ephemeral,
			alice_private_ephemeral,
			alice_string,
			ephemeral_string);
	if (status != 0) {
		goto cleanup;
	}

	//creating Bob's identity keypair
	buffer_create_from_string(bob_string, "Bob");
	status = generate_and_print_keypair(
			bob_public_identity,
			bob_private_identity,
			bob_string,
			identity_string);
	if (status != 0) {
		goto cleanup;
	}

	//creating Bob's ephemeral keypair
	status = generate_and_print_keypair(
			bob_public_ephemeral,
			bob_private_ephemeral,
			bob_string,
			ephemeral_string);
	if (status != 0) {
		goto cleanup;
	}

	//start new ratchet for alice
	printf("Creating new ratchet for Alice ...\n");
	ratchet_state *alice_state = ratchet_create(
			alice_private_identity,
			alice_public_identity,
			bob_public_identity,
			alice_private_ephemeral,
			alice_public_ephemeral,
			bob_public_ephemeral);
	buffer_clear(alice_private_ephemeral);
	buffer_clear(alice_private_identity);
	if (alice_state == NULL) {
		status = EXIT_FAILURE;
		goto cleanup;
	}
	putchar('\n');
	//print Alice's initial root and chain keys
	printf("Alice's initial root key (%zu Bytes):\n", alice_state->root_key->content_length);
	print_hex(alice_state->root_key);
	printf("Alice's initial chain key (%zu Bytes):\n", alice_state->send_chain_key->content_length);
	print_hex(alice_state->send_chain_key);
	putchar('\n');

	//start new ratchet for bob
	printf("Creating new ratchet for Bob ...\n");
	ratchet_state *bob_state = ratchet_create(
			bob_private_identity,
			bob_public_identity,
			alice_public_identity,
			bob_private_ephemeral,
			bob_public_ephemeral,
			alice_public_ephemeral);
	buffer_clear(bob_private_identity);
	buffer_clear(bob_private_ephemeral);
	if (bob_state == NULL) {
		status = EXIT_FAILURE;
		goto cleanup;
	}
	putchar('\n');
	//print Bob's initial root and chain keys
	printf("Bob's initial root key (%zu Bytes):\n", bob_state->root_key->content_length);
	print_hex(bob_state->root_key);
	printf("Bob's initial chain key (%zu Bytes):\n", bob_state->send_chain_key->content_length);
	print_hex(bob_state->send_chain_key);
	putchar('\n');

	//compare Alice's and Bob's initial root and chain keys
	status = buffer_compare(alice_state->root_key, bob_state->root_key);
	if (status != 0) {
		fprintf(stderr, "ERROR: Alice's and Bob's initial root keys aren't the same.\n");
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		goto cleanup;
	}
	printf("Alice's and Bob's initial root keys match!\n");

	//initial chain key
	status = buffer_compare(alice_state->receive_chain_key, bob_state->send_chain_key);
	if (status != 0) {
		fprintf(stderr, "ERROR: Alice's and Bob's initial chain keys aren't the same.\n");
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		goto cleanup;
	}
	printf("Alice's and Bob's initial chain keys match!\n\n");

	//--------------------------------------------------------------------------
	puts("----------------------------------------\n");
	//first, alice sends two messages
	uint32_t alice_send_message_number1;
	uint32_t alice_previous_message_number1;
	status = ratchet_send(
			alice_state,
			alice_send_header_key1,
			&alice_send_message_number1,
			&alice_previous_message_number1,
			alice_send_ephemeral1,
			alice_send_message_key1);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to get Alice's first send message key. (%i)\n", status);
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		goto cleanup;
	}
	//print the send message key
	printf("Alice Ratchet 1 send message key 1:\n");
	print_hex(alice_send_message_key1);
	printf("Alice Ratchet 1 send header key 1:\n");
	print_hex(alice_send_header_key1);
	putchar('\n');

	//second message key
	uint32_t alice_send_message_number2;
	uint32_t alice_previous_message_number2;
	status = ratchet_send(
			alice_state,
			alice_send_header_key2,
			&alice_send_message_number2,
			&alice_previous_message_number2,
			alice_send_ephemeral2,
			alice_send_message_key2);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to get Alice's second send message key. (%i)\n", status);
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		goto cleanup;
	}
	//print the send message key
	printf("Alice Ratchet 1 send message key 2:\n");
	print_hex(alice_send_message_key2);
	printf("Alice Ratchet 1 send header key 2:\n");
	print_hex(alice_send_header_key2);
	putchar('\n');

	//third message_key
	uint32_t alice_send_message_number3;
	uint32_t alice_previous_message_number3;
	status = ratchet_send(
			alice_state,
			alice_send_header_key3,
			&alice_send_message_number3,
			&alice_previous_message_number3,
			alice_send_ephemeral3,
			alice_send_message_key3);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to get Alice's third send message key. (%i)\n", status);
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		goto cleanup;
	}
	//print the send message key
	printf("Alice Ratchet 1 send message key 3:\n");
	print_hex(alice_send_message_key3);
	printf("Alice Ratchet 1 send header key 3:\n");
	print_hex(alice_send_header_key3);
	putchar('\n');

	//--------------------------------------------------------------------------
	puts("----------------------------------------\n");
	//get pointers to bob's receive header keys
	status = ratchet_get_receive_header_keys(
			bob_current_receive_header_key,
			bob_next_receive_header_key,
			bob_state);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to get Bob's receive header keys. (%i)\n", status);
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		goto cleanup;
	}

	printf("Bob's first current receive header key:\n");
	print_hex(bob_current_receive_header_key);
	printf("Bob's first next receive_header_key:\n");
	print_hex(bob_next_receive_header_key);
	putchar('\n');

	//check header decryptability
	ratchet_header_decryptability decryptable = NOT_TRIED;
	if (buffer_compare(bob_current_receive_header_key, alice_send_header_key1) == 0) {
		decryptable = CURRENT_DECRYPTABLE;
		printf("Header decryptable with current header key.\n");
	} else if (buffer_compare(bob_next_receive_header_key, alice_send_header_key1) == 0) {
		decryptable = NEXT_DECRYPTABLE;
		printf("Header decryptable with next header key.\n");
	} else {
		decryptable = UNDECRYPTABLE;
		fprintf(stderr, "ERROR: Failed to decrypt header.\n");
	}
	buffer_clear(alice_send_header_key1);
	buffer_clear(bob_current_receive_header_key);
	buffer_clear(bob_next_receive_header_key);

	//now the receive end, Bob recreates the message keys

	//set the header decryptability
	status = ratchet_set_header_decryptability(
			decryptable,
			bob_state);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to set Bob's header decryptability. (%i)\n", status);
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		goto cleanup;
	}

	status = ratchet_receive(
			bob_receive_key1,
			alice_send_ephemeral1,
			0, //purported message number
			0, //purported previous message number
			bob_state);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to generate Bob's first receive key. (%i)\n", status);
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		goto cleanup;
	}
	//print it out!
	printf("Bob Ratchet 1 receive message key 1:\n");
	print_hex(bob_receive_key1);
	putchar('\n');

	//confirm validity of the message key (this is normally done after successfully decrypting
	//and authenticating a message with the key
	status = ratchet_set_last_message_authenticity(bob_state, true);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to set authenticity state. (%i)\n", status);
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		goto cleanup;
	}

	status = ratchet_get_receive_header_keys(
			bob_current_receive_header_key,
			bob_next_receive_header_key,
			bob_state);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to get Bob's header keys. (%i)\n", status);
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		goto cleanup;
	}

	printf("Bob's second current receive header key:\n");
	print_hex(bob_current_receive_header_key);
	printf("Bob's second next receive_header_key:\n");
	print_hex(bob_next_receive_header_key);
	putchar('\n');

	//check header decryptability
	if (buffer_compare(bob_current_receive_header_key, alice_send_header_key2) == 0) {
		decryptable = CURRENT_DECRYPTABLE;
		printf("Header decryptable with current header key.\n");
	} else if (buffer_compare(bob_next_receive_header_key, alice_send_header_key2) == 0) {
		decryptable = NEXT_DECRYPTABLE;
		printf("Header decryptable with next header key.\n");
	} else {
		decryptable = UNDECRYPTABLE;
		fprintf(stderr, "ERROR: Failed to decrypt header.\n");
	}
	buffer_clear(alice_send_header_key2);
	buffer_clear(bob_current_receive_header_key);
	buffer_clear(bob_next_receive_header_key);

	//set the header decryptability
	status = ratchet_set_header_decryptability(
			decryptable,
			bob_state);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to set header decryptability. (%i)\n", status);
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		goto cleanup;
	}

	//second receive message key
	status = ratchet_receive(
			bob_receive_key2,
			alice_send_ephemeral2,
			1, //purported message number
			0, //purported previous message number
			bob_state);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to generate Bob's second receive key. (%i)\n", status);
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		goto cleanup;
	}
	//print it out!
	printf("Bob Ratchet 1 receive message key 2:\n");
	print_hex(bob_receive_key2);
	putchar('\n');

	//confirm validity of the message key (this is normally done after successfully decrypting
	//and authenticating a message with the key
	status = ratchet_set_last_message_authenticity(bob_state, true);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to set authenticity state. (%i)\n", status);
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		goto cleanup;
	}

	status = ratchet_get_receive_header_keys(
			bob_current_receive_header_key,
			bob_next_receive_header_key,
			bob_state);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to get receive header key buffers. (%i)\n", status);
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		goto cleanup;
	}

	printf("Bob's third current receive header key:\n");
	print_hex(bob_current_receive_header_key);
	printf("Bob's third next receive_header_key:\n");
	print_hex(bob_next_receive_header_key);
	putchar('\n');

	//check header decryptability
	if (buffer_compare(bob_current_receive_header_key, alice_send_header_key3) == 0) {
		decryptable = CURRENT_DECRYPTABLE;
		printf("Header decryptable with current header key.\n");
	} else if (buffer_compare(bob_next_receive_header_key, alice_send_header_key3) == 0) {
		decryptable = NEXT_DECRYPTABLE;
		printf("Header decryptable with next header key.\n");
	} else {
		decryptable = UNDECRYPTABLE;
		fprintf(stderr, "ERROR: Failed to decrypt header.\n");
	}
	buffer_clear(alice_send_header_key3);
	buffer_clear(bob_current_receive_header_key);
	buffer_clear(bob_next_receive_header_key);

	//set the header decryptability
	status = ratchet_set_header_decryptability(
			decryptable,
			bob_state);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to set header decryptability. (%i)\n", status);
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		goto cleanup;
	}

	//third receive message key
	status = ratchet_receive(
			bob_receive_key3,
			alice_send_ephemeral3,
			2, //purported message number
			0, //purported previous message number
			bob_state);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to generate Bob's third receive key. (%i)\n", status);
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		goto cleanup;
	}
	//print it out!
	printf("Bob Ratchet 1 receive message key 3:\n");
	print_hex(bob_receive_key3);
	putchar('\n');

	//confirm validity of the message key (this is normally done after successfully decrypting
	//and authenticating a message with the key
	status = ratchet_set_last_message_authenticity(bob_state, true);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to set authenticity state. (%i)\n", status);
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		goto cleanup;
	}

	//compare the message keys
	if (buffer_compare(alice_send_message_key1, bob_receive_key1) != 0) {
		fprintf(stderr, "ERROR: Alice's first send key and Bob's first receive key aren't the same.\n");
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		status = EXIT_FAILURE;
		goto cleanup;
	}
	buffer_clear(alice_send_message_key1);
	buffer_clear(bob_receive_key1);
	printf("Alice's first send key and Bob's first receive key match.\n");

	//second key
	if (buffer_compare(alice_send_message_key2, bob_receive_key2) != 0) {
		fprintf(stderr, "ERROR: Alice's second send key and Bob's second receive key aren't the same.\n");
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		status = EXIT_FAILURE;
		goto cleanup;
	}
	buffer_clear(alice_send_message_key2);
	buffer_clear(bob_receive_key2);
	printf("Alice's second send key and Bob's second receive key match.\n");

	//third key
	if (buffer_compare(alice_send_message_key3, bob_receive_key3) != 0) {
		fprintf(stderr, "ERROR: Alice's third send key and Bob's third receive key aren't the same.\n");
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		status = EXIT_FAILURE;
		goto cleanup;
	}
	buffer_clear(alice_send_message_key3);
	buffer_clear(bob_receive_key3);
	printf("Alice's third send key and Bob's third receive key match.\n");
	putchar('\n');

	//--------------------------------------------------------------------------
	puts("----------------------------------------\n");
	//Now Bob replies with three messages
	uint32_t bob_send_message_number1;
	uint32_t bob_previous_message_number1;
	status = ratchet_send(
			bob_state,
			bob_send_header_key1,
			&bob_send_message_number1,
			&bob_previous_message_number1,
			bob_send_ephemeral1,
			bob_send_message_key1);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to get Bob's first send message key. (%i)\n", status);
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		goto cleanup;
	}
	//print the send message key
	printf("Bob Ratchet 2 send message key 1:\n");
	print_hex(bob_send_message_key1);
	printf("Bob Ratchet 2 send header key 1:\n");
	print_hex(bob_send_header_key1);
	putchar('\n');

	//second message key
	uint32_t bob_send_message_number2;
	uint32_t bob_previous_message_number2;
	status = ratchet_send(
			bob_state,
			bob_send_header_key2,
			&bob_send_message_number2,
			&bob_previous_message_number2,
			bob_send_ephemeral2,
			bob_send_message_key2);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to get Bob's second send message key. (%i)\n", status);
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		goto cleanup;
	}
	//print the send message key
	printf("Bob Ratchet 2 send message key 1:\n");
	print_hex(bob_send_message_key2);
	printf("Bob Ratchet 2 send header key 1:\n");
	print_hex(bob_send_header_key2);
	putchar('\n');

	//third message key
	uint32_t bob_send_message_number3;
	uint32_t bob_previous_message_number3;
	status = ratchet_send(
			bob_state,
			bob_send_header_key3,
			&bob_send_message_number3,
			&bob_previous_message_number3,
			bob_send_ephemeral3,
			bob_send_message_key3);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to get Bob's third send message key. (%i)\n", status);
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		goto cleanup;
	}
	//print the send message key
	printf("Bob Ratchet 2 send message key 3:\n");
	print_hex(bob_send_message_key3);
	printf("Bob Ratchet 2 send header key 3:\n");
	print_hex(bob_send_header_key3);
	putchar('\n');

	//--------------------------------------------------------------------------
	puts("----------------------------------------\n");
	//get pointers to alice's receive header keys
	status = ratchet_get_receive_header_keys(
			alice_current_receive_header_key,
			alice_next_receive_header_key,
			alice_state);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to get Alice' receive keys. (%i)\n", status);
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		goto cleanup;
	}

	printf("Alice's first current receive header key:\n");
	print_hex(alice_current_receive_header_key);
	printf("Alice's first next receive_header_key:\n");
	print_hex(alice_next_receive_header_key);
	putchar('\n');

	//check header decryptability
	if (buffer_compare(alice_current_receive_header_key, bob_send_header_key1) == 0) {
		decryptable = CURRENT_DECRYPTABLE;
		printf("Header decryptable with current header key.\n");
	} else if (buffer_compare(alice_next_receive_header_key, bob_send_header_key1) == 0) {
		decryptable = NEXT_DECRYPTABLE;
		printf("Header decryptable with next header key.\n");
	} else {
		decryptable = UNDECRYPTABLE;
		fprintf(stderr, "ERROR: Failed to decrypt header.\n");
	}
	buffer_clear(bob_send_header_key1);
	buffer_clear(alice_current_receive_header_key);
	buffer_clear(alice_next_receive_header_key);

	//now alice receives the first, then the third message (second message skipped)

	//set the header decryptability
	status = ratchet_set_header_decryptability(
			decryptable,
			alice_state);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to set header decryptability. (%i)\n", status);
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		goto cleanup;
	}

	status = ratchet_receive(
			alice_receive_message_key1,
			bob_send_ephemeral1,
			0, //purported message number
			0, //purported previous message number
			alice_state);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to generate Alice's first receive key. (%i)\n", status);
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		goto cleanup;
	}
	//print it out
	printf("Alice Ratchet 2 receive message key 1:\n");
	print_hex(alice_receive_message_key1);
	putchar('\n');

	//confirm validity of the message key
	status = ratchet_set_last_message_authenticity(alice_state, true);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to set authenticity state. (%i)\n", status);
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		goto cleanup;
	}

	status = ratchet_get_receive_header_keys(
			alice_current_receive_header_key,
			alice_next_receive_header_key,
			alice_state);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to get Alice' receive header keys. (%i)\n", status);
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		goto cleanup;
	}

	printf("Alice's current receive header key:\n");
	print_hex(alice_current_receive_header_key);
	printf("Alice's next receive_header_key:\n");
	print_hex(alice_next_receive_header_key);
	putchar('\n');

	//check header decryptability
	if (buffer_compare(alice_current_receive_header_key, bob_send_header_key3) == 0) {
		decryptable = CURRENT_DECRYPTABLE;
		printf("Header decryptable with current header key.\n");
	} else if (buffer_compare(alice_next_receive_header_key, bob_send_header_key3) == 0) {
		decryptable = NEXT_DECRYPTABLE;
		printf("Header decryptable with next header key.\n");
	} else {
		decryptable = UNDECRYPTABLE;
		fprintf(stderr, "ERROR: Failed to decrypt header.\n");
	}
	buffer_clear(bob_send_header_key3);
	buffer_clear(alice_current_receive_header_key);
	buffer_clear(alice_next_receive_header_key);

	//set the header decryptability
	status = ratchet_set_header_decryptability(
			decryptable,
			alice_state);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to set header decryptability. (%i)\n", status);
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		goto cleanup;
	}

	//third received message key (second message skipped)
	status = ratchet_receive(
			alice_receive_message_key3,
			bob_send_ephemeral3,
			2,
			0,
			alice_state);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to generate Alice's third receive key. (%i)\n", status);
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		goto cleanup;
	}
	//print it out
	printf("Alice Ratchet 2 receive message key 3:\n");
	print_hex(alice_receive_message_key3);
	putchar('\n');

	assert(alice_state->purported_header_and_message_keys->length == 1);

	//confirm validity of the message key
	status = ratchet_set_last_message_authenticity(alice_state, true);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to set authenticity state. (%i)\n", status);
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		goto cleanup;
	}

	assert(alice_state->purported_header_and_message_keys->length == 0);
	assert(alice_state->skipped_header_and_message_keys->length == 1);

	//get the second receive message key from the message and header keystore
	status = buffer_clone(alice_receive_message_key2, alice_state->skipped_header_and_message_keys->tail->message_key);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to get Alice's second receive message key. (%i)\n", status);
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		goto cleanup;
	}
	printf("Alice Ratchet 2 receive message key 2:\n");
	print_hex(alice_receive_message_key2);
	putchar('\n');

	//get the second receive header key from the message and header keystore
	status = buffer_clone(alice_receive_header_key2, alice_state->skipped_header_and_message_keys->tail->header_key);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to get Alice's second receive header key. (%i)\n", status);
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		goto cleanup;
	}
	printf("Alice Ratchet 2 receive header key 2:\n");
	print_hex(alice_receive_header_key2);
	putchar('\n');

	//compare header keys
	if (buffer_compare(alice_receive_header_key2, bob_send_header_key2) != 0) {
		fprintf(stderr, "ERROR: Bob's second send header key and Alice's receive header key aren't the same.\n");
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		status = EXIT_FAILURE;
		goto cleanup;
	}
	printf("Bob's second send header key and Alice's receive header keys match.\n");
	buffer_clear(alice_receive_header_key2);
	buffer_clear(bob_send_header_key2);

	//compare the keys
	if (buffer_compare(bob_send_message_key1, alice_receive_message_key1) != 0) {
		fprintf(stderr, "ERROR: Bob's first send key and Alice's first receive key aren't the same.\n");
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		status = EXIT_FAILURE;
		goto cleanup;
	}
	buffer_clear(bob_send_message_key1);
	buffer_clear(bob_send_message_key1);
	printf("Bob's first send key and Alice's first receive key match.\n");

	//second key
	if (buffer_compare(bob_send_message_key2, alice_receive_message_key2) != 0) {
		fprintf(stderr, "ERROR: Bob's second send key and Alice's second receive key aren't the same.\n");
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		status = EXIT_FAILURE;
		goto cleanup;
	}
	buffer_clear(bob_send_message_key2);
	buffer_clear(alice_receive_message_key2);
	printf("Bob's second send key and Alice's second receive key match.\n");

	//third key
	if (buffer_compare(bob_send_message_key3, alice_receive_message_key3) != 0) {
		fprintf(stderr, "ERROR: Bob's third send key and Alice's third receive key aren't the same.\n");
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		status = EXIT_FAILURE;
		goto cleanup;
	}
	buffer_clear(bob_send_message_key3);
	buffer_clear(alice_receive_message_key3);
	printf("Bob's third send key and Alice's third receive key match.\n\n");

	//export Alice's ratchet to json
	printf("Test JSON export!\n");
	JSON_EXPORT(output, 100000, 1000, true, alice_state, ratchet_json_export);
	if (output == NULL) {
		fprintf(stderr, "ERROR: Failed to export to JSON.\n");
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		status = EXIT_FAILURE;
		goto cleanup;
	}
	printf("%.*s\n", (int)output->content_length, (char*)output->content);

	//test json import
	ratchet_state *imported_alice_state;
	JSON_IMPORT(imported_alice_state, 100000, output, ratchet_json_import);
	if (imported_alice_state == NULL) {
		fprintf(stderr, "ERROR: Failed to import from JSON.\n");
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		buffer_destroy_from_heap(output);
		status = EXIT_FAILURE;
		goto cleanup;
	}
	//export the imported to JSON again
	JSON_EXPORT(imported_output, 100000, 1000, true, imported_alice_state, ratchet_json_export);
	if (imported_output == NULL) {
		fprintf(stderr, "ERROR: Failed to export imported to JSON again.\n");
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		ratchet_destroy(imported_alice_state);
		buffer_destroy_from_heap(output);
		status = EXIT_FAILURE;
		goto cleanup;
	}
	ratchet_destroy(imported_alice_state);
	//compare with original JSON
	if (buffer_compare(imported_output, output) != 0) {
		fprintf(stderr, "ERROR: Imported user store is incorrect.\n");
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		buffer_destroy_from_heap(output);
		buffer_destroy_from_heap(imported_output);
		status = EXIT_FAILURE;
		goto cleanup;
	}
	buffer_destroy_from_heap(imported_output);
	buffer_destroy_from_heap(output);


	//destroy the ratchets again
	printf("Destroying Alice's ratchet ...\n");
	ratchet_destroy(alice_state);
	printf("Destroying Bob's ratchet ...\n");
	ratchet_destroy(bob_state);

cleanup:
	//create all the buffers
	//alice keys
	buffer_destroy_from_heap(alice_private_identity);
	buffer_destroy_from_heap(alice_public_identity);
	buffer_destroy_from_heap(alice_private_ephemeral);
	buffer_destroy_from_heap(alice_public_ephemeral);
	//bob keys
	buffer_destroy_from_heap(bob_private_identity);
	buffer_destroy_from_heap(bob_public_identity);
	buffer_destroy_from_heap(bob_private_ephemeral);
	buffer_destroy_from_heap(bob_public_ephemeral);
	//alice send message and header keys
	buffer_destroy_from_heap(alice_send_message_key1);
	buffer_destroy_from_heap(alice_send_header_key1);
	buffer_destroy_from_heap(alice_send_ephemeral1);
	buffer_destroy_from_heap(alice_send_message_key2);
	buffer_destroy_from_heap(alice_send_header_key2);
	buffer_destroy_from_heap(alice_send_ephemeral2);
	buffer_destroy_from_heap(alice_send_message_key3);
	buffer_destroy_from_heap(alice_send_header_key3);
	buffer_destroy_from_heap(alice_send_ephemeral3);
	//bobs receive keys
	buffer_destroy_from_heap(bob_current_receive_header_key);
	buffer_destroy_from_heap(bob_next_receive_header_key);
	buffer_destroy_from_heap(bob_receive_key1);
	buffer_destroy_from_heap(bob_receive_key2);
	buffer_destroy_from_heap(bob_receive_key3);
	//bobs śend message and header keys
	buffer_destroy_from_heap(bob_send_message_key1);
	buffer_destroy_from_heap(bob_send_header_key1);
	buffer_destroy_from_heap(bob_send_ephemeral1);
	buffer_destroy_from_heap(bob_send_message_key2);
	buffer_destroy_from_heap(bob_send_header_key2);
	buffer_destroy_from_heap(bob_send_ephemeral2);
	buffer_destroy_from_heap(bob_send_message_key3);
	buffer_destroy_from_heap(bob_send_header_key3);
	buffer_destroy_from_heap(bob_send_ephemeral3);
	//alice receive keys
	buffer_destroy_from_heap(alice_current_receive_header_key);
	buffer_destroy_from_heap(alice_next_receive_header_key);
	buffer_destroy_from_heap(alice_receive_message_key1);
	buffer_destroy_from_heap(alice_receive_message_key2);
	buffer_destroy_from_heap(alice_receive_message_key3);
	buffer_destroy_from_heap(alice_receive_header_key2);

	return status;
}
