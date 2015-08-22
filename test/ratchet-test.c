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
#include "utils.h"
#include "common.h"

int main(void) {
	sodium_init();

	int status;

	//creating Alice's identity keypair
	unsigned char alice_private_identity[crypto_box_SECRETKEYBYTES];
	unsigned char alice_public_identity[crypto_box_PUBLICKEYBYTES];
	status = generate_and_print_keypair(
			alice_public_identity,
			alice_private_identity,
			"Alice",
			"identity");
	if (status != 0) {
		sodium_memzero(alice_private_identity, sizeof(alice_private_identity));
		return status;
	}

	//creating Alice's ephemeral keypair
	unsigned char alice_private_ephemeral[crypto_box_SECRETKEYBYTES];
	unsigned char alice_public_ephemeral[crypto_box_PUBLICKEYBYTES];
	status = generate_and_print_keypair(
			alice_public_ephemeral,
			alice_private_ephemeral,
			"Alice",
			"ephemeral");
	if (status != 0) {
		sodium_memzero(alice_private_identity, sizeof(alice_private_identity));
		sodium_memzero(alice_private_ephemeral, sizeof(alice_private_ephemeral));
		return status;
	}

	//creating Bob's identity keypair
	unsigned char bob_private_identity[crypto_box_SECRETKEYBYTES];
	unsigned char bob_public_identity[crypto_box_PUBLICKEYBYTES];
	status = generate_and_print_keypair(
			bob_public_identity,
			bob_private_identity,
			"Bob",
			"identity");
	if (status != 0) {
		sodium_memzero(alice_private_identity, sizeof(alice_private_identity));
		sodium_memzero(alice_private_ephemeral, sizeof(alice_private_ephemeral));
		sodium_memzero(bob_private_identity, sizeof(bob_private_identity));
		return status;
	}

	//creating Bob's ephemeral keypair
	unsigned char bob_private_ephemeral[crypto_box_SECRETKEYBYTES];
	unsigned char bob_public_ephemeral[crypto_box_PUBLICKEYBYTES];
	status = generate_and_print_keypair(
			bob_public_ephemeral,
			bob_private_ephemeral,
			"Bob",
			"ephemeral");
	if (status != 0) {
		sodium_memzero(alice_private_identity, sizeof(alice_private_identity));
		sodium_memzero(alice_private_ephemeral, sizeof(alice_private_ephemeral));
		sodium_memzero(bob_private_identity, sizeof(bob_private_identity));
		sodium_memzero(bob_private_ephemeral, sizeof(bob_private_ephemeral));
		return status;
	}

	//start new ratchet for alice
	printf("Creating new ratchet for Alice ...\n");
	ratchet_state *alice_state = ratchet_create(
			alice_private_identity,
			alice_public_identity,
			bob_public_identity,
			alice_private_ephemeral,
			alice_public_ephemeral,
			bob_public_ephemeral,
			true);
	sodium_memzero(alice_private_ephemeral, sizeof(alice_private_ephemeral));
	sodium_memzero(alice_private_identity, sizeof(alice_private_identity));
	if (alice_state == NULL) {
		sodium_memzero(bob_private_identity, sizeof(bob_private_identity));
		sodium_memzero(bob_private_ephemeral, sizeof(bob_private_ephemeral));
		return EXIT_FAILURE;
	}
	putchar('\n');
	//print Alice's initial root and chain keys
	printf("Alice's initial root key (%zi Bytes):\n", sizeof(alice_state->root_key));
	print_hex(alice_state->root_key, sizeof(alice_state->root_key), 30);
	printf("Alice's initial chain key (%zi Bytes):\n", sizeof(alice_state->send_chain_key));
	print_hex(alice_state->receive_chain_key, sizeof(alice_state->send_chain_key), 30);
	putchar('\n');

	//start new ratchet for bob
	printf("Creating new ratchet for Bob ...\n");
	ratchet_state *bob_state = ratchet_create(
			bob_private_identity,
			bob_public_identity,
			alice_public_identity,
			bob_private_ephemeral,
			bob_public_ephemeral,
			alice_public_ephemeral,
			false);
	sodium_memzero(bob_private_identity, sizeof(bob_private_identity));
	sodium_memzero(bob_private_ephemeral, sizeof(bob_private_ephemeral));
	if (bob_state == NULL) {
		ratchet_destroy(alice_state);
		return EXIT_FAILURE;
	}
	putchar('\n');
	//print Bob's initial root and chain keys
	printf("Bob's initial root key (%zi Bytes):\n", sizeof(bob_state->root_key));
	print_hex(bob_state->root_key, sizeof(bob_state->root_key), 30);
	printf("Bob's initial chain key (%zi Bytes):\n", sizeof(bob_state->send_chain_key));
	print_hex(bob_state->send_chain_key, sizeof(bob_state->send_chain_key), 30);
	putchar('\n');

	//compare Alice's and Bob's initial root and chain keys
	status = sodium_memcmp(
			alice_state->root_key,
			bob_state->root_key,
			sizeof(alice_state->root_key));
	if (status != 0) {
		fprintf(stderr, "ERROR: Alice's and Bob's initial root keys aren't the same.\n");
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		return EXIT_FAILURE;
	}
	printf("Alice's and Bob's initial root keys match!\n");

	//initial chain key
	status = sodium_memcmp(
			alice_state->receive_chain_key,
			bob_state->send_chain_key,
			sizeof(alice_state->send_chain_key));
	if (status != 0) {
		fprintf(stderr, "ERROR: Alice's and Bob's initial chain keys aren't the same.\n");
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		return EXIT_FAILURE;
	}
	printf("Alice's and Bob's initial chain keys match!\n\n");

	//--------------------------------------------------------------------------
	puts("----------------------------------------\n");
	//first, alice sends two messages
	unsigned char alice_send_key1[crypto_secretbox_KEYBYTES];
	status = ratchet_next_send_key(
			alice_send_key1,
			alice_state);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to get Alice's first send message key. (%i)\n", status);
		sodium_memzero(alice_send_key1, sizeof(alice_send_key1));
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		return status;
	}
	//print the send message key
	printf("Alice Ratchet 1 send message key 1:\n");
	print_hex(alice_send_key1, sizeof(alice_send_key1), 30);
	putchar('\n');

	//second message key
	unsigned char alice_send_key2[crypto_secretbox_KEYBYTES];
	status = ratchet_next_send_key(
			alice_send_key2,
			alice_state);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to get Alice's second send message key. (%i)\n", status);
		sodium_memzero(alice_send_key1, sizeof(alice_send_key1));
		sodium_memzero(alice_send_key2, sizeof(alice_send_key2));
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		return status;
	}
	//print the send message key
	printf("Alice Ratchet 1 send message key 2:\n");
	print_hex(alice_send_key2, sizeof(alice_send_key2), 30);
	putchar('\n');

	//third message_key
	unsigned char alice_send_key3[crypto_secretbox_KEYBYTES];
	status = ratchet_next_send_key(
			alice_send_key3,
			alice_state);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to get Alice's third send message key. (%i)\n", status);
		sodium_memzero(alice_send_key1, sizeof(alice_send_key1));
		sodium_memzero(alice_send_key2, sizeof(alice_send_key2));
		sodium_memzero(alice_send_key3, sizeof(alice_send_key3));
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		return status;
	}
	//print the send message key
	printf("Alice Ratchet 1 send message key 3:\n");
	print_hex(alice_send_key3, sizeof(alice_send_key3), 30);
	putchar('\n');

	//--------------------------------------------------------------------------
	puts("----------------------------------------\n");
	//now the receive end, Bob recreates the message keys
	unsigned char bob_receive_key1[crypto_secretbox_KEYBYTES];
	status = ratchet_receive(
			bob_receive_key1,
			alice_state->our_public_ephemeral,
			0, //purported message number
			0, //purported previous message number
			bob_state);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to generate Bob's first receive key. (%i)\n", status);
		sodium_memzero(alice_send_key1, sizeof(alice_send_key1));
		sodium_memzero(alice_send_key2, sizeof(alice_send_key2));
		sodium_memzero(alice_send_key3, sizeof(alice_send_key3));
		sodium_memzero(bob_receive_key1, sizeof(bob_receive_key1));
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		return status;
	}
	//print it out!
	printf("Bob Ratchet 1 receive message key 1:\n");
	print_hex(bob_receive_key1, sizeof(bob_receive_key1), 30);
	putchar('\n');

	//confirm validity of the message key (this is normally done after successfully decrypting
	//and authenticating a message with the key
	status = ratchet_set_last_message_authenticity(bob_state, true);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to set authenticity state. (%i)\n", status);
		sodium_memzero(alice_send_key1, sizeof(alice_send_key1));
		sodium_memzero(alice_send_key2, sizeof(alice_send_key2));
		sodium_memzero(alice_send_key3, sizeof(alice_send_key3));
		sodium_memzero(bob_receive_key1, sizeof(bob_receive_key1));
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		return status;
	}

	//second receive message key
	unsigned char bob_receive_key2[crypto_secretbox_KEYBYTES];
	status = ratchet_receive(
			bob_receive_key2,
			alice_state->our_public_ephemeral,
			1, //purported message number
			0, //purported previous message number
			bob_state);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to generate Bob's second receive key. (%i)\n", status);
		sodium_memzero(alice_send_key1, sizeof(alice_send_key1));
		sodium_memzero(alice_send_key2, sizeof(alice_send_key2));
		sodium_memzero(alice_send_key3, sizeof(alice_send_key3));
		sodium_memzero(bob_receive_key1, sizeof(bob_receive_key1));
		sodium_memzero(bob_receive_key2, sizeof(bob_receive_key2));
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		return status;
	}
	//print it out!
	printf("Bob Ratchet 1 receive message key 2:\n");
	print_hex(bob_receive_key2, sizeof(bob_receive_key2), 30);
	putchar('\n');

	//confirm validity of the message key (this is normally done after successfully decrypting
	//and authenticating a message with the key
	status = ratchet_set_last_message_authenticity(bob_state, true);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to set authenticity state. (%i)\n", status);
		sodium_memzero(alice_send_key1, sizeof(alice_send_key1));
		sodium_memzero(alice_send_key2, sizeof(alice_send_key2));
		sodium_memzero(alice_send_key3, sizeof(alice_send_key3));
		sodium_memzero(bob_receive_key1, sizeof(bob_receive_key1));
		sodium_memzero(bob_receive_key2, sizeof(bob_receive_key2));
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		return status;
	}

	//third receive message key
	unsigned char bob_receive_key3[crypto_secretbox_KEYBYTES];
	status = ratchet_receive(
			bob_receive_key3,
			alice_state->our_public_ephemeral,
			2, //purported message number
			0, //purported previous message number
			bob_state);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to generate Bob's third receive key. (%i)\n", status);
		sodium_memzero(alice_send_key1, sizeof(alice_send_key1));
		sodium_memzero(alice_send_key2, sizeof(alice_send_key2));
		sodium_memzero(alice_send_key3, sizeof(alice_send_key3));
		sodium_memzero(bob_receive_key1, sizeof(bob_receive_key1));
		sodium_memzero(bob_receive_key2, sizeof(bob_receive_key2));
		sodium_memzero(bob_receive_key3, sizeof(bob_receive_key3));
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		return status;
	}
	//print it out!
	printf("Bob Ratchet 1 receive message key 3:\n");
	print_hex(bob_receive_key3, sizeof(bob_receive_key3), 30);
	putchar('\n');

	//confirm validity of the message key (this is normally done after successfully decrypting
	//and authenticating a message with the key
	status = ratchet_set_last_message_authenticity(bob_state, true);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to set authenticity state. (%i)\n", status);
		sodium_memzero(alice_send_key1, sizeof(alice_send_key1));
		sodium_memzero(alice_send_key2, sizeof(alice_send_key2));
		sodium_memzero(alice_send_key3, sizeof(alice_send_key3));
		sodium_memzero(bob_receive_key1, sizeof(bob_receive_key1));
		sodium_memzero(bob_receive_key2, sizeof(bob_receive_key2));
		sodium_memzero(bob_receive_key3, sizeof(bob_receive_key3));
		return status;
	}

	//compare the message keys
	if (sodium_memcmp(alice_send_key1, bob_receive_key1, sizeof(alice_send_key1)) != 0) {
		fprintf(stderr, "ERROR: Alice's first send key and Bob's first receive key aren't the same.\n");
		sodium_memzero(alice_send_key1, sizeof(alice_send_key1));
		sodium_memzero(alice_send_key2, sizeof(alice_send_key2));
		sodium_memzero(alice_send_key3, sizeof(alice_send_key3));
		sodium_memzero(bob_receive_key1, sizeof(bob_receive_key1));
		sodium_memzero(bob_receive_key2, sizeof(bob_receive_key2));
		sodium_memzero(bob_receive_key3, sizeof(bob_receive_key2));
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		return EXIT_FAILURE;
	}
	sodium_memzero(alice_send_key1, sizeof(alice_send_key1));
	sodium_memzero(bob_receive_key1, sizeof(bob_receive_key1));
	printf("Alice's first send key and Bob's first receive key match.\n");

	//second key
	if (sodium_memcmp(alice_send_key2, bob_receive_key2, sizeof(alice_send_key2)) != 0) {
		fprintf(stderr, "ERROR: Alice's second send key and Bob's second receive key aren't the same.\n");
		sodium_memzero(alice_send_key2, sizeof(alice_send_key2));
		sodium_memzero(alice_send_key3, sizeof(alice_send_key3));
		sodium_memzero(bob_receive_key2, sizeof(bob_receive_key2));
		sodium_memzero(bob_receive_key3, sizeof(bob_receive_key2));
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		return EXIT_FAILURE;
	}
	sodium_memzero(alice_send_key2, sizeof(alice_send_key2));
	sodium_memzero(bob_receive_key2, sizeof(bob_receive_key2));
	printf("Alice's second send key and Bob's second receive key match.\n");

	//third key
	if (sodium_memcmp(alice_send_key3, bob_receive_key3, sizeof(alice_send_key3)) != 0) {
		fprintf(stderr, "ERROR: Alice's third send key and Bob's third receive key aren't the same.\n");
		sodium_memzero(alice_send_key3, sizeof(alice_send_key3));
		sodium_memzero(bob_receive_key3, sizeof(bob_receive_key3));
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		return EXIT_FAILURE;
	}
	sodium_memzero(alice_send_key3, sizeof(alice_send_key3));
	sodium_memzero(bob_receive_key3, sizeof(bob_receive_key3));
	printf("Alice's third send key and Bob's third receive key match.\n");
	putchar('\n');

	//--------------------------------------------------------------------------
	puts("----------------------------------------\n");
	//Now Bob replies with three messages
	unsigned char bob_send_key1[crypto_secretbox_KEYBYTES];
	status = ratchet_next_send_key(
			bob_send_key1,
			bob_state);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to get Bob's first send message key. (%i)\n", status);
		sodium_memzero(bob_send_key1, sizeof(bob_send_key1));
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		return status;
	}
	//print the send message key
	printf("Bob Ratchet 2 send message key 1:\n");
	print_hex(bob_send_key1, sizeof(bob_send_key1), 30);
	putchar('\n');

	//second message key
	unsigned char bob_send_key2[crypto_secretbox_KEYBYTES];
	status = ratchet_next_send_key(
			bob_send_key2,
			bob_state);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to get Bob's second send message key. (%i)\n", status);
		sodium_memzero(bob_send_key1, sizeof(bob_send_key1));
		sodium_memzero(bob_send_key2, sizeof(bob_send_key2));
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		return status;
	}
	//print the send message key
	printf("Bob Ratchet 2 send message key 1:\n");
	print_hex(bob_send_key2, sizeof(bob_send_key2), 30);
	putchar('\n');

	//third message key
	unsigned char bob_send_key3[crypto_secretbox_KEYBYTES];
	status = ratchet_next_send_key(
			bob_send_key3,
			bob_state);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to get Bob's third send message key. (%i)\n", status);
		sodium_memzero(bob_send_key1, sizeof(bob_send_key1));
		sodium_memzero(bob_send_key2, sizeof(bob_send_key2));
		sodium_memzero(bob_send_key3, sizeof(bob_send_key3));
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		return status;
	}
	//print the send message key
	printf("Bob Ratchet 2 send message key 3:\n");
	print_hex(bob_send_key3, sizeof(bob_send_key3), 30);
	putchar('\n');

	//--------------------------------------------------------------------------
	puts("----------------------------------------\n");
	//now alice receives the first, then the third message (second message skipped)
	unsigned char alice_receive_key1[crypto_secretbox_KEYBYTES];
	status = ratchet_receive(
			alice_receive_key1,
			bob_state->our_public_ephemeral,
			0, //purported message number
			0, //purported previous message number
			alice_state);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to generate Alice's first receive key. (%i)\n", status);
		sodium_memzero(bob_send_key1, sizeof(bob_send_key1));
		sodium_memzero(bob_send_key2, sizeof(bob_send_key2));
		sodium_memzero(bob_send_key3, sizeof(bob_send_key3));
		sodium_memzero(alice_receive_key1, sizeof(alice_receive_key1));
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		return status;
	}
	//print it out
	printf("Alice Ratchet 2 receive message key 1:\n");
	print_hex(alice_receive_key1, sizeof(alice_receive_key1), 30);
	putchar('\n');

	//confirm validity of the message key
	status = ratchet_set_last_message_authenticity(alice_state, true);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to set authenticity state. (%i)\n", status);
		sodium_memzero(bob_send_key1, sizeof(bob_send_key1));
		sodium_memzero(bob_send_key2, sizeof(bob_send_key2));
		sodium_memzero(bob_send_key3, sizeof(bob_send_key3));
		sodium_memzero(alice_receive_key1, sizeof(alice_receive_key1));
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		return status;
	}

	//third received message key (second message skipped)
	unsigned char alice_receive_key3[crypto_secretbox_KEYBYTES];
	status = ratchet_receive(
			alice_receive_key3,
			bob_state->our_public_ephemeral,
			2,
			0,
			alice_state);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to generate Alice's third receive key. (%i)\n", status);
		sodium_memzero(bob_send_key1, sizeof(bob_send_key1));
		sodium_memzero(bob_send_key2, sizeof(bob_send_key2));
		sodium_memzero(bob_send_key3, sizeof(bob_send_key3));
		sodium_memzero(alice_receive_key1, sizeof(alice_receive_key1));
		sodium_memzero(alice_receive_key3, sizeof(alice_receive_key3));
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		return status;
	}
	//print it out
	printf("Alice Ratchet 2 receive message key 3:\n");
	print_hex(alice_receive_key3, sizeof(alice_receive_key3), 30);
	putchar('\n');

	assert(alice_state->purported_header_and_message_keys.length == 1);

	//confirm validity of the message key
	status = ratchet_set_last_message_authenticity(alice_state, true);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to set authenticity state. (%i)\n", status);
		sodium_memzero(bob_send_key1, sizeof(bob_send_key1));
		sodium_memzero(bob_send_key2, sizeof(bob_send_key2));
		sodium_memzero(bob_send_key3, sizeof(bob_send_key3));
		sodium_memzero(alice_receive_key1, sizeof(alice_receive_key1));
		sodium_memzero(alice_receive_key3, sizeof(alice_receive_key3));
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		return status;
	}

	assert(alice_state->purported_header_and_message_keys.length == 0);
	assert(alice_state->skipped_header_and_message_keys.length == 1);

	//get the second receive key from the message keystore
	unsigned char alice_receive_key2[crypto_secretbox_KEYBYTES];
	memcpy(alice_receive_key2, alice_state->skipped_header_and_message_keys.tail->message_key, sizeof(alice_receive_key2));
	printf("Alice Ratchet 2 receive message key 2:\n");
	print_hex(alice_receive_key2, sizeof(alice_receive_key2), 30);
	putchar('\n');

	//compare the keys
	if (sodium_memcmp(bob_send_key1, alice_receive_key1, sizeof(bob_send_key1)) != 0) {
		fprintf(stderr, "ERROR: Bob's first send key and Alice's first receive key aren't the same.\n");
		sodium_memzero(bob_send_key1, sizeof(bob_send_key1));
		sodium_memzero(bob_send_key2, sizeof(bob_send_key2));
		sodium_memzero(bob_send_key3, sizeof(bob_send_key3));
		sodium_memzero(alice_receive_key1, sizeof(alice_receive_key1));
		sodium_memzero(alice_receive_key2, sizeof(alice_receive_key2));
		sodium_memzero(alice_receive_key3, sizeof(alice_receive_key3));
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		return EXIT_FAILURE;
	}
	sodium_memzero(bob_send_key1, sizeof(bob_send_key1));
	sodium_memzero(alice_receive_key1, sizeof(alice_receive_key1));
	printf("Bob's first send key and Alice's first receive key match.\n");

	//second key
	if (sodium_memcmp(bob_send_key2, alice_receive_key2, sizeof(bob_send_key2)) != 0) {
		fprintf(stderr, "ERROR: Bob's second send key and Alice's second receive key aren't the same.\n");
		sodium_memzero(bob_send_key2, sizeof(bob_send_key2));
		sodium_memzero(bob_send_key3, sizeof(bob_send_key3));
		sodium_memzero(alice_receive_key2, sizeof(alice_receive_key2));
		sodium_memzero(alice_receive_key3, sizeof(alice_receive_key3));
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		return EXIT_FAILURE;
	}
	sodium_memzero(bob_send_key2, sizeof(bob_send_key2));
	sodium_memzero(alice_receive_key2, sizeof(alice_receive_key2));
	printf("Bob's second send key and Alice's second receive key match.\n");

	//third key
	if (sodium_memcmp(bob_send_key3, alice_receive_key3, sizeof(bob_send_key3)) != 0) {
		fprintf(stderr, "ERROR: Bob's third send key and Alice's third receive key aren't the same.\n");
		sodium_memzero(bob_send_key3, sizeof(bob_send_key3));
		sodium_memzero(alice_receive_key3, sizeof(alice_receive_key3));
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		return EXIT_FAILURE;
	}
	sodium_memzero(bob_send_key3, sizeof(bob_send_key3));
	sodium_memzero(alice_receive_key3, sizeof(alice_receive_key3));
	printf("Bob's third send key and Alice's third receive key match.\n\n");


	//destroy the ratchets again
	printf("Destroying Alice's ratchet ...\n");
	ratchet_destroy(alice_state);
	printf("Destroying Bob's ratchet ...\n");
	ratchet_destroy(bob_state);

	return EXIT_SUCCESS;
}
