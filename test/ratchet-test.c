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
	buffer_t *alice_private_identity = buffer_create(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	buffer_t *alice_public_identity = buffer_create(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	status = generate_and_print_keypair(
			alice_public_identity,
			alice_private_identity,
			buffer_create_from_string("Alice"),
			buffer_create_from_string("identity"));
	if (status != 0) {
		buffer_clear(alice_private_identity);
		return status;
	}

	//creating Alice's ephemeral keypair
	buffer_t *alice_private_ephemeral = buffer_create(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	buffer_t *alice_public_ephemeral = buffer_create(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	status = generate_and_print_keypair(
			alice_public_ephemeral,
			alice_private_ephemeral,
			buffer_create_from_string("Alice"),
			buffer_create_from_string("ephemeral"));
	if (status != 0) {
		buffer_clear(alice_private_identity);
		buffer_clear(alice_private_ephemeral);
		return status;
	}

	//creating Bob's identity keypair
	buffer_t *bob_private_identity = buffer_create(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	buffer_t *bob_public_identity = buffer_create(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	status = generate_and_print_keypair(
			bob_public_identity,
			bob_private_identity,
			buffer_create_from_string("Bob"),
			buffer_create_from_string("identity"));
	if (status != 0) {
		buffer_clear(alice_private_identity);
		buffer_clear(alice_private_ephemeral);
		buffer_clear(bob_private_identity);
		return status;
	}

	//creating Bob's ephemeral keypair
	buffer_t *bob_private_ephemeral = buffer_create(crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES);
	buffer_t *bob_public_ephemeral = buffer_create(crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
	status = generate_and_print_keypair(
			bob_public_ephemeral,
			bob_private_ephemeral,
			buffer_create_from_string("Bob"),
			buffer_create_from_string("ephemeral"));
	if (status != 0) {
		buffer_clear(alice_private_identity);
		buffer_clear(alice_private_ephemeral);
		buffer_clear(bob_private_identity);
		buffer_clear(bob_private_ephemeral);
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
	buffer_clear(alice_private_ephemeral);
	buffer_clear(alice_private_identity);
	if (alice_state == NULL) {
		buffer_clear(bob_private_identity);
		buffer_clear(bob_private_ephemeral);
		return EXIT_FAILURE;
	}
	putchar('\n');
	//print Alice's initial root and chain keys
	printf("Alice's initial root key (%zi Bytes):\n", alice_state->root_key.content_length);
	print_hex(alice_state->root_key.content, alice_state->root_key.content_length, 30);
	printf("Alice's initial chain key (%zi Bytes):\n", alice_state->send_chain_key.content_length);
	print_hex(alice_state->receive_chain_key.content, alice_state->send_chain_key.content_length, 30);
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
	buffer_clear(bob_private_identity);
	buffer_clear(bob_private_ephemeral);
	if (bob_state == NULL) {
		ratchet_destroy(alice_state);
		return EXIT_FAILURE;
	}
	putchar('\n');
	//print Bob's initial root and chain keys
	printf("Bob's initial root key (%zi Bytes):\n", bob_state->root_key.content_length);
	print_hex(bob_state->root_key.content, bob_state->root_key.content_length, 30);
	printf("Bob's initial chain key (%zi Bytes):\n", bob_state->send_chain_key.content_length);
	print_hex(bob_state->send_chain_key.content, bob_state->send_chain_key.content_length, 30);
	putchar('\n');

	//compare Alice's and Bob's initial root and chain keys
	status = buffer_compare(&(alice_state->root_key), &(bob_state->root_key));
	if (status != 0) {
		fprintf(stderr, "ERROR: Alice's and Bob's initial root keys aren't the same.\n");
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		return EXIT_FAILURE;
	}
	printf("Alice's and Bob's initial root keys match!\n");

	//initial chain key
	status = buffer_compare(&(alice_state->receive_chain_key), &(bob_state->send_chain_key));
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
	unsigned char alice_send_message_key1[crypto_secretbox_KEYBYTES];
	unsigned char alice_send_header_key1[crypto_aead_chacha20poly1305_KEYBYTES];
	status = ratchet_next_send_keys(
			alice_send_message_key1,
			alice_send_header_key1,
			alice_state);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to get Alice's first send message key. (%i)\n", status);
		sodium_memzero(alice_send_message_key1, sizeof(alice_send_message_key1));
		sodium_memzero(alice_send_header_key1, sizeof(alice_send_header_key1));
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		return status;
	}
	//print the send message key
	printf("Alice Ratchet 1 send message key 1:\n");
	print_hex(alice_send_message_key1, sizeof(alice_send_message_key1), 30);
	printf("Alice Ratchet 1 send header key 1:\n");
	print_hex(alice_send_header_key1, sizeof(alice_send_header_key1), 30);
	putchar('\n');

	//second message key
	unsigned char alice_send_message_key2[crypto_secretbox_KEYBYTES];
	unsigned char alice_send_header_key2[crypto_aead_chacha20poly1305_KEYBYTES];
	status = ratchet_next_send_keys(
			alice_send_message_key2,
			alice_send_header_key2,
			alice_state);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to get Alice's second send message key. (%i)\n", status);
		sodium_memzero(alice_send_message_key1, sizeof(alice_send_message_key1));
		sodium_memzero(alice_send_message_key2, sizeof(alice_send_message_key2));
		sodium_memzero(alice_send_header_key1, sizeof(alice_send_header_key1));
		sodium_memzero(alice_send_header_key2, sizeof(alice_send_header_key2));
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		return status;
	}
	//print the send message key
	printf("Alice Ratchet 1 send message key 2:\n");
	print_hex(alice_send_message_key2, sizeof(alice_send_message_key2), 30);
	printf("Alice Ratchet 1 send header key 2:\n");
	print_hex(alice_send_header_key2, sizeof(alice_send_header_key2), 30);
	putchar('\n');

	//third message_key
	unsigned char alice_send_message_key3[crypto_secretbox_KEYBYTES];
	unsigned char alice_send_header_key3[crypto_aead_chacha20poly1305_KEYBYTES];
	status = ratchet_next_send_keys(
			alice_send_message_key3,
			alice_send_header_key3,
			alice_state);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to get Alice's third send message key. (%i)\n", status);
		sodium_memzero(alice_send_message_key1, sizeof(alice_send_message_key1));
		sodium_memzero(alice_send_message_key2, sizeof(alice_send_message_key2));
		sodium_memzero(alice_send_message_key3, sizeof(alice_send_message_key3));
		sodium_memzero(alice_send_header_key1, sizeof(alice_send_header_key1));
		sodium_memzero(alice_send_header_key2, sizeof(alice_send_header_key2));
		sodium_memzero(alice_send_header_key3, sizeof(alice_send_header_key3));
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		return status;
	}
	//print the send message key
	printf("Alice Ratchet 1 send message key 3:\n");
	print_hex(alice_send_message_key3, sizeof(alice_send_message_key3), 30);
	printf("Alice Ratchet 1 send header key 3:\n");
	print_hex(alice_send_header_key3, sizeof(alice_send_header_key3), 30);
	putchar('\n');

	//--------------------------------------------------------------------------
	puts("----------------------------------------\n");
	//get pointers to bob's receive header keys
	const unsigned char *bob_current_receive_header_key;
	const unsigned char *bob_next_receive_header_key;
	ratchet_get_receive_header_keys(
			&bob_current_receive_header_key,
			&bob_next_receive_header_key,
			bob_state);

	printf("Bob's first current receive header key:\n");
	print_hex(bob_current_receive_header_key, crypto_aead_chacha20poly1305_KEYBYTES, 30);
	printf("Bob's first next receive_header_key:\n");
	print_hex(bob_next_receive_header_key, crypto_aead_chacha20poly1305_KEYBYTES, 30);
	putchar('\n');

	//check header decryptability
	ratchet_header_decryptability decryptable = NOT_TRIED;
	if (sodium_memcmp(bob_current_receive_header_key, alice_send_header_key1, sizeof(alice_send_header_key1)) == 0) {
		decryptable = CURRENT_DECRYPTABLE;
		printf("Header decryptable with current header key.\n");
	} else if (sodium_memcmp(bob_next_receive_header_key, alice_send_header_key1, sizeof(alice_send_header_key1)) == 0) {
		decryptable = NEXT_DECRYPTABLE;
		printf("Header decryptable with next header key.\n");
	} else {
		decryptable = UNDECRYPTABLE;
		fprintf(stderr, "ERROR: Failed to decrypt header.\n");
	}
	sodium_memzero(alice_send_header_key1, sizeof(alice_send_header_key1));

	//now the receive end, Bob recreates the message keys

	//set the header decryptability
	status = ratchet_set_header_decryptability(
			decryptable,
			bob_state);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to set Bob's header decryptability. (%i)\n", status);
		sodium_memzero(alice_send_message_key1, sizeof(alice_send_message_key1));
		sodium_memzero(alice_send_message_key2, sizeof(alice_send_message_key2));
		sodium_memzero(alice_send_message_key3, sizeof(alice_send_message_key3));
		sodium_memzero(alice_send_header_key2, sizeof(alice_send_header_key2));
		sodium_memzero(alice_send_header_key3, sizeof(alice_send_header_key3));
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		return status;
	}

	unsigned char bob_receive_key1[crypto_secretbox_KEYBYTES];
	status = ratchet_receive(
			bob_receive_key1,
			alice_state->our_public_ephemeral.content,
			0, //purported message number
			0, //purported previous message number
			bob_state);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to generate Bob's first receive key. (%i)\n", status);
		sodium_memzero(alice_send_message_key1, sizeof(alice_send_message_key1));
		sodium_memzero(alice_send_message_key2, sizeof(alice_send_message_key2));
		sodium_memzero(alice_send_message_key3, sizeof(alice_send_message_key3));
		sodium_memzero(alice_send_header_key2, sizeof(alice_send_header_key2));
		sodium_memzero(alice_send_header_key3, sizeof(alice_send_header_key3));
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
		sodium_memzero(alice_send_message_key1, sizeof(alice_send_message_key1));
		sodium_memzero(alice_send_message_key2, sizeof(alice_send_message_key2));
		sodium_memzero(alice_send_message_key3, sizeof(alice_send_message_key3));
		sodium_memzero(alice_send_header_key2, sizeof(alice_send_header_key2));
		sodium_memzero(alice_send_header_key3, sizeof(alice_send_header_key3));
		sodium_memzero(bob_receive_key1, sizeof(bob_receive_key1));
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		return status;
	}

	printf("Bob's second current receive header key:\n");
	print_hex(bob_current_receive_header_key, crypto_aead_chacha20poly1305_KEYBYTES, 30);
	printf("Bob's second next receive_header_key:\n");
	print_hex(bob_next_receive_header_key, crypto_aead_chacha20poly1305_KEYBYTES, 30);
	putchar('\n');

	//check header decryptability
	if (sodium_memcmp(bob_current_receive_header_key, alice_send_header_key2, sizeof(alice_send_header_key2)) == 0) {
		decryptable = CURRENT_DECRYPTABLE;
		printf("Header decryptable with current header key.\n");
	} else if (sodium_memcmp(bob_next_receive_header_key, alice_send_header_key2, sizeof(alice_send_header_key2)) == 0) {
		decryptable = NEXT_DECRYPTABLE;
		printf("Header decryptable with next header key.\n");
	} else {
		decryptable = UNDECRYPTABLE;
		fprintf(stderr, "ERROR: Failed to decrypt header.\n");
	}
	sodium_memzero(alice_send_header_key2, sizeof(alice_send_header_key2));

	//set the header decryptability
	status = ratchet_set_header_decryptability(
			decryptable,
			bob_state);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to set header decryptability. (%i)\n", status);
		sodium_memzero(alice_send_message_key1, sizeof(alice_send_message_key1));
		sodium_memzero(alice_send_message_key2, sizeof(alice_send_message_key2));
		sodium_memzero(alice_send_message_key3, sizeof(alice_send_message_key3));
		sodium_memzero(alice_send_header_key3, sizeof(alice_send_header_key3));
		sodium_memzero(bob_receive_key1, sizeof(bob_receive_key1));
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		return status;
	}

	//second receive message key
	unsigned char bob_receive_key2[crypto_secretbox_KEYBYTES];
	status = ratchet_receive(
			bob_receive_key2,
			alice_state->our_public_ephemeral.content,
			1, //purported message number
			0, //purported previous message number
			bob_state);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to generate Bob's second receive key. (%i)\n", status);
		sodium_memzero(alice_send_message_key1, sizeof(alice_send_message_key1));
		sodium_memzero(alice_send_message_key2, sizeof(alice_send_message_key2));
		sodium_memzero(alice_send_message_key3, sizeof(alice_send_message_key3));
		sodium_memzero(alice_send_header_key3, sizeof(alice_send_header_key3));
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
		sodium_memzero(alice_send_message_key1, sizeof(alice_send_message_key1));
		sodium_memzero(alice_send_message_key2, sizeof(alice_send_message_key2));
		sodium_memzero(alice_send_message_key3, sizeof(alice_send_message_key3));
		sodium_memzero(alice_send_header_key3, sizeof(alice_send_header_key3));
		sodium_memzero(bob_receive_key1, sizeof(bob_receive_key1));
		sodium_memzero(bob_receive_key2, sizeof(bob_receive_key2));
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		return status;
	}

	printf("Bob's third current receive header key:\n");
	print_hex(bob_current_receive_header_key, crypto_aead_chacha20poly1305_KEYBYTES, 30);
	printf("Bob's third next receive_header_key:\n");
	print_hex(bob_next_receive_header_key, crypto_aead_chacha20poly1305_KEYBYTES, 30);
	putchar('\n');

	//check header decryptability
	if (sodium_memcmp(bob_current_receive_header_key, alice_send_header_key3, sizeof(alice_send_header_key3)) == 0) {
		decryptable = CURRENT_DECRYPTABLE;
		printf("Header decryptable with current header key.\n");
	} else if (sodium_memcmp(bob_next_receive_header_key, alice_send_header_key3, sizeof(alice_send_header_key3)) == 0) {
		decryptable = NEXT_DECRYPTABLE;
		printf("Header decryptable with next header key.\n");
	} else {
		decryptable = UNDECRYPTABLE;
		fprintf(stderr, "ERROR: Failed to decrypt header.\n");
	}
	sodium_memzero(alice_send_header_key3, sizeof(alice_send_header_key3));

	//set the header decryptability
	status = ratchet_set_header_decryptability(
			decryptable,
			bob_state);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to set header decryptability. (%i)\n", status);
		sodium_memzero(alice_send_message_key1, sizeof(alice_send_message_key1));
		sodium_memzero(alice_send_message_key2, sizeof(alice_send_message_key2));
		sodium_memzero(alice_send_message_key3, sizeof(alice_send_message_key3));
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
			alice_state->our_public_ephemeral.content,
			2, //purported message number
			0, //purported previous message number
			bob_state);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to generate Bob's third receive key. (%i)\n", status);
		sodium_memzero(alice_send_message_key1, sizeof(alice_send_message_key1));
		sodium_memzero(alice_send_message_key2, sizeof(alice_send_message_key2));
		sodium_memzero(alice_send_message_key3, sizeof(alice_send_message_key3));
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
		sodium_memzero(alice_send_message_key1, sizeof(alice_send_message_key1));
		sodium_memzero(alice_send_message_key2, sizeof(alice_send_message_key2));
		sodium_memzero(alice_send_message_key3, sizeof(alice_send_message_key3));
		sodium_memzero(bob_receive_key1, sizeof(bob_receive_key1));
		sodium_memzero(bob_receive_key2, sizeof(bob_receive_key2));
		sodium_memzero(bob_receive_key3, sizeof(bob_receive_key3));
		return status;
	}

	//compare the message keys
	if (sodium_memcmp(alice_send_message_key1, bob_receive_key1, sizeof(alice_send_message_key1)) != 0) {
		fprintf(stderr, "ERROR: Alice's first send key and Bob's first receive key aren't the same.\n");
		sodium_memzero(alice_send_message_key1, sizeof(alice_send_message_key1));
		sodium_memzero(alice_send_message_key2, sizeof(alice_send_message_key2));
		sodium_memzero(alice_send_message_key3, sizeof(alice_send_message_key3));
		sodium_memzero(bob_receive_key1, sizeof(bob_receive_key1));
		sodium_memzero(bob_receive_key2, sizeof(bob_receive_key2));
		sodium_memzero(bob_receive_key3, sizeof(bob_receive_key2));
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		return EXIT_FAILURE;
	}
	sodium_memzero(alice_send_message_key1, sizeof(alice_send_message_key1));
	sodium_memzero(bob_receive_key1, sizeof(bob_receive_key1));
	printf("Alice's first send key and Bob's first receive key match.\n");

	//second key
	if (sodium_memcmp(alice_send_message_key2, bob_receive_key2, sizeof(alice_send_message_key2)) != 0) {
		fprintf(stderr, "ERROR: Alice's second send key and Bob's second receive key aren't the same.\n");
		sodium_memzero(alice_send_message_key2, sizeof(alice_send_message_key2));
		sodium_memzero(alice_send_message_key3, sizeof(alice_send_message_key3));
		sodium_memzero(bob_receive_key2, sizeof(bob_receive_key2));
		sodium_memzero(bob_receive_key3, sizeof(bob_receive_key2));
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		return EXIT_FAILURE;
	}
	sodium_memzero(alice_send_message_key2, sizeof(alice_send_message_key2));
	sodium_memzero(bob_receive_key2, sizeof(bob_receive_key2));
	printf("Alice's second send key and Bob's second receive key match.\n");

	//third key
	if (sodium_memcmp(alice_send_message_key3, bob_receive_key3, sizeof(alice_send_message_key3)) != 0) {
		fprintf(stderr, "ERROR: Alice's third send key and Bob's third receive key aren't the same.\n");
		sodium_memzero(alice_send_message_key3, sizeof(alice_send_message_key3));
		sodium_memzero(bob_receive_key3, sizeof(bob_receive_key3));
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		return EXIT_FAILURE;
	}
	sodium_memzero(alice_send_message_key3, sizeof(alice_send_message_key3));
	sodium_memzero(bob_receive_key3, sizeof(bob_receive_key3));
	printf("Alice's third send key and Bob's third receive key match.\n");
	putchar('\n');

	//--------------------------------------------------------------------------
	puts("----------------------------------------\n");
	//Now Bob replies with three messages
	unsigned char bob_send_message_key1[crypto_secretbox_KEYBYTES];
	unsigned char bob_send_header_key1[crypto_aead_chacha20poly1305_KEYBYTES];
	status = ratchet_next_send_keys(
			bob_send_message_key1,
			bob_send_header_key1,
			bob_state);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to get Bob's first send message key. (%i)\n", status);
		sodium_memzero(bob_send_message_key1, sizeof(bob_send_message_key1));
		sodium_memzero(bob_send_header_key1, sizeof(bob_send_header_key1));
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		return status;
	}
	//print the send message key
	printf("Bob Ratchet 2 send message key 1:\n");
	print_hex(bob_send_message_key1, sizeof(bob_send_message_key1), 30);
	printf("Bob Ratchet 2 send header key 1:\n");
	print_hex(bob_send_header_key1, sizeof(bob_send_header_key1), 30);
	putchar('\n');

	//second message key
	unsigned char bob_send_message_key2[crypto_secretbox_KEYBYTES];
	unsigned char bob_send_header_key2[crypto_aead_chacha20poly1305_KEYBYTES];
	status = ratchet_next_send_keys(
			bob_send_message_key2,
			bob_send_header_key2,
			bob_state);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to get Bob's second send message key. (%i)\n", status);
		sodium_memzero(bob_send_message_key1, sizeof(bob_send_message_key1));
		sodium_memzero(bob_send_message_key2, sizeof(bob_send_message_key2));
		sodium_memzero(bob_send_header_key1, sizeof(bob_send_header_key1));
		sodium_memzero(bob_send_header_key2, sizeof(bob_send_header_key2));
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		return status;
	}
	//print the send message key
	printf("Bob Ratchet 2 send message key 1:\n");
	print_hex(bob_send_message_key2, sizeof(bob_send_message_key2), 30);
	printf("Bob Ratchet 2 send header key 1:\n");
	print_hex(bob_send_header_key2, sizeof(bob_send_header_key2), 30);
	putchar('\n');

	//third message key
	unsigned char bob_send_message_key3[crypto_secretbox_KEYBYTES];
	unsigned char bob_send_header_key3[crypto_aead_chacha20poly1305_KEYBYTES];
	status = ratchet_next_send_keys(
			bob_send_message_key3,
			bob_send_header_key3,
			bob_state);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to get Bob's third send message key. (%i)\n", status);
		sodium_memzero(bob_send_message_key1, sizeof(bob_send_message_key1));
		sodium_memzero(bob_send_message_key2, sizeof(bob_send_message_key2));
		sodium_memzero(bob_send_message_key3, sizeof(bob_send_message_key3));
		sodium_memzero(bob_send_header_key1, sizeof(bob_send_header_key1));
		sodium_memzero(bob_send_header_key2, sizeof(bob_send_header_key2));
		sodium_memzero(bob_send_header_key3, sizeof(bob_send_header_key3));
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		return status;
	}
	//print the send message key
	printf("Bob Ratchet 2 send message key 3:\n");
	print_hex(bob_send_message_key3, sizeof(bob_send_message_key3), 30);
	printf("Bob Ratchet 2 send header key 3:\n");
	print_hex(bob_send_header_key3, sizeof(bob_send_header_key3), 30);
	putchar('\n');

	//--------------------------------------------------------------------------
	puts("----------------------------------------\n");
	//get pointers to alice's receive header keys
	const unsigned char *alice_current_receive_header_key;
	const unsigned char *alice_next_receive_header_key;
	ratchet_get_receive_header_keys(
			&alice_current_receive_header_key,
			&alice_next_receive_header_key,
			alice_state);

	printf("Alice's first current receive header key:\n");
	print_hex(alice_current_receive_header_key, crypto_aead_chacha20poly1305_KEYBYTES, 30);
	printf("Alice's first next receive_header_key:\n");
	print_hex(alice_next_receive_header_key, crypto_aead_chacha20poly1305_KEYBYTES, 30);
	putchar('\n');

	//check header decryptability
	if (sodium_memcmp(alice_current_receive_header_key, bob_send_header_key1, sizeof(bob_send_header_key1)) == 0) {
		decryptable = CURRENT_DECRYPTABLE;
		printf("Header decryptable with current header key.\n");
	} else if (sodium_memcmp(alice_next_receive_header_key, bob_send_header_key1, sizeof(bob_send_header_key1)) == 0) {
		decryptable = NEXT_DECRYPTABLE;
		printf("Header decryptable with next header key.\n");
	} else {
		decryptable = UNDECRYPTABLE;
		fprintf(stderr, "ERROR: Failed to decrypt header.\n");
	}
	sodium_memzero(bob_send_header_key1, sizeof(bob_send_header_key1));

	//now alice receives the first, then the third message (second message skipped)

	//set the header decryptability
	status = ratchet_set_header_decryptability(
			decryptable,
			alice_state);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to set header decryptability. (%i)\n", status);
		sodium_memzero(bob_send_message_key1, sizeof(bob_send_message_key1));
		sodium_memzero(bob_send_message_key2, sizeof(bob_send_message_key2));
		sodium_memzero(bob_send_message_key3, sizeof(bob_send_message_key3));
		sodium_memzero(bob_send_header_key2, sizeof(bob_send_header_key2));
		sodium_memzero(bob_send_header_key3, sizeof(bob_send_header_key3));
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		return status;
	}

	unsigned char alice_receive_message_key1[crypto_secretbox_KEYBYTES];
	status = ratchet_receive(
			alice_receive_message_key1,
			bob_state->our_public_ephemeral.content,
			0, //purported message number
			0, //purported previous message number
			alice_state);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to generate Alice's first receive key. (%i)\n", status);
		sodium_memzero(bob_send_message_key1, sizeof(bob_send_message_key1));
		sodium_memzero(bob_send_message_key2, sizeof(bob_send_message_key2));
		sodium_memzero(bob_send_message_key3, sizeof(bob_send_message_key3));
		sodium_memzero(bob_send_header_key2, sizeof(bob_send_header_key2));
		sodium_memzero(bob_send_header_key3, sizeof(bob_send_header_key3));
		sodium_memzero(alice_receive_message_key1, sizeof(alice_receive_message_key1));
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		return status;
	}
	//print it out
	printf("Alice Ratchet 2 receive message key 1:\n");
	print_hex(alice_receive_message_key1, sizeof(alice_receive_message_key1), 30);
	putchar('\n');

	//confirm validity of the message key
	status = ratchet_set_last_message_authenticity(alice_state, true);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to set authenticity state. (%i)\n", status);
		sodium_memzero(bob_send_message_key1, sizeof(bob_send_message_key1));
		sodium_memzero(bob_send_message_key2, sizeof(bob_send_message_key2));
		sodium_memzero(bob_send_message_key3, sizeof(bob_send_message_key3));
		sodium_memzero(bob_send_header_key2, sizeof(bob_send_header_key2));
		sodium_memzero(bob_send_header_key3, sizeof(bob_send_header_key3));
		sodium_memzero(alice_receive_message_key1, sizeof(alice_receive_message_key1));
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		return status;
	}

	printf("Alice's current receive header key:\n");
	print_hex(alice_current_receive_header_key, crypto_aead_chacha20poly1305_KEYBYTES, 30);
	printf("Alice's next receive_header_key:\n");
	print_hex(alice_next_receive_header_key, crypto_aead_chacha20poly1305_KEYBYTES, 30);
	putchar('\n');

	//check header decryptability
	if (sodium_memcmp(alice_current_receive_header_key, bob_send_header_key3, sizeof(bob_send_header_key3)) == 0) {
		decryptable = CURRENT_DECRYPTABLE;
		printf("Header decryptable with current header key.\n");
	} else if (sodium_memcmp(alice_next_receive_header_key, bob_send_header_key3, sizeof(bob_send_header_key3)) == 0) {
		decryptable = NEXT_DECRYPTABLE;
		printf("Header decryptable with next header key.\n");
	} else {
		decryptable = UNDECRYPTABLE;
		fprintf(stderr, "ERROR: Failed to decrypt header.\n");
	}
	sodium_memzero(bob_send_header_key3, sizeof(bob_send_header_key3));

	//set the header decryptability
	status = ratchet_set_header_decryptability(
			decryptable,
			alice_state);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to set header decryptability. (%i)\n", status);
		sodium_memzero(bob_send_message_key1, sizeof(bob_send_message_key1));
		sodium_memzero(bob_send_message_key2, sizeof(bob_send_message_key2));
		sodium_memzero(bob_send_message_key3, sizeof(bob_send_message_key3));
		sodium_memzero(bob_send_header_key2, sizeof(bob_send_header_key2));
		sodium_memzero(alice_receive_message_key1, sizeof(alice_receive_message_key1));
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		return status;
	}

	//third received message key (second message skipped)
	unsigned char alice_receive_message_key3[crypto_secretbox_KEYBYTES];
	status = ratchet_receive(
			alice_receive_message_key3,
			bob_state->our_public_ephemeral.content,
			2,
			0,
			alice_state);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to generate Alice's third receive key. (%i)\n", status);
		sodium_memzero(bob_send_message_key1, sizeof(bob_send_message_key1));
		sodium_memzero(bob_send_message_key2, sizeof(bob_send_message_key2));
		sodium_memzero(bob_send_message_key3, sizeof(bob_send_message_key3));
		sodium_memzero(bob_send_header_key2, sizeof(bob_send_header_key2));
		sodium_memzero(alice_receive_message_key1, sizeof(alice_receive_message_key1));
		sodium_memzero(alice_receive_message_key3, sizeof(alice_receive_message_key3));
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		return status;
	}
	//print it out
	printf("Alice Ratchet 2 receive message key 3:\n");
	print_hex(alice_receive_message_key3, sizeof(alice_receive_message_key3), 30);
	putchar('\n');

	assert(alice_state->purported_header_and_message_keys.length == 1);

	//confirm validity of the message key
	status = ratchet_set_last_message_authenticity(alice_state, true);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to set authenticity state. (%i)\n", status);
		sodium_memzero(bob_send_message_key1, sizeof(bob_send_message_key1));
		sodium_memzero(bob_send_message_key2, sizeof(bob_send_message_key2));
		sodium_memzero(bob_send_message_key3, sizeof(bob_send_message_key3));
		sodium_memzero(bob_send_header_key2, sizeof(bob_send_header_key2));
		sodium_memzero(alice_receive_message_key1, sizeof(alice_receive_message_key1));
		sodium_memzero(alice_receive_message_key3, sizeof(alice_receive_message_key3));
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		return status;
	}

	assert(alice_state->purported_header_and_message_keys.length == 0);
	assert(alice_state->skipped_header_and_message_keys.length == 1);

	//get the second receive message key from the message and header keystore
	buffer_t *alice_receive_message_key2 = buffer_create(crypto_secretbox_KEYBYTES, crypto_secretbox_KEYBYTES);
	status = buffer_clone(alice_receive_message_key2, &(alice_state->skipped_header_and_message_keys.tail->message_key));
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to get Alice's second receive message key. (%i)\n", status);
		buffer_clear(alice_receive_message_key2);
		sodium_memzero(bob_send_message_key1, sizeof(bob_send_message_key1));
		sodium_memzero(bob_send_message_key2, sizeof(bob_send_message_key2));
		sodium_memzero(bob_send_message_key3, sizeof(bob_send_message_key3));
		sodium_memzero(bob_send_header_key2, sizeof(bob_send_header_key2));
		sodium_memzero(alice_receive_message_key1, sizeof(alice_receive_message_key1));
		sodium_memzero(alice_receive_message_key3, sizeof(alice_receive_message_key3));
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		return status;
	}
	printf("Alice Ratchet 2 receive message key 2:\n");
	print_hex(alice_receive_message_key2->content, alice_receive_message_key2->content_length, 30);
	putchar('\n');

	//get the second receive header key from the message and header keystore
	buffer_t *alice_receive_header_key2 = buffer_create(crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_KEYBYTES);
	status = buffer_clone(alice_receive_header_key2, &(alice_state->skipped_header_and_message_keys.tail->header_key));
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to get Alice's second receive header key. (%i)\n", status);
		buffer_clear(alice_receive_message_key2);
		buffer_clear(alice_receive_header_key2);
		sodium_memzero(bob_send_message_key1, sizeof(bob_send_message_key1));
		sodium_memzero(bob_send_message_key2, sizeof(bob_send_message_key2));
		sodium_memzero(bob_send_message_key3, sizeof(bob_send_message_key3));
		sodium_memzero(bob_send_header_key2, sizeof(bob_send_header_key2));
		sodium_memzero(alice_receive_message_key1, sizeof(alice_receive_message_key1));
		sodium_memzero(alice_receive_message_key3, sizeof(alice_receive_message_key3));
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		return status;
	}
	printf("Alice Ratchet 2 receive header key 2:\n");
	print_hex(alice_receive_header_key2->content, alice_receive_header_key2->content_length, 30);
	putchar('\n');

	//compare header keys
	if (sodium_memcmp(alice_receive_header_key2->content, bob_send_header_key2, crypto_secretbox_KEYBYTES) != 0) {
		fprintf(stderr, "ERROR: Bob's second send header key and Alice's receive header key aren't the same.\n");
		sodium_memzero(bob_send_message_key1, sizeof(bob_send_message_key1));
		sodium_memzero(bob_send_message_key2, sizeof(bob_send_message_key2));
		sodium_memzero(bob_send_message_key3, sizeof(bob_send_message_key3));
		sodium_memzero(alice_receive_message_key1, sizeof(alice_receive_message_key1));
		buffer_clear(alice_receive_message_key2);
		sodium_memzero(alice_receive_message_key3, sizeof(alice_receive_message_key3));
		buffer_clear(alice_receive_header_key2);
		sodium_memzero(bob_send_header_key2, sizeof(bob_send_header_key2));
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		return EXIT_FAILURE;
	}
	printf("Bob's second send header key and Alice's receive header keys match.\n");
	buffer_clear(alice_receive_header_key2);
	sodium_memzero(bob_send_header_key2, sizeof(bob_send_header_key2));

	//compare the keys
	if (sodium_memcmp(bob_send_message_key1, alice_receive_message_key1, sizeof(bob_send_message_key1)) != 0) {
		fprintf(stderr, "ERROR: Bob's first send key and Alice's first receive key aren't the same.\n");
		sodium_memzero(bob_send_message_key1, sizeof(bob_send_message_key1));
		sodium_memzero(bob_send_message_key2, sizeof(bob_send_message_key2));
		sodium_memzero(bob_send_message_key3, sizeof(bob_send_message_key3));
		sodium_memzero(alice_receive_message_key1, sizeof(alice_receive_message_key1));
		buffer_clear(alice_receive_message_key2);
		sodium_memzero(alice_receive_message_key3, sizeof(alice_receive_message_key3));
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		return EXIT_FAILURE;
	}
	sodium_memzero(bob_send_message_key1, sizeof(bob_send_message_key1));
	sodium_memzero(alice_receive_message_key1, sizeof(alice_receive_message_key1));
	printf("Bob's first send key and Alice's first receive key match.\n");

	//second key
	if (sodium_memcmp(bob_send_message_key2, alice_receive_message_key2->content, sizeof(bob_send_message_key2)) != 0) {
		fprintf(stderr, "ERROR: Bob's second send key and Alice's second receive key aren't the same.\n");
		sodium_memzero(bob_send_message_key2, sizeof(bob_send_message_key2));
		sodium_memzero(bob_send_message_key3, sizeof(bob_send_message_key3));
		buffer_clear(alice_receive_message_key2);
		sodium_memzero(alice_receive_message_key3, sizeof(alice_receive_message_key3));
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		return EXIT_FAILURE;
	}
	sodium_memzero(bob_send_message_key2, sizeof(bob_send_message_key2));
	buffer_clear(alice_receive_message_key2);
	printf("Bob's second send key and Alice's second receive key match.\n");

	//third key
	if (sodium_memcmp(bob_send_message_key3, alice_receive_message_key3, sizeof(bob_send_message_key3)) != 0) {
		fprintf(stderr, "ERROR: Bob's third send key and Alice's third receive key aren't the same.\n");
		sodium_memzero(bob_send_message_key3, sizeof(bob_send_message_key3));
		sodium_memzero(alice_receive_message_key3, sizeof(alice_receive_message_key3));
		ratchet_destroy(alice_state);
		ratchet_destroy(bob_state);
		return EXIT_FAILURE;
	}
	sodium_memzero(bob_send_message_key3, sizeof(bob_send_message_key3));
	sodium_memzero(alice_receive_message_key3, sizeof(alice_receive_message_key3));
	printf("Bob's third send key and Alice's third receive key match.\n\n");


	//destroy the ratchets again
	printf("Destroying Alice's ratchet ...\n");
	ratchet_destroy(alice_state);
	printf("Destroying Bob's ratchet ...\n");
	ratchet_destroy(bob_state);

	return EXIT_SUCCESS;
}
