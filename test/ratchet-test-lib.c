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

#include "utils.h"
#include "ratchet-test-lib.h"

/*
 * Explanation: "!!" makes sure that the value is
 * actually 0 or 1 even if x was another nonzero value.
 *
 * Otherwise this should be self explanatory. This is
 * either the null terminated string "false" if x is 0 or
 * "true" (address + 6) if x isn't zero.
 *
 * The array indexing is due to a warning on Mac OS X that
 * complains about adding an integer to a string.
 */
#define bool_to_string(x) (&"false\0true"[6*!!(x)])

/*
 * Print all the keys in a ratchet for debugging purporses.
 */
void print_ratchet(ratchet_state *ratchet) {
	printf("------RATCHET_STATE------\n");

	if (ratchet->am_i_alice) {
		printf("Is Alice!\n");
	} else {
		printf("Isn't Alice!\n");
	}

	//root keys
	printf("Root keys:\n");
	printf("root key:\n");
	print_hex(ratchet->root_key);

	printf("purported root key:\n");
	print_hex(ratchet->purported_root_key);
	putchar('\n');

	//header keys
	printf("Header keys:\n");
	printf("send header key:\n");
	print_hex(ratchet->send_header_key);

	printf("receive header key:\n");
	print_hex(ratchet->receive_header_key);

	printf("next send header key:\n");
	print_hex(ratchet->next_send_header_key);

	printf("next receive header key:\n");
	print_hex(ratchet->next_receive_header_key);

	printf("purported receive header key:\n");
	print_hex(ratchet->purported_receive_header_key);

	printf("purported next receive header key:\n");
	print_hex(ratchet->purported_next_receive_header_key);
	putchar('\n');

	//chain keys
	printf("Chain keys:\n");
	printf("send chain key:\n");
	print_hex(ratchet->send_chain_key);

	printf("receive chain key:\n");
	print_hex(ratchet->receive_chain_key);

	printf("purported receive chain key:\n");
	print_hex(ratchet->purported_receive_chain_key);
	putchar('\n');

	//identity keys
	printf("Identity key:\n");
	printf("our public identity:\n");
	print_hex(ratchet->our_public_identity);

	printf("their public identity:\n");
	print_hex(ratchet->their_public_identity);
	putchar('\n');

	//ephemeral keys
	printf("Ephemeral keys:\n");
	printf("our private ephemeral:\n");
	print_hex(ratchet->our_private_ephemeral);

	printf("our public ephemeral:\n");
	print_hex(ratchet->our_public_ephemeral);

	printf("their public ephemeral:\n");
	print_hex(ratchet->their_public_ephemeral);

	printf("their purported public ephemeral:\n");
	print_hex(ratchet->their_purported_public_ephemeral);
	putchar('\n');

	//message numbers
	printf("Message numbers:\n");
	printf("send message number: %u\n", ratchet->send_message_number);
	printf("receive message number: %u\n", ratchet->receive_message_number);
	printf("purported message number: %u\n", ratchet->purported_message_number);
	printf("previous message number: %u\n", ratchet->previous_message_number);
	printf("purported previous message number: %u\n", ratchet->purported_previous_message_number);
	putchar('\n');

	printf("ratchet flag: %s\n", bool_to_string(ratchet->ratchet_flag));
	printf("received valid: %s\n", bool_to_string(ratchet->received_valid));

	printf("----------------------\n");
}
