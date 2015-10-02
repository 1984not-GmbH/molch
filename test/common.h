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

#include "../lib/header-and-message-keystore.h"

#ifndef TEST_COMMON_H
#define TEST_COMMON_H
/*
 * Print a header and message keystore with all of it's entries.
 */
void print_header_and_message_keystore(header_and_message_keystore *keystore);

/*
 * Generates and prints a crypto_box keypair.
 */
int generate_and_print_keypair(
		buffer_t * const public_key, //crypto_box_PUBLICKEYBYTES
		buffer_t * const private_key, //crypto_box_SECRETKEYBYTES
		const buffer_t * name, //Name of the key owner (e.g. "Alice")
		const buffer_t * type); //type of the key (e.g. "ephemeral")
#endif
