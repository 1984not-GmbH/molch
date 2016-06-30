/* Molch, an implementation of the axolotl ratchet based on libsodium
 *  Copyright (C) 2015-2016 1984not Security GmbH
 *  Author: Max Bruckner (FSMaxB)
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

//This header defines all the constants that are globally available in the library.
#include <sodium.h>

#ifndef LIB_CONSTANTS_H
#define LIB_CONSTANTS_H

#define CONVERSATION_ID_SIZE 32U //length of a conversation id in bytes
#define PREKEY_AMOUNT 100U //number of prekeys that are used

#define DIFFIE_HELLMAN_SIZE crypto_generichash_BYTES

#define SIGNATURE_SIZE crypto_sign_BYTES

//key sizes
#define CHAIN_KEY_SIZE crypto_secretbox_KEYBYTES
#define MESSAGE_KEY_SIZE crypto_secretbox_KEYBYTES
#define HEADER_KEY_SIZE crypto_aead_chacha20poly1305_KEYBYTES
#define ROOT_KEY_SIZE crypto_secretbox_KEYBYTES
#define PRIVATE_KEY_SIZE crypto_box_SECRETKEYBYTES
#define PUBLIC_KEY_SIZE crypto_box_PUBLICKEYBYTES
#define PUBLIC_MASTER_KEY_SIZE crypto_sign_PUBLICKEYBYTES
#define PRIVATE_MASTER_KEY_SIZE crypto_sign_SECRETKEYBYTES
#define BACKUP_KEY_SIZE crypto_secretbox_KEYBYTES

//nonce sizes
#define MESSAGE_NONCE_SIZE crypto_secretbox_NONCEBYTES
#define HEADER_NONCE_SIZE crypto_aead_chacha20poly1305_NPUBBYTES
#define BACKUP_NONCE_SIZE crypto_secretbox_NONCEBYTES
#endif
