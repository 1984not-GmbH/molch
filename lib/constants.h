/*
 * Molch, an implementation of the axolotl ratchet based on libsodium
 *
 * ISC License
 *
 * Copyright (C) 2015-2016 1984not Security GmbH
 * Author: Max Bruckner (FSMaxB)
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

//!file This header defines all the constants that are globally available in the library.

#ifndef LIB_CONSTANTS_H
#define LIB_CONSTANTS_H

#include <sodium.h>

#define CONVERSATION_ID_SIZE 32U //length of a conversation id in bytes
#define PREKEY_AMOUNT 100U //number of prekeys that are used

#define DIFFIE_HELLMAN_SIZE crypto_generichash_BYTES

#define SIGNATURE_SIZE crypto_sign_BYTES

//key sizes
#define CHAIN_KEY_SIZE crypto_secretbox_KEYBYTES
#define MESSAGE_KEY_SIZE crypto_secretbox_KEYBYTES
#define HEADER_KEY_SIZE crypto_secretbox_KEYBYTES
#define ROOT_KEY_SIZE crypto_secretbox_KEYBYTES
#define PRIVATE_KEY_SIZE crypto_box_SECRETKEYBYTES
#define PUBLIC_KEY_SIZE crypto_box_PUBLICKEYBYTES
#define PUBLIC_MASTER_KEY_SIZE crypto_sign_PUBLICKEYBYTES
#define PRIVATE_MASTER_KEY_SIZE crypto_sign_SECRETKEYBYTES
#define BACKUP_KEY_SIZE crypto_secretbox_KEYBYTES

//nonce sizes
#define MESSAGE_NONCE_SIZE crypto_secretbox_NONCEBYTES
#define HEADER_NONCE_SIZE crypto_secretbox_NONCEBYTES
#define BACKUP_NONCE_SIZE crypto_secretbox_NONCEBYTES
#endif
