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

#ifndef LIB_HKDF_H
#define LIB_HKDF_H
/*
 * This function implements HKDF (HMAC based key derivation function)
 * as defined in RFC 5869 using the primitives provided by libsodium.
 */
int hkdf(
        unsigned char * const output_key,
        const size_t output_key_length, //needs to be less than 255 * crypto_auth_KEYBYTES!!!
        const unsigned char * const salt, //the salt needs to be crypto_auth_KEYBYTES long
        const unsigned char * const input_key,
        const size_t input_key_length,
        const unsigned char * const info,
        const size_t info_length);
#endif
