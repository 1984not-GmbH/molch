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

#include "hkdf.h"

/*
 * extract phase of hkdf
 */
int expand(
		unsigned char * const output_key,
		const size_t output_key_length,
		const unsigned char * const pseudo_random_key,
		const unsigned char * const info,
		const size_t info_length) {
	//expand phase of hkdf

	//buffer to store T(x)|info|0x?? (HMAC input)
	unsigned char* const round_buffer = malloc(crypto_auth_BYTES + info_length + 1);
	if (round_buffer == NULL) {
		return -10;
	}

	//round_buffer = <empty>|info|0x01
	memcpy(round_buffer, info, info_length);
	round_buffer[info_length] = 0x01;

	//T(1) = HMAC-HASH(PRK, <empty>|info|0x01)
	int status;
	status = crypto_auth(
			output_key, //will be T(0)|T(1) .... T(N) in the end (only T(0) for now)
			round_buffer,
			info_length + 1, //length of round_buffer
			pseudo_random_key);
	if (status != 0) {
		sodium_memzero(round_buffer, crypto_auth_BYTES + info_length + 1);
		free(round_buffer);
		return status;
	}

	//N (number of T(x) needed to fill the output_key_length
	unsigned int n = 1 + ((output_key_length - 1) / crypto_auth_BYTES); //N = ceil(L/HashLen)

	//T(2) ... T(N-1)
	unsigned int pos;
	for (pos = 1; pos < (n - 1); pos++) {
		//create round_buffer T(pos)|info|pos+1
		memcpy(round_buffer, output_key + (pos - 1) * crypto_auth_BYTES, crypto_auth_BYTES);
		memcpy(round_buffer + crypto_auth_BYTES, info, info_length);
		round_buffer[crypto_auth_BYTES + info_length] = (unsigned char) (pos + 1);

		//T(pos+1) = HMAC-Hash(PRK, T(pos)|info|pos+1)
		status = crypto_auth(
				output_key + pos * crypto_auth_BYTES, // ...|T(pos+1)|...
				round_buffer,
				crypto_auth_BYTES + info_length + 1, //length of round_buffer
				pseudo_random_key);
		if (status != 0) {
			sodium_memzero(round_buffer, crypto_auth_BYTES + info_length + 1);
			free(round_buffer);
			return status;
		}
	}

	//create round_buffer T(N-1)|info|N
	memcpy(round_buffer, output_key + (n - 2) * crypto_auth_BYTES, crypto_auth_BYTES);
	memcpy(round_buffer + crypto_auth_BYTES, info, info_length);
	round_buffer[crypto_auth_BYTES + info_length] = (unsigned char) n;

	//T(N) = HMAC-Hash(PRK, T(N-1)|info|N)
	unsigned char t_n_buffer[crypto_auth_BYTES];
	status = crypto_auth(
			t_n_buffer, //T(N)
			round_buffer,
			crypto_auth_BYTES + info_length + 1, //length of round buffer
			pseudo_random_key);
	if (status != 0) {
		sodium_memzero(t_n_buffer, crypto_auth_BYTES);
		sodium_memzero(round_buffer, crypto_auth_BYTES + info_length + 1);
		return status;
	}

	//copy as many bytes of T(N) as fit into output_key
	memcpy(
			output_key + (n - 1) * crypto_auth_BYTES,
			t_n_buffer,
			crypto_auth_BYTES - ((n * crypto_auth_BYTES) - output_key_length));

	sodium_memzero(t_n_buffer, crypto_auth_BYTES);
	sodium_memzero(round_buffer, crypto_auth_BYTES + info_length + 1);
	free(round_buffer);
	return 0;
}

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
        const size_t info_length) {
	//ensure that the length-assumption is correct
	if (! (crypto_auth_KEYBYTES <= crypto_auth_BYTES)) {
		return -10;
	}

	//extract phase of hkdf
	unsigned char pseudo_random_key[crypto_auth_BYTES];
	int status;
	//generate pseudo random key by calculating
	//HMAC from input_key using salt as key
	//PRK = HMAC-Hash(salt, IKM)
	status = crypto_auth(pseudo_random_key, input_key, input_key_length, salt);
	if (status != 0) {
		sodium_memzero(pseudo_random_key, crypto_auth_BYTES);
		return status;
	}

	//expand phase of hkdf
	status = expand(output_key, output_key_length, pseudo_random_key, info, info_length);
	sodium_memzero(pseudo_random_key, crypto_auth_BYTES);
	if (status != 0) {
		return status;
	}

	return 0;
}
