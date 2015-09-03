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
#include <assert.h>

#include "hkdf.h"

/*
 * extract phase of hkdf
 */
int expand(
		buffer_t * const output_key,
		const size_t output_key_length,
		const buffer_t * const pseudo_random_key,
		const buffer_t * const info) {
	//expand phase of hkdf

	//test size of the buffers
	if ((output_key->buffer_length < output_key_length) || (pseudo_random_key->content_length != crypto_auth_BYTES)) {
		return -6;
	}

	//buffer to store T(x)|info|0x?? (HMAC input)
	buffer_t *round_buffer = buffer_create(crypto_auth_BYTES + info->content_length + 1, crypto_auth_BYTES + info->content_length + 1);

	//round_buffer = <empty>|info|0x01
	buffer_clone(round_buffer, info);
	round_buffer->content[round_buffer->content_length] = 0x01;
	round_buffer->content_length++;

	//T(1) = HMAC-HASH(PRK, <empty>|info|0x01)
	int status;
	status = crypto_auth(
			output_key->content, //will be T(0)|T(1) .... T(N) in the end (only T(0) for now)
			round_buffer->content,
			round_buffer->content_length, //length of round_buffer in first step
			pseudo_random_key->content);
	if (status != 0) {
		buffer_clear(round_buffer);
		return status;
	}
	output_key->content_length = output_key_length;

	//N (number of T(x) needed to fill the output_key_length
	unsigned int n = 1 + ((output_key_length - 1) / crypto_auth_BYTES); //N = ceil(L/HashLen)
	if (n > 0xff) { //n has to fit into one byte
		buffer_clear(round_buffer);
		return -10;
	}

	//T(2) ... T(N-1)
	unsigned int pos;
	for (pos = 1; pos < (n - 1); pos++) {
		//create round_buffer T(pos)|info|pos+1
		round_buffer->content_length = 0;
		buffer_copy(round_buffer, 0, output_key, (pos - 1) * crypto_auth_BYTES, crypto_auth_BYTES);
		buffer_concat(round_buffer, info);
		round_buffer->content[round_buffer->content_length] = (unsigned char) (pos + 1);
		round_buffer->content_length++;

		//T(pos+1) = HMAC-Hash(PRK, T(pos)|info|pos+1)
		status = crypto_auth(
				output_key->content + pos * crypto_auth_BYTES, // ...|T(pos+1)|...
				round_buffer->content,
				round_buffer->content_length, //length of round_buffer
				pseudo_random_key->content);
		if (status != 0) {
			buffer_clear(round_buffer);
			return status;
		}
	}

	//create round_buffer T(N-1)|info|N
	round_buffer->content_length = 0;
	buffer_copy(round_buffer, 0, output_key, (n - 2) * crypto_auth_BYTES, crypto_auth_BYTES);
	buffer_concat(round_buffer, info);
	round_buffer->content[round_buffer->content_length] = (unsigned char) n;
	round_buffer->content_length++;

	//T(N) = HMAC-Hash(PRK, T(N-1)|info|N)
	buffer_t *t_n_buffer = buffer_create(crypto_auth_BYTES, crypto_auth_BYTES);
	status = crypto_auth(
			t_n_buffer->content, //T(N)
			round_buffer->content,
			round_buffer->content_length, //length of round buffer
			pseudo_random_key->content);
	if (status != 0) {
		buffer_clear(t_n_buffer);
		buffer_clear(round_buffer);
		return status;
	}

	//copy as many bytes of T(N) as fit into output_key
	buffer_copy(
			output_key, (n - 1) * crypto_auth_BYTES,
			t_n_buffer,
			0,
			crypto_auth_BYTES - ((n * crypto_auth_BYTES) - output_key_length));

	buffer_clear(t_n_buffer);
	buffer_clear(round_buffer);
	return 0;
}

/*
 * This function implements HKDF (HMAC based key derivation function)
 * as defined in RFC 5869 using the primitives provided by libsodium.
 */
int hkdf(
	buffer_t * const output_key,
        const size_t output_key_length, //needs to be less than 255 * crypto_auth_KEYBYTES!!!
	const buffer_t * const salt, //the salt needs to be crypto_auth_KEYBYTES long
	const buffer_t * const input_key,
	const buffer_t * const info) {
	//ensure that the length-assumption is correct
	assert(crypto_auth_KEYBYTES == crypto_auth_BYTES);

	//make sure output_key_length doesn't exceed 255 * crypto_auth_KEYBYTES
	if (output_key_length > 255 * crypto_auth_KEYBYTES) {
		return -10;
	}

	//check the buffer lengths
	if ((output_key->buffer_length < output_key_length) || (salt->content_length != crypto_auth_KEYBYTES)) {
		return -6;
	}

	//extract phase of hkdf
	buffer_t * const pseudo_random_key = buffer_create(crypto_auth_BYTES, crypto_auth_BYTES);
	int status;
	//generate pseudo random key by calculating
	//HMAC from input_key using salt as key
	//PRK = HMAC-Hash(salt, IKM)
	status = crypto_auth(pseudo_random_key->content, input_key->content, input_key->content_length, salt->content);
	if (status != 0) {
		buffer_clear(pseudo_random_key);
		return status;
	}

	//expand phase of hkdf
	output_key->content_length = output_key_length;
	status = expand(output_key, output_key->content_length, pseudo_random_key, info);
	buffer_clear(pseudo_random_key);
	if (status != 0) {
		return status;
	}

	return 0;
}
