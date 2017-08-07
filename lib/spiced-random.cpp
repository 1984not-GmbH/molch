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

#include <sodium.h>

#include "constants.h"
#include "spiced-random.h"
#include "return-status.h"
#include "molch-exception.h"

/*
 * Generate a random number by combining the OSs random number
 * generator with an external source of randomness (like some kind of
 * user input).
 *
 * WARNING: Don't feed this with random numbers from the OSs random
 * source because it might annihilate the randomness.
 */
void spiced_random(
		Buffer& random_output,
		const Buffer& low_entropy_spice,
		const size_t output_length) {
	//buffer to put the random data derived from the random spice into
	Buffer spice(output_length, output_length, &sodium_malloc, &sodium_free);
	exception_on_invalid_buffer(spice);
	//buffer that contains the random data from the OS
	Buffer os_random(output_length, output_length, &sodium_malloc, &sodium_free);
	exception_on_invalid_buffer(os_random);
	//buffer that contains a random salt
	Buffer salt(crypto_pwhash_SALTBYTES, 0);
	exception_on_invalid_buffer(salt);

	//check buffer length
	if (!random_output.fits(output_length)) {
		throw MolchException(INCORRECT_BUFFER_SIZE, "Output buffers is too short.");
	}

	if (os_random.fillRandom(output_length) != 0) {
		throw MolchException(GENERIC_ERROR, "Failed to fill buffer with random data.");
	}

	if (salt.fillRandom(crypto_pwhash_SALTBYTES) != 0) {
		throw MolchException(GENERIC_ERROR, "Failed to fill salt with random data.");
	}

	//derive random data from the random spice
	int status_int = crypto_pwhash(
			spice.content,
			spice.content_length,
			reinterpret_cast<const char*>(low_entropy_spice.content),
			low_entropy_spice.content_length,
			salt.content,
			crypto_pwhash_OPSLIMIT_INTERACTIVE,
			crypto_pwhash_MEMLIMIT_INTERACTIVE,
			crypto_pwhash_ALG_DEFAULT);
	if (status_int != 0) {
		throw MolchException(GENERIC_ERROR, "Failed to derive random data from spice.");
	}

	//now combine the spice with the OS provided random data.
	if (os_random.xorWith(&spice) != 0) {
		throw MolchException(GENERIC_ERROR, "Failed to xor os random data and random data derived from spice.");
	}

	//copy the random data to the output
	if (random_output.cloneFrom(&os_random) != 0) {
		throw MolchException(BUFFER_ERROR, "Failed to copy random data.");
	}
}
