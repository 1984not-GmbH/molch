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

#include <sodium.h>
#include <assert.h>

#include "constants.h"
#include "spiced-random.h"
#include "return-status.h"

/*
 * Generate a random number by combining the OSs random number
 * generator with an external source of randomness (like some kind of
 * user input).
 *
 * WARNING: Don't feed this with random numbers from the OSs random
 * source because it might annihilate the randomness.
 */
return_status spiced_random(
		buffer_t * const random_output,
		const buffer_t * const random_spice,
		const size_t output_length) {
	return_status status = return_status_init();

	//buffer to put the random data derived from the random spice into
	buffer_t *spice = buffer_create_with_custom_allocator(output_length, output_length, sodium_malloc, sodium_free);
	//buffer that contains the random data from the OS
	buffer_t *os_random = buffer_create_with_custom_allocator(output_length, output_length, sodium_malloc, sodium_free);

	//check buffer length
	if (random_output->buffer_length < output_length) {
		throw(INCORRECT_BUFFER_SIZE, "Output buffers is too short.");
	}

	if (buffer_fill_random(os_random, output_length) != 0) {
		throw(GENERIC_ERROR, "Failed to fill buffer with random data.");
	}

	buffer_create_from_string(salt, " molch: an axolotl ratchet lib ");
	assert(salt->content_length == crypto_pwhash_scryptsalsa208sha256_SALTBYTES);

	//derive random data from the random spice
	int status_int = 0;
	status_int = crypto_pwhash_scryptsalsa208sha256(
			spice->content,
			spice->content_length,
			(const char*)random_spice->content,
			random_spice->content_length,
			salt->content,
			crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE,
			crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE);
	if (status_int != 0) {
		throw(GENERIC_ERROR, "Failed to derive random data from spice.");
	}

	//now combine the spice with the OS provided random data.
	if (buffer_xor(os_random, spice) != 0) {
		throw(GENERIC_ERROR, "Failed to xor os random data and random data derived from spice.");
	}

	//copy the random data to the output
	if (buffer_clone(random_output, os_random) != 0) {
		throw(BUFFER_ERROR, "Failed to copy random data.");
	}

cleanup:
	if (status.status != SUCCESS) {
		if (random_output != NULL) {
			buffer_clear(random_output);
			random_output->content_length = 0;
		}
	}
	buffer_destroy_with_custom_deallocator(spice, sodium_free);
	buffer_destroy_with_custom_deallocator(os_random, sodium_free);

	return status;
}
