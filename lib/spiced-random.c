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

#include "spiced-random.h"
#include "hkdf.h"

/*
 * Generate a random number by combining the OSs random number
 * generator with an external source of randomness (like some kind of
 * user input).
 *
 * WARNING: Don't feed this with random numbers from the OSs random
 * source because it might annihilate the randomness.
 */
int spiced_random(
		buffer_t * const random_output,
		const buffer_t * const random_spice,
		const size_t output_length) {
	//content length defaults to zero in case of failure
	random_output->content_length = 0;

	//check buffer length
	if (random_output->buffer_length < output_length) {
		return -6;
	}

	int status;
	//buffer that contains the random data from the OS
	buffer_t *os_random = buffer_create(output_length, output_length);
	status = buffer_fill_random(os_random, output_length);
	if (status != 0) {
		buffer_clear(os_random);
		return status;
	}

	//create uniformly distributed random numbers from random input
	//using hkdf
	buffer_t *spice = buffer_create(output_length, output_length);
	status = hkdf(
			spice,
			output_length,
			buffer_create_from_string("some random string as salt     "), //TODO something better?
			random_spice,
			buffer_create(0, 0));
	if (status != 0) {
		buffer_clear(spice);
		buffer_clear(os_random);
		return status;
	}

	//now combine the spice with the OS provided random data.
	status = buffer_xor(os_random, spice);
	buffer_clear(spice);
	if (status != 0) {
		buffer_clear(os_random);
		return status;
	}

	//copy the random data to the output
	status = buffer_clone(random_output, os_random);
	buffer_clear(os_random);
	if (status != 0) {
		return status;
	}

	return 0;
}
