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
#include <stdio.h>
#include <stdlib.h>

#include "../lib/endianness.h"
#include "utils.h"
#include "tracing.h"

int main(void) {
	int status = 0;

	buffer_t *buffer64 = buffer_create_on_heap(8, 8);
	buffer_t *buffer32 = buffer_create_on_heap(4, 4);

	if (endianness_is_little_endian()) {
		printf("Current byte order: Little Endian!\n");
	} else {
		printf("Current_byte_oder: Big Endian!\n");
	}

	//uint32_t -> big endian
	uint32_t uint32 = 67305985ULL;
	status = endianness_uint32_to_big_endian(uint32, buffer32);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to convert uint32_t to big endian! (%i)\n", status);
		goto cleanup;
	}
	printf("uint32_t %llu to big endian:\n", (unsigned long long) uint32);
	print_hex(buffer32);

	if (buffer_compare_to_raw(buffer32, (unsigned char*)"\x04\x03\x02\x01", sizeof(uint32_t)) != 0) {
		fprintf(stderr, "ERROR: Big endian of uint32_t is incorrect!\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}

	//uint32_t <- big endian
	uint32_t uint32_from_big_endian;
	status = endianness_uint32_from_big_endian(&uint32_from_big_endian, buffer32);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to convert big endian to uint32_t! (%i)\n", status);
		goto cleanup;
	}
	if (uint32 != uint32_from_big_endian) {
		fprintf(stderr, "ERROR: uint32_t from big endian is incorrect!\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	printf("Successfully converted back!\n\n");

	//int32_t -> big endian
	int32_t int32 = -66052LL;
	status = endianness_int32_to_big_endian(int32, buffer32);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to convert int32_t to big endian! (%i)\n", status);
		goto cleanup;
	}
	printf("int32_t %lli to big endian:\n", (signed long long) int32);
	print_hex(buffer32);

	if (buffer_compare_to_raw(buffer32, (unsigned char*)"\xFF\xFE\xFD\xFC", sizeof(int32_t)) != 0) {
		fprintf(stderr, "ERROR: Big endian of int32_t is incorrect!\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}

	//int32_t <- big endian
	int32_t int32_from_big_endian;
	status = endianness_int32_from_big_endian(&int32_from_big_endian, buffer32);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to convert big endian to int32_t! (%i)\n", status);
		goto cleanup;
	}
	if (int32 != int32_from_big_endian) {
		fprintf(stderr, "ERROR: uint32_t from big endian is incorrect!\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	printf("Successfully converted back!\n\n");

	//uint64_t -> big endian
	uint64_t uint64 = 578437695752307201ULL;
	status = endianness_uint64_to_big_endian(uint64, buffer64);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to convert uint64_t to big endian! (%i)\n", status);
		goto cleanup;
	}
	printf("uint64_t %llu to big endian:\n", (unsigned long long) uint64);
	print_hex(buffer64);

	if (buffer_compare_to_raw(buffer64, (unsigned char*)"\x08\x07\x06\x05\x04\x03\x02\x01", sizeof(uint64_t)) != 0) {
		fprintf(stderr, "ERROR: Big endian of uint64_t is incorrect!\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}

	//uint64_t <- big endian
	uint64_t uint64_from_big_endian;
	status = endianness_uint64_from_big_endian(&uint64_from_big_endian, buffer64);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to convert big endian to uint64_t! (%i)\n", status);
		goto cleanup;
	}
	if (uint64 != uint64_from_big_endian) {
		fprintf(stderr, "ERROR: uint64_t from big endian is incorrect!\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	printf("Successfully converted back!\n\n");

	//int64_t -> big endian
	int64_t int64 = -283686952306184LL;
	status = endianness_int64_to_big_endian(int64, buffer64);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to convert int64_t to big endian! (%i)\n", status);
		goto cleanup;
	}
	printf("int64_t %lli to big endian:\n", (signed long long) int64);
	print_hex(buffer64);

	if (buffer_compare_to_raw(buffer64, (unsigned char*)"\xFF\xFE\xFD\xFC\xFB\xFA\xF9\xF8", sizeof(int64_t)) != 0) {
		fprintf(stderr, "ERROR: Big endian of int64_t is incorrect!\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}

	//int64_t <- big endian
	int64_t int64_from_big_endian;
	status = endianness_int64_from_big_endian(&int64_from_big_endian, buffer64);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to convert big endian to int64_t! (%i)\n", status);
		goto cleanup;
	}
	if (int64 != int64_from_big_endian) {
		fprintf(stderr, "ERROR: uint64_t from big endian is incorrect!\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	printf("Successfully converted back!\n\n");

	//time_t -> big endian
	time_t timestamp = time(NULL);
	status = endianness_time_to_big_endian(timestamp, buffer64);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to convert time_t to big endian! (%i)\n", status);
		goto cleanup;
	}
	printf("time_t %llu to big endian:\n", (unsigned long long) timestamp);
	print_hex(buffer64);

	//time_t <- big endian
	time_t time_from_big_endian;
	status = endianness_time_from_big_endian(&time_from_big_endian, buffer64);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to convert big endian to time_t! (%i)\n", status);
		goto cleanup;
	}
	if (timestamp != time_from_big_endian) {
		fprintf(stderr, "ERROR: time_t from big endian is incorrect!\n");
		status = EXIT_FAILURE;
		goto cleanup;
	}
	printf("Successfully converted back!\n\n");

cleanup:
	buffer_destroy_from_heap(buffer64);
	buffer_destroy_from_heap(buffer32);

	return status;
}
