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

#ifndef LIB_JSON_H
#define LIB_JSON_H

#include "../mcJSON/mcJSON.h"
#include "../buffer/buffer.h"

//macro to export an object to a JSON buffer
#define JSON_EXPORT(buffer_name, pool_size, printbuffer_size, format, object, export_function)\
	buffer_t * buffer_name = NULL;\
	{\
		mempool_t *__pool = buffer_create_on_heap(pool_size, pool_size);\
		if (__pool != NULL) {\
			mcJSON *__json = export_function(object, __pool);\
			if (__json != NULL) {\
				buffer_name = mcJSON_PrintBuffered(__json, printbuffer_size, format);\
			}\
			buffer_destroy_from_heap(__pool);\
		}\
	}

//macro to import an object from a JSON buffer
//NOTE: This only works on json_import functions that return the imported object
#define JSON_IMPORT(object_name, pool_size, json_string, import_function)\
	{\
		object_name = NULL;\
		mempool_t *__pool = buffer_create_on_heap(pool_size, pool_size);\
		if (__pool != NULL) {\
			mcJSON *__json = mcJSON_ParseWithBuffer(json_string, __pool);\
			if (__json != NULL) {\
				object_name = import_function(__json);\
			}\
			buffer_destroy_from_heap(__pool);\
		}\
	}

//macro to import an object from a json buffer by initialising an existing object
//NOTE: This only works on json_import functions that receive a pointer to an existing object
#define JSON_INITIALIZE(object_pointer, pool_size, json_string, import_function, status_value)\
	{\
		status_value = -1;\
		mempool_t *__pool = buffer_create_on_heap(pool_size, pool_size);\
		if (__pool != NULL) {\
			mcJSON *__json = mcJSON_ParseWithBuffer(json_string, __pool);\
			if (__json != NULL) {\
				status_value = import_function(__json, object_pointer);\
			}\
			buffer_destroy_from_heap(__pool);\
		}\
	}

#endif
