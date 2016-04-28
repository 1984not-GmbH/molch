/*  Molch, an implementation of the axolotl ratchet based on libsodium
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
