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
		mempool_t *pool = buffer_create_on_heap(pool_size, pool_size);\
		if (pool != NULL) {\
			mcJSON *json = export_function(object, pool);\
			if (json != NULL) {\
				buffer_name = mcJSON_PrintBuffered(json, printbuffer_size, format);\
			}\
			buffer_destroy_from_heap(pool);\
		}\
	}

#endif
