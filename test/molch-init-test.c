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
#include <sodium.h>

#include "utils.h"
#include "tracing.h"
#include "../lib/molch.h"
#include "../lib/constants.h"

int main(void) {
	/* don't initialize libsodium here */
	buffer_t *user_id = buffer_create_on_heap(PUBLIC_MASTER_KEY_SIZE, PUBLIC_MASTER_KEY_SIZE);
	buffer_t *json_backup = NULL; //json backup to import from
	unsigned char *json = NULL;
	unsigned char *prekey_list = NULL;

	return_status status = return_status_init();

	//load the json backup from a file
	read_file(&json_backup, "test-data/molch-init.json");
	if (json_backup == NULL) {
		throw(DATA_FETCH_ERROR, "Failed to read JSON backup from a file.");
	}

	//try to import the backup
	status = molch_json_import(json_backup->content, json_backup->content_length);
	throw_on_error(IMPORT_ERROR, "Failed to import backup from JSON.");

	//destroy again
	molch_destroy_all_users();

	//create a new user
	size_t json_length;
	size_t prekey_list_length;
	status = molch_create_user(
			user_id->content,
			&prekey_list,
			&prekey_list_length,
			(unsigned char*)"random",
			sizeof("random"),
			&json,
			&json_length);
	throw_on_error(CREATION_ERROR, "Failed to create user.");
	if (json == NULL) {
		throw(EXPORT_ERROR, "Failed to export JSON.");
	}

	//print the json to a file
	buffer_create_with_existing_array(json_buffer, json, json_length);
	print_to_file(json_buffer, "molch-init.json");

cleanup:
	buffer_destroy_from_heap(user_id);
	if (json != NULL) {
		sodium_free(json);
	}
	if (prekey_list != NULL) {
		free(prekey_list);
	}
	if (json_backup != NULL) {
		buffer_destroy_from_heap(json_backup);
	}

	on_error(
		print_errors(&status);
	);
	return_status_destroy_errors(&status);

	return status.status;
}
