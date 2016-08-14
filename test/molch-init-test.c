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
	buffer_t *backup_file = NULL; //backup to import from
	buffer_t *backup_key_file = NULL;

	unsigned char *backup = NULL;
	unsigned char *prekey_list = NULL;
	unsigned char *backup_key = malloc(BACKUP_KEY_SIZE);

	return_status status = return_status_init();

	if (sodium_init() != 0) {
		throw(INIT_ERROR, "Failed to initialize libsodium.");
	}

	//load the backup from a file
	read_file(&backup_file, "test-data/molch-init.backup");
	if (backup_file == NULL) {
		throw(DATA_FETCH_ERROR, "Failed to read backup from a file.");
	}

	//load the backup key from a file
	read_file(&backup_key_file, "test-data/molch-init-backup.key");
	if (backup_key_file == NULL) {
		throw(DATA_FETCH_ERROR, "Failed to read backup key from a file.");
	}
	if (backup_key_file->content_length != BACKUP_KEY_SIZE) {
		throw(INCORRECT_BUFFER_SIZE, "Backup key from file has an incorrect length.");
	}

	//try to import the backup
	status = molch_import(
			backup_key,
			BACKUP_KEY_SIZE,
			backup_file->content,
			backup_file->content_length,
			backup_key_file->content,
			backup_key_file->content_length);
	throw_on_error(IMPORT_ERROR, "Failed to import backup from backup.");

	//destroy again
	molch_destroy_all_users();

	//create a new user
	size_t backup_length;
	size_t prekey_list_length;
	status = molch_create_user(
			user_id->content,
			user_id->content_length,
			&prekey_list,
			&prekey_list_length,
			backup_key,
			BACKUP_KEY_SIZE,
			&backup,
			&backup_length,
			(unsigned char*)"random",
			sizeof("random"));
	throw_on_error(CREATION_ERROR, "Failed to create user.");
	if (backup == NULL) {
		throw(EXPORT_ERROR, "Failed to export backup.");
	}

	//print the backup to a file
	buffer_create_with_existing_array(backup_buffer, backup, backup_length);
	buffer_create_with_existing_array(backup_key_buffer, backup_key, BACKUP_KEY_SIZE);
	print_to_file(backup_buffer, "molch-init.backup");
	print_to_file(backup_key_buffer, "molch-init-backup.key");

cleanup:
	buffer_destroy_from_heap_and_null(user_id);
	if (backup != NULL) {
		free_and_null(backup);
	}
	if (prekey_list != NULL) {
		free_and_null(prekey_list);
	}
	if (backup_file != NULL) {
		buffer_destroy_from_heap_and_null(backup_file);
	}
	if (backup_key_file != NULL) {
		buffer_destroy_from_heap_and_null(backup_key_file);
	}

	free_and_null(backup_key);

	on_error(
		print_errors(&status);
	);
	return_status_destroy_errors(&status);

	return status.status;
}
