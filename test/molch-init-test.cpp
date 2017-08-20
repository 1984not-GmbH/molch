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

#include <cstdio>
#include <cstdlib>
#include <sodium.h>
#include <cstring>
#include <exception>
#include <iostream>
#include <string>

#include "utils.hpp"
#include "../lib/molch.h"
#include "../lib/constants.h"
#include "../lib/destroyers.hpp"
#include "../lib/molch-exception.hpp"
#include "../lib/malloc.hpp"

using namespace Molch;

int main(int argc, char *args[]) noexcept {
	try {
		bool recreate = false;
		if (argc == 2) {
			if (strcmp(args[1], "--recreate") == 0) {
				recreate = true;
			}
		}

		if (sodium_init() != 0) {
			throw Molch::Exception(INIT_ERROR, "Failed to initialize libsodium.");
		}

		unsigned char backup_key[BACKUP_KEY_SIZE];
		if (!recreate) {
			//load the backup from a file
			auto backup_file = read_file("test-data/molch-init.backup");

			//load the backup key from a file
			auto backup_key_file = read_file("test-data/molch-init-backup.key");
			if (backup_key_file.size != BACKUP_KEY_SIZE) {
				throw Molch::Exception(INCORRECT_BUFFER_SIZE, "Backup key from file has an incorrect length.");
			}

			//try to import the backup
			{
				return_status status = molch_import(
						backup_key,
						BACKUP_KEY_SIZE,
						backup_file.content,
						backup_file.size,
						backup_key_file.content,
						backup_key_file.size);
				on_error {
					throw Molch::Exception(status);
				}
			}

			//destroy again
			molch_destroy_all_users();
		}

		//create a new user
		std::unique_ptr<unsigned char,MallocDeleter<unsigned char>> backup;
		std::unique_ptr<unsigned char,MallocDeleter<unsigned char>> prekey_list;
		Buffer user_id(PUBLIC_MASTER_KEY_SIZE, PUBLIC_MASTER_KEY_SIZE);
		size_t backup_length;
		size_t prekey_list_length;
		{
			unsigned char *backup_ptr = nullptr;
			unsigned char *prekey_list_ptr = nullptr;
			return_status status = molch_create_user(
					user_id.content,
					user_id.size,
					&prekey_list_ptr,
					&prekey_list_length,
					backup_key,
					BACKUP_KEY_SIZE,
					&backup_ptr,
					&backup_length,
					reinterpret_cast<const unsigned char*>("random"),
					sizeof("random"));
			on_error {
				throw Molch::Exception(status);
			}
			backup.reset(backup_ptr);
			prekey_list.reset(prekey_list_ptr);
		}
		if (backup == nullptr) {
			throw Molch::Exception(EXPORT_ERROR, "Failed to export backup.");
		}

		//print the backup to a file
		Buffer backup_buffer(backup.get(), backup_length);
		Buffer backup_key_buffer(backup_key, BACKUP_KEY_SIZE);
		print_to_file(backup_buffer, "molch-init.backup");
		print_to_file(backup_key_buffer, "molch-init-backup.key");
	} catch (const Molch::Exception& exception) {
		exception.print(std::cerr) << std::endl;
		return EXIT_FAILURE;
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
