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
#include "../include/molch.h"

using namespace Molch;

int main(int argc, char *args[]) noexcept {
	try {
		auto recreate{false};
		if (argc == 2) {
			if (strcmp(args[1], "--recreate") == 0) {
				recreate = true;
			}
		}

		Molch::sodium_init();

		unsigned char backup_key[BACKUP_KEY_SIZE];
		if (!recreate) {
			//load the backup from a file
			auto backup_file{read_file("test-data/molch-init.backup")};

			//load the backup key from a file
			auto backup_key_file{read_file("test-data/molch-init-backup.key")};
			if (!backup_key_file.contains(BACKUP_KEY_SIZE)) {
				throw Molch::Exception{status_type::INCORRECT_BUFFER_SIZE, "Backup key from file has an incorrect length."};
			}

			//try to import the backup
			{
				auto status{molch_import(
						backup_key,
						BACKUP_KEY_SIZE,
						byte_to_uchar(backup_file.data()),
						backup_file.size(),
						byte_to_uchar(backup_key_file.data()),
						backup_key_file.size())};
				on_error {
					throw Molch::Exception{status};
				}
			}

			//destroy again
			molch_destroy_all_users();
		}

		//create a new user
		std::unique_ptr<unsigned char,MallocDeleter<unsigned char>> backup;
		std::unique_ptr<unsigned char,MallocDeleter<unsigned char>> prekey_list;
		Buffer user_id{PUBLIC_MASTER_KEY_SIZE, PUBLIC_MASTER_KEY_SIZE};
		size_t backup_length;
		size_t prekey_list_length;
		{
			unsigned char *backup_ptr{nullptr};
			unsigned char *prekey_list_ptr{nullptr};
			auto status{molch_create_user(
					byte_to_uchar(user_id.data()),
					user_id.size(),
					&prekey_list_ptr,
					&prekey_list_length,
					backup_key,
					BACKUP_KEY_SIZE,
					&backup_ptr,
					&backup_length,
					reinterpret_cast<const unsigned char*>("random"),
					sizeof("random"))};
			on_error {
				throw Molch::Exception{status};
			}
			backup.reset(backup_ptr);
			prekey_list.reset(prekey_list_ptr);
		}
		if (backup == nullptr) {
			throw Molch::Exception{status_type::EXPORT_ERROR, "Failed to export backup."};
		}

		//print the backup to a file
		span<std::byte> backup_buffer{uchar_to_byte(backup.get()), backup_length};
		span<std::byte> backup_key_buffer{uchar_to_byte(backup_key), BACKUP_KEY_SIZE};
		print_to_file(backup_buffer, "molch-init.backup");
		print_to_file(backup_key_buffer, "molch-init-backup.key");
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
