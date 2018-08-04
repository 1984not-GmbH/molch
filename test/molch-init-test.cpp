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

#include "../include/molch.h"
#include "integration-utils.hpp"


int main(int argc, char *args[]) noexcept {
	try {
		auto recreate{false};
		if (argc == 2) {
			if (strcmp(args[1], "--recreate") == 0) {
				recreate = true;
			}
		}

		if (::sodium_init() != 0) {
			throw ::Exception("Failed to initialize libsodium.");
		}

		BackupKeyArray backup_key;
		if (!recreate) {
			//load the backup from a file
			auto backup_file{read_file("test-data/molch-init.backup")};

			//load the backup key from a file
			auto backup_key_file{read_file("test-data/molch-init-backup.key")};
			if (backup_key_file.size() not_eq backup_key.size()) {
				throw ::Exception("Backup key from file has an incorrect length.");
			}

			//try to import the backup
			{
				auto status{molch_import(
						backup_key.data(),
						backup_key.size(),
						backup_file.data(),
						backup_file.size(),
						backup_key_file.data(),
						backup_key_file.size())};
				if (status.status != status_type::SUCCESS) {
					throw ::Exception("Failed to import backup.");
				}
			}

			//destroy again
			molch_destroy_all_users();
		}

		//create a new user
		AutoFreeBuffer backup;
		AutoFreeBuffer prekey_list;
		PublicIdentity user_id;
		{
			auto status{molch_create_user(
					user_id.data(),
					user_id.size(),
					&prekey_list.pointer,
					&prekey_list.length,
					backup_key.data(),
					backup_key.size(),
					&backup.pointer,
					&backup.length,
					reinterpret_cast<const unsigned char*>("random"),
					sizeof("random"))};
			if (status.status != status_type::SUCCESS) {
				throw ::Exception("Failed to create user.");
			}
		}
		if (backup.pointer == nullptr) {
			throw ::Exception("Failed to export backup.");
		}

		//print the backup to a file
		write_to_file(backup, "molch-init.backup");
		write_to_file(backup_key, "molch-init-backup.key");
	} catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
