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

#include "protobuf-deleters.hpp"

namespace Molch {
	void BackupDeleter::operator ()(Backup* backup) {
				backup__free_unpacked(backup, &protobuf_c_allocators);
	}

	void ConversationDeleter::operator ()(Conversation* conversation) {
		conversation__free_unpacked(conversation, &protobuf_c_allocators);
	}

	void EncryptedBackupDeleter::operator ()(EncryptedBackup* backup) {
		encrypted_backup__free_unpacked(backup, &protobuf_c_allocators);
	}

	void HeaderDeleter::operator ()(Header* header) {
		header__free_unpacked(header, &protobuf_c_allocators);
	}

	void KeyDeleter::operator ()(Key *key) {
		key__free_unpacked(key, &protobuf_c_allocators);
	}

	void KeyBundleDeleter::operator ()(KeyBundle *key_bundle) {
		key_bundle__free_unpacked(key_bundle, &protobuf_c_allocators);
	}

	void PacketDeleter::operator ()(Packet *packet) {
		packet__free_unpacked(packet, &protobuf_c_allocators);
	}

	void PacketHeaderDeleter::operator ()(PacketHeader *packet_header) {
		packet_header__free_unpacked(packet_header, &protobuf_c_allocators);
	}

	void PrekeyDeleter::operator ()(Prekey *prekey) {
		prekey__free_unpacked(prekey, &protobuf_c_allocators);
	}

	void UserDeleter::operator ()(User *user) {
		user__free_unpacked(user, &protobuf_c_allocators);
	}
}
