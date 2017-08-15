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
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef LIB_PROTOBUF_DELETERS_H
#define LIB_PROTOBUF_DELETERS_H

#include "zeroed_malloc.hpp"

extern "C" {
	#include <backup.pb-c.h>
	#include <conversation.pb-c.h>
	#include <encrypted_backup.pb-c.h>
	#include <header.pb-c.h>
	#include <key.pb-c.h>
	#include <key_bundle.pb-c.h>
	#include <packet.pb-c.h>
	#include <packet_header.pb-c.h>
	#include <prekey.pb-c.h>
	#include <user.pb-c.h>
}

class BackupDeleter {
	public:
		void operator ()(Backup* backup);
};

class ConversationDeleter {
	public:
		void operator ()(Conversation* conversation);
};

class EncryptedBackupDeleter {
	public:
		void operator ()(EncryptedBackup* backup);
};

class HeaderDeleter {
	public:
		void operator ()(Header* header);
};

class KeyDeleter {
public:
	void operator ()(Key *key);
};

class KeyBundleDeleter {
	public:
		void operator ()(KeyBundle *key_bundle);
};

class PacketDeleter {
	public:
		void operator ()(Packet *packet);
};

class PacketHeaderDeleter {
	public:
		void operator ()(PacketHeader *packet_header);
};

class PrekeyDeleter {
public:
	void operator ()(Prekey *prekey);
};

class UserDeleter {
	public:
		void operator ()(User *user);
};

#endif /* LIB_PROTOBUF_DELETERS_H */
