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

typedef Molch__Protobuf__Backup ProtobufCBackup;
typedef Molch__Protobuf__Conversation ProtobufCConversation;
typedef Molch__Protobuf__EncryptedBackup ProtobufCEncryptedBackup;
typedef Molch__Protobuf__Header ProtobufCHeader;
typedef Molch__Protobuf__Key ProtobufCKey;
typedef Molch__Protobuf__KeyBundle ProtobufCKeyBundle;
typedef Molch__Protobuf__Packet ProtobufCPacket;
typedef Molch__Protobuf__PacketHeader ProtobufCPacketHeader;
typedef Molch__Protobuf__Prekey ProtobufCPrekey;
typedef Molch__Protobuf__User ProtobufCUser;

namespace Molch {
	class EncryptedBackupDeleter {
		public:
			void operator ()(ProtobufCEncryptedBackup* backup);
	};

	class HeaderDeleter {
		public:
			void operator ()(ProtobufCHeader* header);
	};

	class PacketDeleter {
		public:
			void operator ()(ProtobufCPacket *packet);
	};

	void *protobuf_c_new(void *allocator_data, size_t size);
	void protobuf_c_delete(void *allocator_data, void *pointer);

	extern ProtobufCAllocator protobuf_c_allocator;
}

#endif /* LIB_PROTOBUF_DELETERS_H */
