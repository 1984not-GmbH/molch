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

#include "protobuf-arena.hpp"

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
	#include <signed_prekey_list.pb-c.h>
	#include <prekey_list.pb-c.h>
	#include <public_prekey.pb-c.h>
}

namespace Molch {
#define ProtobufDefinition(camel_case_name, snake_case_name) \
	using ProtobufC##camel_case_name = Molch__Protobuf__##camel_case_name;\
	inline auto protobuf_init(ProtobufC##camel_case_name* protobuf_struct) {\
		molch__protobuf__##snake_case_name##__init(protobuf_struct);\
	} \
	inline auto protobuf_packed_size(ProtobufC##camel_case_name* protobuf_struct) -> size_t {\
		return molch__protobuf__##snake_case_name##__get_packed_size(protobuf_struct);\
	}

ProtobufDefinition(Backup, backup)
ProtobufDefinition(Conversation, conversation)
ProtobufDefinition(EncryptedBackup, encrypted_backup)
ProtobufDefinition(Header, header)
ProtobufDefinition(Key, key)
ProtobufDefinition(KeyBundle, key_bundle)
ProtobufDefinition(Packet, packet)
ProtobufDefinition(PacketHeader, packet_header)
ProtobufDefinition(Prekey, prekey)
ProtobufDefinition(User, user)
ProtobufDefinition(PublicPrekey, public_prekey)
ProtobufDefinition(PrekeyList, prekey_list)
ProtobufDefinition(SignedPrekeyList, signed_prekey_list)

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

	template <typename ProtobufType>
	inline auto protobuf_create(Arena& arena) -> ProtobufType* {
		auto allocated_type{arena.allocate<ProtobufType>(1)};
		protobuf_init(allocated_type);

		return allocated_type;
	}
}

#define outcome_protobuf_bytes_arena_export(arena, message, name, size) \
	(message)->name.data = (arena).allocate<unsigned char>(size);\
	OUTCOME_TRY(copyFromTo(name,{uchar_to_byte((message)->name.data), (size)}));\
	(message)->name.len = (size);

/*
 * Macro containing the steps to export a key 'name' of size 'size'
 * to a protobuf message 'message' on the arena allocator 'arena'.
 */
#define outcome_protobuf_optional_bytes_arena_export(arena, message, name, size) \
	outcome_protobuf_bytes_arena_export(arena, message, name, size)\
	(message)->has_##name = true;

/*
 * Macro containing the steps to export an optional value
 * to a protobuf message.
 */
#define protobuf_optional_export(message, name, value) \
	(message)->has_##name = true;\
	(message)->name = value;

#define outcome_protobuf_array_arena_export(arena, message, name, value) \
	OUTCOME_TRY(exported_##name, (value).exportProtobuf(arena));\
	(message)->name = exported_##name.data();\
	(message)->n_##name = exported_##name.size();

#endif /* LIB_PROTOBUF_DELETERS_H */
