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

%module molch

%{
#include <lib/molch.h>
#include <lib/constants.h>
#include <stdlib.h>
#include <string.h>
%}

%include <lib/constants.h>


// tell SWIG to treat size_t as an integer
typedef unsigned int size_t;
typedef unsigned int uint32_t;

%include <cpointer.i>
%pointer_class(size_t, size_t);
%pointer_cast(unsigned char**, void*, ucstring_to_void);

%include <carrays.i>
%array_class(unsigned char, ucstring_array);
%inline %{
	unsigned char **create_ucstring_pointer() {
		return malloc(sizeof(unsigned char*));
	}

	unsigned char *dereference_ucstring_pointer(unsigned char ** pointer) {
		return *pointer;
	}

	void ucstring_copy(unsigned char* destination, unsigned char* source, size_t length) {
		memcpy(destination, source, length);
	}

	status_type get_status(return_status *status) {
		return status->status;
	}
%}

typedef enum status_type {
	SUCCESS = 0,
	GENERIC_ERROR,
	INVALID_INPUT,
	INVALID_VALUE,
	INCORRECT_BUFFER_SIZE,
	BUFFER_ERROR,
	INCORRECT_DATA,
	INIT_ERROR,
	CREATION_ERROR,
	ADDITION_ERROR,
	ALLOCATION_FAILED,
	NOT_FOUND,
	VERIFICATION_FAILED,
	EXPORT_ERROR,
	IMPORT_ERROR,
	KEYGENERATION_FAILED,
	KEYDERIVATION_FAILED,
	SEND_ERROR,
	RECEIVE_ERROR,
	DATA_FETCH_ERROR,
	DATA_SET_ERROR,
	ENCRYPT_ERROR,
	DECRYPT_ERROR,
	CONVERSION_ERROR,
	SIGN_ERROR, VERIFY_ERROR,
	REMOVE_ERROR,
	SHOULDNT_HAPPEN,
	INVALID_STATE,
	OUTDATED
} status_type;

extern void free(void *);
extern void sodium_free(void *);

extern return_status molch_create_user(
		unsigned char *const public_master_key,
		const size_t public_master_key_length,
		unsigned char **const prekey_list,
		size_t *const prekey_list_length,
		unsigned char * backup_key,
		const size_t backup_key_length,
		unsigned char **const backup,
		size_t *const backup_length,
		const unsigned char *const random_data,
		const size_t random_data_length
	);

extern return_status molch_destroy_user(
		const unsigned char *const public_master_key,
		const size_t public_master_key_length,
		unsigned char **const backup,
		size_t *const backup_length
);

extern size_t molch_user_count();

extern return_status molch_list_users(
	unsigned char **const user_list,
	size_t * const user_list_length,
	size_t * count);

extern void molch_destroy_all_users();

typedef enum molch_message_type { PREKEY_MESSAGE, NORMAL_MESSAGE, INVALID } molch_message_type;

extern molch_message_type molch_get_message_type(
		const unsigned char * const packet,
		const size_t packet_length);

extern return_status molch_start_send_conversation(
		unsigned char * const conversation_id,
		const size_t conversation_id_length,
		unsigned char ** const packet,
		size_t *packet_length,
		const unsigned char * const sender_public_master_key,
		const size_t sender_public_master_key_length,
		const unsigned char * const receiver_public_master_key,
		const size_t receiver_public_master_key_length,
		const unsigned char * const prekey_list,
		const size_t prekey_list_length,
		const unsigned char * const message,
		const size_t message_length,
		unsigned char ** const backup,
		size_t * const backup_length
		);

extern return_status molch_start_receive_conversation(
		unsigned char * const conversation_id,
		const size_t conversation_id_length,
		unsigned char ** const message,
		size_t * const message_length,
		unsigned char ** const prekey_list,
		size_t * const prekey_list_length,
		const unsigned char * const receiver_public_master_key,
		const size_t receiver_public_master_key_length,
		const unsigned char * const sender_public_master_key,
		const size_t sender_public_master_key_length,
		const unsigned char * const packet,
		const size_t packet_length,
		unsigned char ** const backup,
		size_t * const backup_length
		);

extern return_status molch_encrypt_message(
		unsigned char ** const packet,
		size_t *packet_length,
		const unsigned char * const conversation_id,
		const size_t conversation_id_length,
		const unsigned char * const message,
		const size_t message_length,
		unsigned char ** const backup,
		size_t * const backup_length
		);

extern return_status molch_decrypt_message(
		unsigned char ** const message,
		size_t *message_length,
		uint32_t * const receive_message_number,
		uint32_t * const previous_receive_message_number,
		const unsigned char * const conversation_id,
		const size_t conversation_id_length,
		const unsigned char * const packet,
		const size_t packet_length,
		unsigned char ** const backup,
		size_t * const backup_length
		);

extern return_status molch_end_conversation(
		const unsigned char * const conversation_id,
		const size_t conversation_id_length,
		unsigned char ** const backup,
		size_t * const backup_length
		);

extern return_status molch_list_conversations(
		unsigned char ** const conversation_list,
		size_t * const conversation_list_length,
		size_t * const number,
		const unsigned char * const user_public_master_key,
		const size_t user_public_master_key_length);

extern char *molch_print_status(size_t * const output_length, return_status status);

extern const char *molch_print_status_type(status_type type);

extern void molch_destroy_return_status(return_status * const status);

extern return_status molch_conversation_export(
		unsigned char ** const backup,
		size_t * const backup_length,
		const unsigned char * const conversation_id,
		const size_t conversation_id_length);

extern return_status molch_export(unsigned char ** const backup, size_t *backup_length);

extern return_status molch_conversation_import(
		unsigned char * new_backup_key,
		const size_t new_backup_key_length,
		const unsigned char * const backup,
		const size_t backup_length,
		const unsigned char * backup_key,
		const size_t backup_key);

return_status molch_import(
		unsigned char * const new_backup_key,
		const size_t new_backup_key_length,
		unsigned char * const backup,
		const size_t backup_length,
		const unsigned char * const backup_key,
		const size_t backup_key_length);

extern return_status molch_get_prekey_list(
		unsigned char ** const prekey_list,
		size_t * const prekey_list_length,
		unsigned char * const public_master_key,
		const size_t public_master_key_length);

extern return_status molch_update_backup_key(unsigned char * const new_key, const size_t new_key_length);
