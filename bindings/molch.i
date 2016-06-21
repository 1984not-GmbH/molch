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
	SIGN_ERROR,
	VERIFY_ERROR,
	REMOVE_ERROR,
	SHOULDNT_HAPPEN,
	INVALID_STATE,
	OUTDATED
} status_type;

extern void free(void *);
extern void sodium_free(void *);

extern return_status molch_create_user(
		unsigned char *const public_master_key,
		unsigned char **const prekey_list,
		size_t *const prekey_list_length,
		const unsigned char *const random_data,
		const size_t random_data_length,
		unsigned char **const json_export,
		size_t *const json_export_length
	);

extern return_status molch_destroy_user(
		const unsigned char *const public_signing_key,
		unsigned char **const json_export,
		size_t *const json_export_length
);

extern size_t molch_user_count();

extern return_status molch_user_list(unsigned char **const user_list, size_t *count);

extern void molch_destroy_all_users();

typedef enum molch_message_type { PREKEY_MESSAGE, NORMAL_MESSAGE, INVALID } molch_message_type;

extern molch_message_type molch_get_message_type(
		const unsigned char * const packet,
		const size_t packet_length);

extern return_status molch_create_send_conversation(
		unsigned char * const conversation_id,
		unsigned char ** const packet,
		size_t *packet_length,
		const unsigned char * const message,
		const size_t message_length,
		const unsigned char * const prekey_list,
		const size_t prekey_list_length,
		const unsigned char * const sender_public_signing_key,
		const unsigned char * const receiver_public_signing_key,
		unsigned char ** const json_export,
		size_t * const json_export_length
		);

extern return_status molch_create_receive_conversation(
		unsigned char * const conversation_id,
		unsigned char ** const message,
		size_t * const message_length,
		const unsigned char * const packet,
		const size_t packet_length,
		unsigned char ** const prekey_list,
		size_t * const prekey_list_length,
		const unsigned char * const sender_public_signing_key,
		const unsigned char * const receiver_public_signing_key,
		unsigned char ** const json_export,
		size_t * const json_export_length
		);

extern return_status molch_encrypt_message(
		unsigned char ** const packet,
		size_t *packet_length,
		const unsigned char * const message,
		const size_t message_length,
		const unsigned char * const conversation_id,
		unsigned char ** const json_export_conversation,
		size_t * const json_export_conversation_length
		);

extern return_status molch_decrypt_message(
		unsigned char ** const message,
		size_t *message_length,
		const unsigned char * const packet,
		const size_t packet_length,
		const unsigned char * const conversation_id,
		unsigned char ** const json_export_conversation,
		size_t * const json_export_conversation_length
		);

extern void molch_end_conversation(
		const unsigned char * const conversation_id,
		unsigned char ** const json_export,
		size_t * const json_export_length
		);

extern return_status molch_list_conversations(
		const unsigned char * const user_public_signing_key,
		unsigned char ** const conversation_list,
		size_t *number);

extern char *molch_print_status(return_status status, size_t * const output_length);

extern const char *molch_print_status_type(status_type type);

extern void molch_destroy_return_status(return_status * const status);

extern return_status molch_conversation_json_export(
		unsigned char ** const json,
		const unsigned char * const conversation_id,
		size_t * const length);

extern return_status molch_json_export(
		unsigned char ** const json,
		size_t *length);

extern return_status molch_conversation_json_import(const unsigned char * const json, const size_t length);

extern return_status molch_json_import(const unsigned char* const json, const size_t length);
