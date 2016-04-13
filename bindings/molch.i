%module molch

%{
#include <lib/molch.h>
#include <lib/constants.h>
#include <malloc.h>
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
%}

extern void free(void *);
extern void sodium_free(void *);


extern int molch_create_user(
		unsigned char * const public_master_key,
		unsigned char ** const prekey_list,
		size_t * const prekey_list_length,
		const unsigned char * const random_data,
		const size_t random_data_length,
		unsigned char ** const json_export,
		size_t * const json_export_length);

extern int molch_destroy_user(
		const unsigned char * const public_signing_key,
		unsigned char ** const json_export,
		size_t * const json_export_length);

extern size_t molch_user_count();

extern unsigned char* molch_user_list(size_t *count);

extern void molch_destroy_all_users();

typedef enum molch_message_type { PREKEY_MESSAGE, NORMAL_MESSAGE, INVALID } molch_message_type;

extern molch_message_type molch_get_message_type(
    const unsigned char * const packet,
    const size_t packet_length);

extern int molch_create_send_conversation(
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
		size_t * const json_export_length);

extern int molch_create_receive_conversation(
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
		size_t * const json_export_length);

extern int molch_encrypt_message(
		unsigned char ** const packet,
		size_t *packet_length,
		const unsigned char * const message,
		const size_t message_length,
		const unsigned char * const conversation_id,
		unsigned char ** const json_export_conversation,
		size_t * const json_export_conversation_length);

extern int molch_decrypt_message(
		unsigned char ** const message,
		size_t *message_length,
		const unsigned char * const packet,
		const size_t packet_length,
		const unsigned char * const conversation_id,
		unsigned char ** const json_export_conversation,
		size_t * const json_export_conversation_length);

extern void molch_end_conversation(
		const unsigned char * const conversation_id,
		unsigned char ** const json_export,
		size_t * const json_export_length);

extern unsigned char *molch_list_conversations(const unsigned char * const user_public_signing_key, size_t *number);

extern unsigned char *molch_conversation_json_export(const unsigned char * const conversation_id, size_t * const length);

extern unsigned char *molch_json_export(size_t *length);

extern int molch_conversation_json_import(const unsigned char * const json, const size_t length);

extern int molch_json_import(const unsigned char* const json, const size_t length);
