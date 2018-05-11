/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: header.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "header.pb-c.h"
void   molch__protobuf__header__init
                     (Molch__Protobuf__Header         *message)
{
  static const Molch__Protobuf__Header init_value = MOLCH__PROTOBUF__HEADER__INIT;
  *message = init_value;
}
size_t molch__protobuf__header__get_packed_size
                     (const Molch__Protobuf__Header *message)
{
  assert(message->base.descriptor == &molch__protobuf__header__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t molch__protobuf__header__pack
                     (const Molch__Protobuf__Header *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &molch__protobuf__header__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t molch__protobuf__header__pack_to_buffer
                     (const Molch__Protobuf__Header *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &molch__protobuf__header__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Molch__Protobuf__Header *
       molch__protobuf__header__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Molch__Protobuf__Header *)
     protobuf_c_message_unpack (&molch__protobuf__header__descriptor,
                                allocator, len, data);
}
void   molch__protobuf__header__free_unpacked
                     (Molch__Protobuf__Header *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &molch__protobuf__header__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor molch__protobuf__header__field_descriptors[3] =
{
  {
    "public_ephemeral_key",
    1,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_BYTES,
    offsetof(Molch__Protobuf__Header, has_public_ephemeral_key),
    offsetof(Molch__Protobuf__Header, public_ephemeral_key),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "message_number",
    2,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_FIXED32,
    offsetof(Molch__Protobuf__Header, has_message_number),
    offsetof(Molch__Protobuf__Header, message_number),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "previous_message_number",
    3,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_FIXED32,
    offsetof(Molch__Protobuf__Header, has_previous_message_number),
    offsetof(Molch__Protobuf__Header, previous_message_number),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned molch__protobuf__header__field_indices_by_name[] = {
  1,   /* field[1] = message_number */
  2,   /* field[2] = previous_message_number */
  0,   /* field[0] = public_ephemeral_key */
};
static const ProtobufCIntRange molch__protobuf__header__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 3 }
};
const ProtobufCMessageDescriptor molch__protobuf__header__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "Molch.Protobuf.Header",
  "Header",
  "Molch__Protobuf__Header",
  "Molch.Protobuf",
  sizeof(Molch__Protobuf__Header),
  3,
  molch__protobuf__header__field_descriptors,
  molch__protobuf__header__field_indices_by_name,
  1,  molch__protobuf__header__number_ranges,
  (ProtobufCMessageInit) molch__protobuf__header__init,
  NULL,NULL,NULL    /* reserved[123] */
};
