/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: key.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "key.pb-c.h"
void   molch__protobuf__key__init
                     (Molch__Protobuf__Key         *message)
{
  static const Molch__Protobuf__Key init_value = MOLCH__PROTOBUF__KEY__INIT;
  *message = init_value;
}
size_t molch__protobuf__key__get_packed_size
                     (const Molch__Protobuf__Key *message)
{
  assert(message->base.descriptor == &molch__protobuf__key__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t molch__protobuf__key__pack
                     (const Molch__Protobuf__Key *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &molch__protobuf__key__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t molch__protobuf__key__pack_to_buffer
                     (const Molch__Protobuf__Key *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &molch__protobuf__key__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Molch__Protobuf__Key *
       molch__protobuf__key__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Molch__Protobuf__Key *)
     protobuf_c_message_unpack (&molch__protobuf__key__descriptor,
                                allocator, len, data);
}
void   molch__protobuf__key__free_unpacked
                     (Molch__Protobuf__Key *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &molch__protobuf__key__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor molch__protobuf__key__field_descriptors[1] =
{
  {
    "key",
    1,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(Molch__Protobuf__Key, key),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned molch__protobuf__key__field_indices_by_name[] = {
  0,   /* field[0] = key */
};
static const ProtobufCIntRange molch__protobuf__key__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 1 }
};
const ProtobufCMessageDescriptor molch__protobuf__key__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "Molch.Protobuf.Key",
  "Key",
  "Molch__Protobuf__Key",
  "Molch.Protobuf",
  sizeof(Molch__Protobuf__Key),
  1,
  molch__protobuf__key__field_descriptors,
  molch__protobuf__key__field_indices_by_name,
  1,  molch__protobuf__key__number_ranges,
  (ProtobufCMessageInit) molch__protobuf__key__init,
  NULL,NULL,NULL    /* reserved[123] */
};
