# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: counters.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='counters.proto',
  package='counters',
  syntax='proto3',
  serialized_options=None,
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n\x0e\x63ounters.proto\x12\x08\x63ounters\"%\n\x10MappacketRequest\x12\x11\n\tinterface\x18\x01 \x01(\t\"4\n\rMappaketReply\x12#\n\x08map_info\x18\x01 \x03(\x0b\x32\x11.counters.MapInfo\"H\n\x07MapInfo\x12\n\n\x02id\x18\x01 \x01(\x05\x12\x0c\n\x04name\x18\x02 \x01(\t\x12#\n\x07\x65ntries\x18\x03 \x03(\x0b\x32\x12.counters.MapEntry\"?\n\x10UpdateMapRequest\x12\x0e\n\x06map_id\x18\x01 \x01(\x05\x12\x0e\n\x06subnet\x18\x02 \x01(\t\x12\x0b\n\x03lbl\x18\x03 \x01(\x05\"!\n\x0eUpdateMapReply\x12\x0f\n\x07message\x18\x01 \x01(\t\":\n\x08MapEntry\x12\x0e\n\x06subnet\x18\x01 \x01(\x05\x12\x11\n\tipaddress\x18\x02 \x01(\t\x12\x0b\n\x03lbl\x18\x03 \x01(\x05\x32K\n\x07int_map\x12@\n\x07GetMaps\x12\x1a.counters.MappacketRequest\x1a\x17.counters.MappaketReply\"\x00\x32T\n\rint_UpdateMap\x12\x43\n\tUpdateMap\x12\x1a.counters.UpdateMapRequest\x1a\x18.counters.UpdateMapReply\"\x00\x62\x06proto3'
)




_MAPPACKETREQUEST = _descriptor.Descriptor(
  name='MappacketRequest',
  full_name='counters.MappacketRequest',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='interface', full_name='counters.MappacketRequest.interface', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=28,
  serialized_end=65,
)


_MAPPAKETREPLY = _descriptor.Descriptor(
  name='MappaketReply',
  full_name='counters.MappaketReply',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='map_info', full_name='counters.MappaketReply.map_info', index=0,
      number=1, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=67,
  serialized_end=119,
)


_MAPINFO = _descriptor.Descriptor(
  name='MapInfo',
  full_name='counters.MapInfo',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='id', full_name='counters.MapInfo.id', index=0,
      number=1, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='name', full_name='counters.MapInfo.name', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='entries', full_name='counters.MapInfo.entries', index=2,
      number=3, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=121,
  serialized_end=193,
)


_UPDATEMAPREQUEST = _descriptor.Descriptor(
  name='UpdateMapRequest',
  full_name='counters.UpdateMapRequest',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='map_id', full_name='counters.UpdateMapRequest.map_id', index=0,
      number=1, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='subnet', full_name='counters.UpdateMapRequest.subnet', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='lbl', full_name='counters.UpdateMapRequest.lbl', index=2,
      number=3, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=195,
  serialized_end=258,
)


_UPDATEMAPREPLY = _descriptor.Descriptor(
  name='UpdateMapReply',
  full_name='counters.UpdateMapReply',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='message', full_name='counters.UpdateMapReply.message', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=260,
  serialized_end=293,
)


_MAPENTRY = _descriptor.Descriptor(
  name='MapEntry',
  full_name='counters.MapEntry',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='subnet', full_name='counters.MapEntry.subnet', index=0,
      number=1, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='ipaddress', full_name='counters.MapEntry.ipaddress', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='lbl', full_name='counters.MapEntry.lbl', index=2,
      number=3, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=295,
  serialized_end=353,
)

_MAPPAKETREPLY.fields_by_name['map_info'].message_type = _MAPINFO
_MAPINFO.fields_by_name['entries'].message_type = _MAPENTRY
DESCRIPTOR.message_types_by_name['MappacketRequest'] = _MAPPACKETREQUEST
DESCRIPTOR.message_types_by_name['MappaketReply'] = _MAPPAKETREPLY
DESCRIPTOR.message_types_by_name['MapInfo'] = _MAPINFO
DESCRIPTOR.message_types_by_name['UpdateMapRequest'] = _UPDATEMAPREQUEST
DESCRIPTOR.message_types_by_name['UpdateMapReply'] = _UPDATEMAPREPLY
DESCRIPTOR.message_types_by_name['MapEntry'] = _MAPENTRY
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

MappacketRequest = _reflection.GeneratedProtocolMessageType('MappacketRequest', (_message.Message,), {
  'DESCRIPTOR' : _MAPPACKETREQUEST,
  '__module__' : 'counters_pb2'
  # @@protoc_insertion_point(class_scope:counters.MappacketRequest)
  })
_sym_db.RegisterMessage(MappacketRequest)

MappaketReply = _reflection.GeneratedProtocolMessageType('MappaketReply', (_message.Message,), {
  'DESCRIPTOR' : _MAPPAKETREPLY,
  '__module__' : 'counters_pb2'
  # @@protoc_insertion_point(class_scope:counters.MappaketReply)
  })
_sym_db.RegisterMessage(MappaketReply)

MapInfo = _reflection.GeneratedProtocolMessageType('MapInfo', (_message.Message,), {
  'DESCRIPTOR' : _MAPINFO,
  '__module__' : 'counters_pb2'
  # @@protoc_insertion_point(class_scope:counters.MapInfo)
  })
_sym_db.RegisterMessage(MapInfo)

UpdateMapRequest = _reflection.GeneratedProtocolMessageType('UpdateMapRequest', (_message.Message,), {
  'DESCRIPTOR' : _UPDATEMAPREQUEST,
  '__module__' : 'counters_pb2'
  # @@protoc_insertion_point(class_scope:counters.UpdateMapRequest)
  })
_sym_db.RegisterMessage(UpdateMapRequest)

UpdateMapReply = _reflection.GeneratedProtocolMessageType('UpdateMapReply', (_message.Message,), {
  'DESCRIPTOR' : _UPDATEMAPREPLY,
  '__module__' : 'counters_pb2'
  # @@protoc_insertion_point(class_scope:counters.UpdateMapReply)
  })
_sym_db.RegisterMessage(UpdateMapReply)

MapEntry = _reflection.GeneratedProtocolMessageType('MapEntry', (_message.Message,), {
  'DESCRIPTOR' : _MAPENTRY,
  '__module__' : 'counters_pb2'
  # @@protoc_insertion_point(class_scope:counters.MapEntry)
  })
_sym_db.RegisterMessage(MapEntry)



_INT_MAP = _descriptor.ServiceDescriptor(
  name='int_map',
  full_name='counters.int_map',
  file=DESCRIPTOR,
  index=0,
  serialized_options=None,
  create_key=_descriptor._internal_create_key,
  serialized_start=355,
  serialized_end=430,
  methods=[
  _descriptor.MethodDescriptor(
    name='GetMaps',
    full_name='counters.int_map.GetMaps',
    index=0,
    containing_service=None,
    input_type=_MAPPACKETREQUEST,
    output_type=_MAPPAKETREPLY,
    serialized_options=None,
    create_key=_descriptor._internal_create_key,
  ),
])
_sym_db.RegisterServiceDescriptor(_INT_MAP)

DESCRIPTOR.services_by_name['int_map'] = _INT_MAP


_INT_UPDATEMAP = _descriptor.ServiceDescriptor(
  name='int_UpdateMap',
  full_name='counters.int_UpdateMap',
  file=DESCRIPTOR,
  index=1,
  serialized_options=None,
  create_key=_descriptor._internal_create_key,
  serialized_start=432,
  serialized_end=516,
  methods=[
  _descriptor.MethodDescriptor(
    name='UpdateMap',
    full_name='counters.int_UpdateMap.UpdateMap',
    index=0,
    containing_service=None,
    input_type=_UPDATEMAPREQUEST,
    output_type=_UPDATEMAPREPLY,
    serialized_options=None,
    create_key=_descriptor._internal_create_key,
  ),
])
_sym_db.RegisterServiceDescriptor(_INT_UPDATEMAP)

DESCRIPTOR.services_by_name['int_UpdateMap'] = _INT_UPDATEMAP

# @@protoc_insertion_point(module_scope)