// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: mathtest.proto

#ifndef PROTOBUF_INCLUDED_mathtest_2eproto
#define PROTOBUF_INCLUDED_mathtest_2eproto

#include <string>

#include <google/protobuf/stubs/common.h>

#if GOOGLE_PROTOBUF_VERSION < 3006001
#error This file was generated by a newer version of protoc which is
#error incompatible with your Protocol Buffer headers.  Please update
#error your headers.
#endif
#if 3006001 < GOOGLE_PROTOBUF_MIN_PROTOC_VERSION
#error This file was generated by an older version of protoc which is
#error incompatible with your Protocol Buffer headers.  Please
#error regenerate this file with a newer version of protoc.
#endif

#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/arena.h>
#include <google/protobuf/arenastring.h>
#include <google/protobuf/generated_message_table_driven.h>
#include <google/protobuf/generated_message_util.h>
#include <google/protobuf/inlined_string_field.h>
#include <google/protobuf/metadata.h>
#include <google/protobuf/message.h>
#include <google/protobuf/repeated_field.h>  // IWYU pragma: export
#include <google/protobuf/extension_set.h>  // IWYU pragma: export
#include <google/protobuf/unknown_field_set.h>
// @@protoc_insertion_point(includes)
#define PROTOBUF_INTERNAL_EXPORT_protobuf_mathtest_2eproto 

namespace protobuf_mathtest_2eproto {
// Internal implementation detail -- do not use these members.
struct TableStruct {
  static const ::google::protobuf::internal::ParseTableField entries[];
  static const ::google::protobuf::internal::AuxillaryParseTableField aux[];
  static const ::google::protobuf::internal::ParseTable schema[2];
  static const ::google::protobuf::internal::FieldMetadata field_metadata[];
  static const ::google::protobuf::internal::SerializationTable serialization_table[];
  static const ::google::protobuf::uint32 offsets[];
};
void AddDescriptors();
}  // namespace protobuf_mathtest_2eproto
namespace mathtest {
class MathReply;
class MathReplyDefaultTypeInternal;
extern MathReplyDefaultTypeInternal _MathReply_default_instance_;
class MathRequest;
class MathRequestDefaultTypeInternal;
extern MathRequestDefaultTypeInternal _MathRequest_default_instance_;
}  // namespace mathtest
namespace google {
namespace protobuf {
template<> ::mathtest::MathReply* Arena::CreateMaybeMessage<::mathtest::MathReply>(Arena*);
template<> ::mathtest::MathRequest* Arena::CreateMaybeMessage<::mathtest::MathRequest>(Arena*);
}  // namespace protobuf
}  // namespace google
namespace mathtest {

// ===================================================================

class MathRequest : public ::google::protobuf::Message /* @@protoc_insertion_point(class_definition:mathtest.MathRequest) */ {
 public:
  MathRequest();
  virtual ~MathRequest();

  MathRequest(const MathRequest& from);

  inline MathRequest& operator=(const MathRequest& from) {
    CopyFrom(from);
    return *this;
  }
  #if LANG_CXX11
  MathRequest(MathRequest&& from) noexcept
    : MathRequest() {
    *this = ::std::move(from);
  }

  inline MathRequest& operator=(MathRequest&& from) noexcept {
    if (GetArenaNoVirtual() == from.GetArenaNoVirtual()) {
      if (this != &from) InternalSwap(&from);
    } else {
      CopyFrom(from);
    }
    return *this;
  }
  #endif
  static const ::google::protobuf::Descriptor* descriptor();
  static const MathRequest& default_instance();

  static void InitAsDefaultInstance();  // FOR INTERNAL USE ONLY
  static inline const MathRequest* internal_default_instance() {
    return reinterpret_cast<const MathRequest*>(
               &_MathRequest_default_instance_);
  }
  static constexpr int kIndexInFileMessages =
    0;

  void Swap(MathRequest* other);
  friend void swap(MathRequest& a, MathRequest& b) {
    a.Swap(&b);
  }

  // implements Message ----------------------------------------------

  inline MathRequest* New() const final {
    return CreateMaybeMessage<MathRequest>(NULL);
  }

  MathRequest* New(::google::protobuf::Arena* arena) const final {
    return CreateMaybeMessage<MathRequest>(arena);
  }
  void CopyFrom(const ::google::protobuf::Message& from) final;
  void MergeFrom(const ::google::protobuf::Message& from) final;
  void CopyFrom(const MathRequest& from);
  void MergeFrom(const MathRequest& from);
  void Clear() final;
  bool IsInitialized() const final;

  size_t ByteSizeLong() const final;
  bool MergePartialFromCodedStream(
      ::google::protobuf::io::CodedInputStream* input) final;
  void SerializeWithCachedSizes(
      ::google::protobuf::io::CodedOutputStream* output) const final;
  ::google::protobuf::uint8* InternalSerializeWithCachedSizesToArray(
      bool deterministic, ::google::protobuf::uint8* target) const final;
  int GetCachedSize() const final { return _cached_size_.Get(); }

  private:
  void SharedCtor();
  void SharedDtor();
  void SetCachedSize(int size) const final;
  void InternalSwap(MathRequest* other);
  private:
  inline ::google::protobuf::Arena* GetArenaNoVirtual() const {
    return NULL;
  }
  inline void* MaybeArenaPtr() const {
    return NULL;
  }
  public:

  ::google::protobuf::Metadata GetMetadata() const final;

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  // int32 a = 1;
  void clear_a();
  static const int kAFieldNumber = 1;
  ::google::protobuf::int32 a() const;
  void set_a(::google::protobuf::int32 value);

  // int32 b = 2;
  void clear_b();
  static const int kBFieldNumber = 2;
  ::google::protobuf::int32 b() const;
  void set_b(::google::protobuf::int32 value);

  // @@protoc_insertion_point(class_scope:mathtest.MathRequest)
 private:

  ::google::protobuf::internal::InternalMetadataWithArena _internal_metadata_;
  ::google::protobuf::int32 a_;
  ::google::protobuf::int32 b_;
  mutable ::google::protobuf::internal::CachedSize _cached_size_;
  friend struct ::protobuf_mathtest_2eproto::TableStruct;
};
// -------------------------------------------------------------------

class MathReply : public ::google::protobuf::Message /* @@protoc_insertion_point(class_definition:mathtest.MathReply) */ {
 public:
  MathReply();
  virtual ~MathReply();

  MathReply(const MathReply& from);

  inline MathReply& operator=(const MathReply& from) {
    CopyFrom(from);
    return *this;
  }
  #if LANG_CXX11
  MathReply(MathReply&& from) noexcept
    : MathReply() {
    *this = ::std::move(from);
  }

  inline MathReply& operator=(MathReply&& from) noexcept {
    if (GetArenaNoVirtual() == from.GetArenaNoVirtual()) {
      if (this != &from) InternalSwap(&from);
    } else {
      CopyFrom(from);
    }
    return *this;
  }
  #endif
  static const ::google::protobuf::Descriptor* descriptor();
  static const MathReply& default_instance();

  static void InitAsDefaultInstance();  // FOR INTERNAL USE ONLY
  static inline const MathReply* internal_default_instance() {
    return reinterpret_cast<const MathReply*>(
               &_MathReply_default_instance_);
  }
  static constexpr int kIndexInFileMessages =
    1;

  void Swap(MathReply* other);
  friend void swap(MathReply& a, MathReply& b) {
    a.Swap(&b);
  }

  // implements Message ----------------------------------------------

  inline MathReply* New() const final {
    return CreateMaybeMessage<MathReply>(NULL);
  }

  MathReply* New(::google::protobuf::Arena* arena) const final {
    return CreateMaybeMessage<MathReply>(arena);
  }
  void CopyFrom(const ::google::protobuf::Message& from) final;
  void MergeFrom(const ::google::protobuf::Message& from) final;
  void CopyFrom(const MathReply& from);
  void MergeFrom(const MathReply& from);
  void Clear() final;
  bool IsInitialized() const final;

  size_t ByteSizeLong() const final;
  bool MergePartialFromCodedStream(
      ::google::protobuf::io::CodedInputStream* input) final;
  void SerializeWithCachedSizes(
      ::google::protobuf::io::CodedOutputStream* output) const final;
  ::google::protobuf::uint8* InternalSerializeWithCachedSizesToArray(
      bool deterministic, ::google::protobuf::uint8* target) const final;
  int GetCachedSize() const final { return _cached_size_.Get(); }

  private:
  void SharedCtor();
  void SharedDtor();
  void SetCachedSize(int size) const final;
  void InternalSwap(MathReply* other);
  private:
  inline ::google::protobuf::Arena* GetArenaNoVirtual() const {
    return NULL;
  }
  inline void* MaybeArenaPtr() const {
    return NULL;
  }
  public:

  ::google::protobuf::Metadata GetMetadata() const final;

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  // int32 result = 1;
  void clear_result();
  static const int kResultFieldNumber = 1;
  ::google::protobuf::int32 result() const;
  void set_result(::google::protobuf::int32 value);

  // @@protoc_insertion_point(class_scope:mathtest.MathReply)
 private:

  ::google::protobuf::internal::InternalMetadataWithArena _internal_metadata_;
  ::google::protobuf::int32 result_;
  mutable ::google::protobuf::internal::CachedSize _cached_size_;
  friend struct ::protobuf_mathtest_2eproto::TableStruct;
};
// ===================================================================


// ===================================================================

#ifdef __GNUC__
  #pragma GCC diagnostic push
  #pragma GCC diagnostic ignored "-Wstrict-aliasing"
#endif  // __GNUC__
// MathRequest

// int32 a = 1;
inline void MathRequest::clear_a() {
  a_ = 0;
}
inline ::google::protobuf::int32 MathRequest::a() const {
  // @@protoc_insertion_point(field_get:mathtest.MathRequest.a)
  return a_;
}
inline void MathRequest::set_a(::google::protobuf::int32 value) {
  
  a_ = value;
  // @@protoc_insertion_point(field_set:mathtest.MathRequest.a)
}

// int32 b = 2;
inline void MathRequest::clear_b() {
  b_ = 0;
}
inline ::google::protobuf::int32 MathRequest::b() const {
  // @@protoc_insertion_point(field_get:mathtest.MathRequest.b)
  return b_;
}
inline void MathRequest::set_b(::google::protobuf::int32 value) {
  
  b_ = value;
  // @@protoc_insertion_point(field_set:mathtest.MathRequest.b)
}

// -------------------------------------------------------------------

// MathReply

// int32 result = 1;
inline void MathReply::clear_result() {
  result_ = 0;
}
inline ::google::protobuf::int32 MathReply::result() const {
  // @@protoc_insertion_point(field_get:mathtest.MathReply.result)
  return result_;
}
inline void MathReply::set_result(::google::protobuf::int32 value) {
  
  result_ = value;
  // @@protoc_insertion_point(field_set:mathtest.MathReply.result)
}

#ifdef __GNUC__
  #pragma GCC diagnostic pop
#endif  // __GNUC__
// -------------------------------------------------------------------


// @@protoc_insertion_point(namespace_scope)

}  // namespace mathtest

// @@protoc_insertion_point(global_scope)

#endif  // PROTOBUF_INCLUDED_mathtest_2eproto
