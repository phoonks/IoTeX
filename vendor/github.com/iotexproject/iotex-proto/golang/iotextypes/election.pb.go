// Copyright (c) 2019 IoTeX
// This is an alpha (internal) release and is not suitable for production. This source code is provided 'as is' and no
// warranties are given as to title or non-infringement, merchantability or fitness for purpose and, to the extent
// permitted by law, all liability for your use of the code is disclaimed. This source code is governed by Apache
// License 2.0 that can be found in the LICENSE file.

// To compile the proto, run:
//      protoc --go_out=plugins=grpc:$GOPATH/src *.proto

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.2
// 	protoc        v5.27.1
// source: proto/types/election.proto

package iotextypes

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	durationpb "google.golang.org/protobuf/types/known/durationpb"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type ElectionBucket struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Voter     []byte                 `protobuf:"bytes,1,opt,name=voter,proto3" json:"voter,omitempty"`
	Candidate []byte                 `protobuf:"bytes,2,opt,name=candidate,proto3" json:"candidate,omitempty"`
	Amount    []byte                 `protobuf:"bytes,3,opt,name=amount,proto3" json:"amount,omitempty"`
	StartTime *timestamppb.Timestamp `protobuf:"bytes,4,opt,name=startTime,proto3" json:"startTime,omitempty"`
	Duration  *durationpb.Duration   `protobuf:"bytes,5,opt,name=duration,proto3" json:"duration,omitempty"`
	Decay     bool                   `protobuf:"varint,6,opt,name=decay,proto3" json:"decay,omitempty"`
}

func (x *ElectionBucket) Reset() {
	*x = ElectionBucket{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_types_election_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ElectionBucket) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ElectionBucket) ProtoMessage() {}

func (x *ElectionBucket) ProtoReflect() protoreflect.Message {
	mi := &file_proto_types_election_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ElectionBucket.ProtoReflect.Descriptor instead.
func (*ElectionBucket) Descriptor() ([]byte, []int) {
	return file_proto_types_election_proto_rawDescGZIP(), []int{0}
}

func (x *ElectionBucket) GetVoter() []byte {
	if x != nil {
		return x.Voter
	}
	return nil
}

func (x *ElectionBucket) GetCandidate() []byte {
	if x != nil {
		return x.Candidate
	}
	return nil
}

func (x *ElectionBucket) GetAmount() []byte {
	if x != nil {
		return x.Amount
	}
	return nil
}

func (x *ElectionBucket) GetStartTime() *timestamppb.Timestamp {
	if x != nil {
		return x.StartTime
	}
	return nil
}

func (x *ElectionBucket) GetDuration() *durationpb.Duration {
	if x != nil {
		return x.Duration
	}
	return nil
}

func (x *ElectionBucket) GetDecay() bool {
	if x != nil {
		return x.Decay
	}
	return false
}

var File_proto_types_election_proto protoreflect.FileDescriptor

var file_proto_types_election_proto_rawDesc = []byte{
	0x0a, 0x1a, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2f, 0x65, 0x6c,
	0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0a, 0x69, 0x6f,
	0x74, 0x65, 0x78, 0x74, 0x79, 0x70, 0x65, 0x73, 0x1a, 0x1e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x64, 0x75, 0x72, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74,
	0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xe3, 0x01, 0x0a, 0x0e, 0x45, 0x6c,
	0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x42, 0x75, 0x63, 0x6b, 0x65, 0x74, 0x12, 0x14, 0x0a, 0x05,
	0x76, 0x6f, 0x74, 0x65, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x05, 0x76, 0x6f, 0x74,
	0x65, 0x72, 0x12, 0x1c, 0x0a, 0x09, 0x63, 0x61, 0x6e, 0x64, 0x69, 0x64, 0x61, 0x74, 0x65, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x63, 0x61, 0x6e, 0x64, 0x69, 0x64, 0x61, 0x74, 0x65,
	0x12, 0x16, 0x0a, 0x06, 0x61, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x06, 0x61, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x12, 0x38, 0x0a, 0x09, 0x73, 0x74, 0x61, 0x72,
	0x74, 0x54, 0x69, 0x6d, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69,
	0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x09, 0x73, 0x74, 0x61, 0x72, 0x74, 0x54, 0x69,
	0x6d, 0x65, 0x12, 0x35, 0x0a, 0x08, 0x64, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x05,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x44, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52,
	0x08, 0x64, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x14, 0x0a, 0x05, 0x64, 0x65, 0x63,
	0x61, 0x79, 0x18, 0x06, 0x20, 0x01, 0x28, 0x08, 0x52, 0x05, 0x64, 0x65, 0x63, 0x61, 0x79, 0x42,
	0x5d, 0x0a, 0x22, 0x63, 0x6f, 0x6d, 0x2e, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x69, 0x6f,
	0x74, 0x65, 0x78, 0x70, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x2e, 0x67, 0x72, 0x70, 0x63, 0x2e,
	0x74, 0x79, 0x70, 0x65, 0x73, 0x50, 0x01, 0x5a, 0x35, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e,
	0x63, 0x6f, 0x6d, 0x2f, 0x69, 0x6f, 0x74, 0x65, 0x78, 0x70, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74,
	0x2f, 0x69, 0x6f, 0x74, 0x65, 0x78, 0x2d, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x67, 0x6f, 0x6c,
	0x61, 0x6e, 0x67, 0x2f, 0x69, 0x6f, 0x74, 0x65, 0x78, 0x74, 0x79, 0x70, 0x65, 0x73, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_proto_types_election_proto_rawDescOnce sync.Once
	file_proto_types_election_proto_rawDescData = file_proto_types_election_proto_rawDesc
)

func file_proto_types_election_proto_rawDescGZIP() []byte {
	file_proto_types_election_proto_rawDescOnce.Do(func() {
		file_proto_types_election_proto_rawDescData = protoimpl.X.CompressGZIP(file_proto_types_election_proto_rawDescData)
	})
	return file_proto_types_election_proto_rawDescData
}

var file_proto_types_election_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_proto_types_election_proto_goTypes = []any{
	(*ElectionBucket)(nil),        // 0: iotextypes.ElectionBucket
	(*timestamppb.Timestamp)(nil), // 1: google.protobuf.Timestamp
	(*durationpb.Duration)(nil),   // 2: google.protobuf.Duration
}
var file_proto_types_election_proto_depIdxs = []int32{
	1, // 0: iotextypes.ElectionBucket.startTime:type_name -> google.protobuf.Timestamp
	2, // 1: iotextypes.ElectionBucket.duration:type_name -> google.protobuf.Duration
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_proto_types_election_proto_init() }
func file_proto_types_election_proto_init() {
	if File_proto_types_election_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_proto_types_election_proto_msgTypes[0].Exporter = func(v any, i int) any {
			switch v := v.(*ElectionBucket); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_proto_types_election_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_proto_types_election_proto_goTypes,
		DependencyIndexes: file_proto_types_election_proto_depIdxs,
		MessageInfos:      file_proto_types_election_proto_msgTypes,
	}.Build()
	File_proto_types_election_proto = out.File
	file_proto_types_election_proto_rawDesc = nil
	file_proto_types_election_proto_goTypes = nil
	file_proto_types_election_proto_depIdxs = nil
}