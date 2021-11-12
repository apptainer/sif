// Copyright (c) 2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package sif

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/sebdah/goldie/v2"
)

var testTime = time.Unix(1136239445, 0)

func TestNewDescriptorInput(t *testing.T) {
	t.Parallel()

	fp := []byte{
		0x12, 0x04, 0x5c, 0x8c, 0x0b, 0x10, 0x04, 0xd0, 0x58, 0xde,
		0x4b, 0xed, 0xa2, 0x0c, 0x27, 0xee, 0x7f, 0xf7, 0xba, 0x84,
	}

	tests := []struct {
		name    string
		t       DataType
		opts    []DescriptorInputOpt
		wantErr error
	}{
		{
			name: "Empty",
			t:    DataGeneric,
			opts: []DescriptorInputOpt{
				OptObjectTime(testTime),
			},
		},
		{
			name: "OptNoGroup",
			t:    DataGeneric,
			opts: []DescriptorInputOpt{
				OptNoGroup(),
				OptObjectTime(testTime),
			},
		},
		{
			name: "OptGroupIDInvalid",
			t:    DataGeneric,
			opts: []DescriptorInputOpt{
				OptGroupID(0),
			},
			wantErr: ErrInvalidGroupID,
		},
		{
			name: "OptGroupID",
			t:    DataGeneric,
			opts: []DescriptorInputOpt{
				OptGroupID(2),
				OptObjectTime(testTime),
			},
		},
		{
			name: "OptLinkedIDInvalid",
			t:    DataGeneric,
			opts: []DescriptorInputOpt{
				OptLinkedID(0),
			},
			wantErr: ErrInvalidObjectID,
		},
		{
			name: "OptLinkedID",
			t:    DataGeneric,
			opts: []DescriptorInputOpt{
				OptLinkedID(1),
				OptObjectTime(testTime),
			},
		},
		{
			name: "OptLinkedGroupIDInvalid",
			t:    DataGeneric,
			opts: []DescriptorInputOpt{
				OptLinkedGroupID(0),
			},
			wantErr: ErrInvalidGroupID,
		},
		{
			name: "OptLinkedGroupID",
			t:    DataGeneric,
			opts: []DescriptorInputOpt{
				OptLinkedGroupID(1),
				OptObjectTime(testTime),
			},
		},
		{
			name: "OptObjectAlignment",
			t:    DataGeneric,
			opts: []DescriptorInputOpt{
				OptObjectAlignment(8),
				OptObjectTime(testTime),
			},
		},
		{
			name: "OptObjectName",
			t:    DataGeneric,
			opts: []DescriptorInputOpt{
				OptObjectName("name"),
				OptObjectTime(testTime),
			},
		},
		{
			name: "OptCryptoMessageMetadataUnexpectedDataType",
			t:    DataGeneric,
			opts: []DescriptorInputOpt{
				OptCryptoMessageMetadata(FormatOpenPGP, MessageClearSignature),
			},
			wantErr: &unexpectedDataTypeError{DataGeneric, DataCryptoMessage},
		},
		{
			name: "OptCryptoMessageMetadata",
			t:    DataCryptoMessage,
			opts: []DescriptorInputOpt{
				OptCryptoMessageMetadata(FormatOpenPGP, MessageClearSignature),
				OptObjectTime(testTime),
			},
		},
		{
			name: "OptPartitionMetadataUnexpectedDataType",
			t:    DataGeneric,
			opts: []DescriptorInputOpt{
				OptPartitionMetadata(FsSquash, PartPrimSys, "386"),
			},
			wantErr: &unexpectedDataTypeError{DataGeneric, DataPartition},
		},
		{
			name: "OptPartitionMetadata",
			t:    DataPartition,
			opts: []DescriptorInputOpt{
				OptPartitionMetadata(FsSquash, PartPrimSys, "386"),
				OptObjectTime(testTime),
			},
		},
		{
			name: "OptSignatureMetadataUnexpectedDataType",
			t:    DataGeneric,
			opts: []DescriptorInputOpt{
				OptSignatureMetadata(crypto.SHA256, fp),
			},
			wantErr: &unexpectedDataTypeError{DataGeneric, DataSignature},
		},
		{
			name: "OptSignatureMetadata",
			t:    DataSignature,
			opts: []DescriptorInputOpt{
				OptSignatureMetadata(crypto.SHA256, fp),
				OptObjectTime(testTime),
			},
		},
	}
	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			di, err := NewDescriptorInput(tt.t, nil, tt.opts...)

			if got, want := err, tt.wantErr; !errors.Is(got, want) {
				t.Fatalf("got error %v, want %v", got, want)
			}

			if err == nil {
				d := rawDescriptor{}
				if err := di.fillDescriptor(&d); err != nil {
					t.Fatal(err)
				}

				b := bytes.Buffer{}
				if err := binary.Write(&b, binary.LittleEndian, d); err != nil {
					t.Fatal(err)
				}

				g := goldie.New(t, goldie.WithTestNameForDir(true))
				g.Assert(t, tt.name, b.Bytes())
			}
		})
	}
}
