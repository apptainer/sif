// Copyright (c) Contributors to the Apptainer project, established as
//   Apptainer a Series of LF Projects LLC.
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// Copyright (c) 2021-2023, Sylabs Inc. All rights reserved.
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

// getDescriptorInput returns a new DescriptorInput of type dt with contents b, according to opts.
func getDescriptorInput(t *testing.T, dt DataType, b []byte, opts ...DescriptorInputOpt) DescriptorInput {
	t.Helper()

	di, err := NewDescriptorInput(dt, bytes.NewReader(b), opts...)
	if err != nil {
		t.Fatal(err)
	}
	return di
}

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
		},
		{
			name: "OptNoGroup",
			t:    DataGeneric,
			opts: []DescriptorInputOpt{
				OptNoGroup(),
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
			},
		},
		{
			name: "OptObjectAlignment",
			t:    DataGeneric,
			opts: []DescriptorInputOpt{
				OptObjectAlignment(8),
			},
		},
		{
			name: "OptObjectName",
			t:    DataGeneric,
			opts: []DescriptorInputOpt{
				OptObjectName("name"),
			},
		},
		{
			name: "OptObjectTime",
			t:    DataGeneric,
			opts: []DescriptorInputOpt{
				OptObjectTime(time.Unix(946702800, 0)),
			},
		},
		{
			name: "OptMetadata",
			t:    DataGeneric,
			opts: []DescriptorInputOpt{
				OptMetadata(testMetadata{100}),
			},
		},
		{
			name: "OptCryptoMessageMetadataUnexpectedDataType",
			t:    DataGeneric,
			opts: []DescriptorInputOpt{
				OptCryptoMessageMetadata(FormatOpenPGP, MessageClearSignature),
			},
			wantErr: &unexpectedDataTypeError{DataGeneric, []DataType{DataCryptoMessage}},
		},
		{
			name: "OptCryptoMessageMetadata",
			t:    DataCryptoMessage,
			opts: []DescriptorInputOpt{
				OptCryptoMessageMetadata(FormatOpenPGP, MessageClearSignature),
			},
		},
		{
			name: "OptPartitionMetadataUnexpectedDataType",
			t:    DataGeneric,
			opts: []DescriptorInputOpt{
				OptPartitionMetadata(FsSquash, PartPrimSys, "386"),
			},
			wantErr: &unexpectedDataTypeError{DataGeneric, []DataType{DataPartition}},
		},
		{
			name: "OptPartitionMetadata",
			t:    DataPartition,
			opts: []DescriptorInputOpt{
				OptPartitionMetadata(FsSquash, PartPrimSys, "386"),
			},
		},
		{
			name: "OptSignatureMetadataUnexpectedDataType",
			t:    DataGeneric,
			opts: []DescriptorInputOpt{
				OptSignatureMetadata(crypto.SHA256, fp),
			},
			wantErr: &unexpectedDataTypeError{DataGeneric, []DataType{DataSignature}},
		},
		{
			name: "OptSignatureMetadata",
			t:    DataSignature,
			opts: []DescriptorInputOpt{
				OptSignatureMetadata(crypto.SHA256, fp),
			},
		},
		{
			name: "OptSBOMMetadataUnexpectedDataType",
			t:    DataGeneric,
			opts: []DescriptorInputOpt{
				OptSBOMMetadata(SBOMFormatCycloneDXJSON),
			},
			wantErr: &unexpectedDataTypeError{DataGeneric, []DataType{DataSBOM}},
		},
		{
			name: "OptSBOMMetadata",
			t:    DataSBOM,
			opts: []DescriptorInputOpt{
				OptSBOMMetadata(SBOMFormatCycloneDXJSON),
			},
		},
		{
			name: "DataOCIRootIndex",
			t:    DataOCIRootIndex,
		},
		{
			name: "DataOCIBlob",
			t:    DataOCIBlob,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			di, err := NewDescriptorInput(tt.t, nil, tt.opts...)

			if got, want := err, tt.wantErr; !errors.Is(got, want) {
				t.Fatalf("got error %v, want %v", got, want)
			}

			if err == nil {
				d := rawDescriptor{}
				if err := di.fillDescriptor(time.Time{}, &d); err != nil {
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
