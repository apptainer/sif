// Copyright (c) Contributors to the Apptainer project, established as
//   Apptainer a Series of LF Projects LLC.
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// Copyright (c) 2018-2024, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package sif

import (
	"errors"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sebdah/goldie/v2"
)

func TestSetPrimPart(t *testing.T) {
	tests := []struct {
		name       string
		createOpts []CreateOpt
		id         uint32
		opts       []SetOpt
		wantErr    error
	}{
		{
			name: "ErrObjectNotFound",
			createOpts: []CreateOpt{
				OptCreateDeterministic(),
			},
			id:      1,
			wantErr: ErrObjectNotFound,
		},
		{
			name: "Deterministic",
			createOpts: []CreateOpt{
				OptCreateWithID("de170c43-36ab-44a8-bca9-1ea1a070a274"),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataPartition, []byte{0xfa, 0xce},
						OptPartitionMetadata(FsRaw, PartSystem, "386"),
					),
				),
				OptCreateWithTime(time.Unix(946702800, 0)),
			},
			id: 1,
			opts: []SetOpt{
				OptSetDeterministic(),
			},
		},
		{
			name: "WithTime",
			createOpts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataPartition, []byte{0xfa, 0xce},
						OptPartitionMetadata(FsRaw, PartPrimSys, "386"),
					),
					getDescriptorInput(t, DataPartition, []byte{0xfe, 0xed},
						OptPartitionMetadata(FsRaw, PartSystem, "amd64"),
					),
				),
			},
			id: 2,
			opts: []SetOpt{
				OptSetWithTime(time.Unix(946702800, 0)),
			},
		},
		{
			name: "One",
			createOpts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataPartition, []byte{0xfa, 0xce},
						OptPartitionMetadata(FsRaw, PartSystem, "386"),
					),
				),
			},
			id: 1,
		},
		{
			name: "Two",
			createOpts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataPartition, []byte{0xfa, 0xce},
						OptPartitionMetadata(FsRaw, PartPrimSys, "386"),
					),
					getDescriptorInput(t, DataPartition, []byte{0xfe, 0xed},
						OptPartitionMetadata(FsRaw, PartSystem, "amd64"),
					),
				),
			},
			id: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var b Buffer

			f, err := CreateContainer(&b, tt.createOpts...)
			if err != nil {
				t.Fatal(err)
			}

			if got, want := f.SetPrimPart(tt.id, tt.opts...), tt.wantErr; !errors.Is(got, want) {
				t.Errorf("got error %v, want %v", got, want)
			}

			if err := f.UnloadContainer(); err != nil {
				t.Error(err)
			}

			g := goldie.New(t, goldie.WithTestNameForDir(true))
			g.Assert(t, tt.name, b.Bytes())
		})
	}
}

func TestSetMetadata(t *testing.T) {
	tests := []struct {
		name       string
		createOpts []CreateOpt
		id         uint32
		opts       []SetOpt
		wantErr    error
	}{
		{
			name: "Deterministic",
			createOpts: []CreateOpt{
				OptCreateWithID("de170c43-36ab-44a8-bca9-1ea1a070a274"),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataOCIBlob, []byte{0xfa, 0xce}),
				),
				OptCreateWithTime(time.Unix(946702800, 0)),
			},
			id: 1,
			opts: []SetOpt{
				OptSetDeterministic(),
			},
		},
		{
			name: "WithTime",
			createOpts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataOCIBlob, []byte{0xfa, 0xce}),
				),
			},
			id: 1,
			opts: []SetOpt{
				OptSetWithTime(time.Unix(946702800, 0)),
			},
		},
		{
			name: "One",
			createOpts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataOCIBlob, []byte{0xfa, 0xce}),
				),
			},
			id: 1,
		},
		{
			name: "Two",
			createOpts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataOCIBlob, []byte{0xfa, 0xce}),
					getDescriptorInput(t, DataOCIBlob, []byte{0xfe, 0xed}),
				),
			},
			id: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var b Buffer

			f, err := CreateContainer(&b, tt.createOpts...)
			if err != nil {
				t.Fatal(err)
			}

			if got, want := f.SetMetadata(tt.id, newOCIBlobDigest(), tt.opts...), tt.wantErr; !errors.Is(got, want) {
				t.Errorf("got error %v, want %v", got, want)
			}

			if err := f.UnloadContainer(); err != nil {
				t.Error(err)
			}

			g := goldie.New(t, goldie.WithTestNameForDir(true))
			g.Assert(t, tt.name, b.Bytes())
		})
	}
}

func TestFileImage_SetOCIBlobDigest(t *testing.T) {
	tests := []struct {
		name       string
		createOpts []CreateOpt
		id         uint32
		h          v1.Hash
		opts       []SetOpt
		wantErr    error
	}{
		{
			name: "UnexpectedDataType",
			createOpts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataGeneric, []byte{0xfa, 0xce}),
				),
			},
			id: 1,
			h: v1.Hash{
				Algorithm: "sha256",
				Hex:       "93a6ab73f77ce27501f74bb35af9b4da5b964c62f96175a1bc0e8ba2ae0dec08",
			},
			wantErr: &unexpectedDataTypeError{DataGeneric, []DataType{DataOCIBlob, DataOCIRootIndex}},
		},
		{
			name: "Deterministic",
			createOpts: []CreateOpt{
				OptCreateWithID("de170c43-36ab-44a8-bca9-1ea1a070a274"),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataOCIBlob, []byte{0xfa, 0xce}),
				),
				OptCreateWithTime(time.Unix(946702800, 0)),
			},
			id: 1,
			h: v1.Hash{
				Algorithm: "sha256",
				Hex:       "93a6ab73f77ce27501f74bb35af9b4da5b964c62f96175a1bc0e8ba2ae0dec08",
			},
			opts: []SetOpt{
				OptSetDeterministic(),
			},
		},
		{
			name: "WithTime",
			createOpts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataOCIBlob, []byte{0xfa, 0xce}),
				),
			},
			id: 1,
			h: v1.Hash{
				Algorithm: "sha256",
				Hex:       "93a6ab73f77ce27501f74bb35af9b4da5b964c62f96175a1bc0e8ba2ae0dec08",
			},
			opts: []SetOpt{
				OptSetWithTime(time.Unix(946702800, 0)),
			},
		},
		{
			name: "One",
			createOpts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataOCIBlob, []byte{0xfa, 0xce}),
				),
			},
			id: 1,
			h: v1.Hash{
				Algorithm: "sha256",
				Hex:       "93a6ab73f77ce27501f74bb35af9b4da5b964c62f96175a1bc0e8ba2ae0dec08",
			},
		},
		{
			name: "Two",
			createOpts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataOCIBlob, []byte{0xfa, 0xce}),
					getDescriptorInput(t, DataOCIBlob, []byte{0xfe, 0xed}),
				),
			},
			id: 2,
			h: v1.Hash{
				Algorithm: "sha256",
				Hex:       "93a6ab73f77ce27501f74bb35af9b4da5b964c62f96175a1bc0e8ba2ae0dec08",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var b Buffer

			f, err := CreateContainer(&b, tt.createOpts...)
			if err != nil {
				t.Fatal(err)
			}

			if got, want := f.SetOCIBlobDigest(tt.id, tt.h, tt.opts...), tt.wantErr; !errors.Is(got, want) {
				t.Errorf("got error %v, want %v", got, want)
			}

			if err := f.UnloadContainer(); err != nil {
				t.Error(err)
			}

			if tt.wantErr == nil {
				g := goldie.New(t, goldie.WithTestNameForDir(true))
				g.Assert(t, tt.name, b.Bytes())
			}
		})
	}
}
