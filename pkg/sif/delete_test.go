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

	"github.com/sebdah/goldie/v2"
)

func TestDeleteObject(t *testing.T) {
	tests := []struct {
		name       string
		createOpts []CreateOpt
		ids        []uint32
		opts       []DeleteOpt
		wantErr    error
	}{
		{
			name: "ErrObjectNotFound",
			createOpts: []CreateOpt{
				OptCreateDeterministic(),
			},
			ids:     []uint32{1},
			wantErr: ErrObjectNotFound,
		},
		{
			name: "Compact",
			createOpts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataGeneric, []byte{0xfa, 0xce}),
					getDescriptorInput(t, DataGeneric, []byte{0xfe, 0xed}),
				),
			},
			ids: []uint32{1, 2},
			opts: []DeleteOpt{
				OptDeleteCompact(true),
			},
		},
		{
			name: "OneZero",
			createOpts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataGeneric, []byte{0xfa, 0xce}),
					getDescriptorInput(t, DataGeneric, []byte{0xfe, 0xed}),
				),
			},
			ids: []uint32{1},
			opts: []DeleteOpt{
				OptDeleteZero(true),
			},
		},
		{
			name: "OneCompact",
			createOpts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataGeneric, []byte{0xfa, 0xce}),
					getDescriptorInput(t, DataGeneric, []byte{0xfe, 0xed}),
				),
			},
			ids: []uint32{1},
			opts: []DeleteOpt{
				OptDeleteCompact(true),
			},
		},
		{
			name: "OneZeroCompact",
			createOpts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataGeneric, []byte{0xfa, 0xce}),
					getDescriptorInput(t, DataGeneric, []byte{0xfe, 0xed}),
				),
			},
			ids: []uint32{1},
			opts: []DeleteOpt{
				OptDeleteZero(true),
				OptDeleteCompact(true),
			},
		},
		{
			name: "TwoZero",
			createOpts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataGeneric, []byte{0xfa, 0xce}),
					getDescriptorInput(t, DataGeneric, []byte{0xfe, 0xed}),
				),
			},
			ids: []uint32{2},
			opts: []DeleteOpt{
				OptDeleteZero(true),
			},
		},
		{
			name: "TwoCompact",
			createOpts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataGeneric, []byte{0xfa, 0xce}),
					getDescriptorInput(t, DataGeneric, []byte{0xfe, 0xed}),
				),
			},
			ids: []uint32{2},
			opts: []DeleteOpt{
				OptDeleteCompact(true),
			},
		},
		{
			name: "TwoZeroCompact",
			createOpts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataGeneric, []byte{0xfa, 0xce}),
					getDescriptorInput(t, DataGeneric, []byte{0xfe, 0xed}),
				),
			},
			ids: []uint32{2},
			opts: []DeleteOpt{
				OptDeleteZero(true),
				OptDeleteCompact(true),
			},
		},
		{
			name: "Deterministic",
			createOpts: []CreateOpt{
				OptCreateWithID("de170c43-36ab-44a8-bca9-1ea1a070a274"),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataGeneric, []byte{0xfa, 0xce}),
				),
				OptCreateWithTime(time.Unix(946702800, 0)),
			},
			ids: []uint32{1},
			opts: []DeleteOpt{
				OptDeleteDeterministic(),
			},
		},
		{
			name: "WithTime",
			createOpts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataGeneric, []byte{0xfa, 0xce}),
				),
			},
			ids: []uint32{1},
			opts: []DeleteOpt{
				OptDeleteWithTime(time.Unix(946702800, 0)),
			},
		},
		{
			name: "PrimaryPartition",
			createOpts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataPartition, []byte{0xfa, 0xce},
						OptPartitionMetadata(FsSquash, PartPrimSys, "386"),
					),
				),
			},
			ids: []uint32{1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var b Buffer

			f, err := CreateContainer(&b, tt.createOpts...)
			if err != nil {
				t.Fatal(err)
			}

			for _, id := range tt.ids {
				if got, want := f.DeleteObject(id, tt.opts...), tt.wantErr; !errors.Is(got, want) {
					t.Errorf("got error %v, want %v", got, want)
				}
			}

			if err := f.UnloadContainer(); err != nil {
				t.Error(err)
			}

			g := goldie.New(t, goldie.WithTestNameForDir(true))
			g.Assert(t, tt.name, b.Bytes())
		})
	}
}

func TestDeleteObjects(t *testing.T) {
	tests := []struct {
		name       string
		createOpts []CreateOpt
		fn         DescriptorSelectorFunc
		opts       []DeleteOpt
		wantErr    error
	}{
		{
			name: "ErrObjectNotFound",
			createOpts: []CreateOpt{
				OptCreateDeterministic(),
			},
			fn:      WithID(1),
			wantErr: ErrObjectNotFound,
		},
		{
			name: "NilSelectFunc",
			createOpts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataGeneric, []byte{0xfa, 0xce}),
					getDescriptorInput(t, DataGeneric, []byte{0xfe, 0xed}),
				),
			},
			fn:      nil,
			wantErr: errNilSelectFunc,
		},
		{
			name: "DataType",
			createOpts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataGeneric, []byte{0xfa, 0xce}),
					getDescriptorInput(t, DataGeneric, []byte{0xfe, 0xed}),
				),
			},
			fn: WithDataType(DataGeneric),
		},
		{
			name: "DataTypeCompact",
			createOpts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataGeneric, []byte{0xfa, 0xce}),
					getDescriptorInput(t, DataGeneric, []byte{0xfe, 0xed}),
				),
			},
			fn: WithDataType(DataGeneric),
			opts: []DeleteOpt{
				OptDeleteCompact(true),
			},
		},
		{
			name: "PrimaryPartitionCompact",
			createOpts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataPartition, []byte{0xfa, 0xce},
						OptPartitionMetadata(FsSquash, PartPrimSys, "386"),
					),
				),
			},
			fn: WithPartitionType(PartPrimSys),
			opts: []DeleteOpt{
				OptDeleteCompact(true),
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

			if got, want := f.DeleteObjects(tt.fn, tt.opts...), tt.wantErr; !errors.Is(got, want) {
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

func TestDeleteObjectAndAddObject(t *testing.T) {
	tests := []struct {
		name string
		id   uint32
		opts []DeleteOpt
	}{
		{
			name: "Compact",
			id:   2,
			opts: []DeleteOpt{
				OptDeleteCompact(true),
			},
		},
		{
			name: "NoCompact",
			id:   2,
		},
		{
			name: "Zero",
			id:   2,
			opts: []DeleteOpt{
				OptDeleteZero(true),
			},
		},
		{
			name: "ZeroCompact",
			id:   2,
			opts: []DeleteOpt{
				OptDeleteZero(true),
				OptDeleteCompact(true),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var b Buffer

			f, err := CreateContainer(&b,
				OptCreateDeterministic(),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataGeneric, []byte("abc")),
					getDescriptorInput(t, DataGeneric, []byte("def")),
				),
			)
			if err != nil {
				t.Fatal(err)
			}

			if err := f.DeleteObject(tt.id, tt.opts...); err != nil {
				t.Fatal(err)
			}

			if err := f.AddObject(getDescriptorInput(t, DataGeneric, []byte("ghi"))); err != nil {
				t.Fatal(err)
			}

			g := goldie.New(t, goldie.WithTestNameForDir(true))
			g.Assert(t, tt.name, b.Bytes())
		})
	}
}
