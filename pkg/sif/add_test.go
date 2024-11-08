// Copyright (c) Contributors to the Apptainer project, established as
//   Apptainer a Series of LF Projects LLC.
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// Copyright (c) 2018-2023, Sylabs Inc. All rights reserved.
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

func TestAddObject(t *testing.T) {
	tests := []struct {
		name       string
		createOpts []CreateOpt
		di         DescriptorInput
		opts       []AddOpt
		wantErr    error
	}{
		{
			name: "ErrInsufficientCapacity",
			createOpts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithDescriptorCapacity(0),
			},
			di:      getDescriptorInput(t, DataGeneric, []byte{0xfe, 0xed}),
			wantErr: errInsufficientCapacity,
		},
		{
			name: "ErrPrimaryPartition",
			createOpts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataPartition, []byte{0xfa, 0xce},
						OptPartitionMetadata(FsSquash, PartPrimSys, "386"),
					),
				),
			},
			di: getDescriptorInput(t, DataPartition, []byte{0xfe, 0xed},
				OptPartitionMetadata(FsSquash, PartPrimSys, "amd64"),
			),
			wantErr: errPrimaryPartition,
		},
		{
			name: "Deterministic",
			createOpts: []CreateOpt{
				OptCreateWithID("de170c43-36ab-44a8-bca9-1ea1a070a274"),
				OptCreateWithTime(time.Unix(946702800, 0)),
			},
			di: getDescriptorInput(t, DataGeneric, []byte{0xfa, 0xce}),
			opts: []AddOpt{
				OptAddDeterministic(),
			},
		},
		{
			name: "WithTime",
			createOpts: []CreateOpt{
				OptCreateDeterministic(),
			},
			di: getDescriptorInput(t, DataGeneric, []byte{0xfa, 0xce}),
			opts: []AddOpt{
				OptAddWithTime(time.Unix(946702800, 0)),
			},
		},
		{
			name: "Empty",
			createOpts: []CreateOpt{
				OptCreateDeterministic(),
			},
			di: getDescriptorInput(t, DataGeneric, []byte{0xfa, 0xce}),
		},
		{
			name: "EmptyNotAligned",
			createOpts: []CreateOpt{
				OptCreateDeterministic(),
			},
			di: getDescriptorInput(t, DataGeneric, []byte{0xfa, 0xce},
				OptObjectAlignment(0),
			),
		},
		{
			name: "EmptyAligned",
			createOpts: []CreateOpt{
				OptCreateDeterministic(),
			},
			di: getDescriptorInput(t, DataGeneric, []byte{0xfa, 0xce},
				OptObjectAlignment(128),
			),
		},
		{
			name: "NotEmpty",
			createOpts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataGeneric, []byte{0xfa, 0xce}),
				),
			},
			di: getDescriptorInput(t, DataPartition, []byte{0xfe, 0xed},
				OptPartitionMetadata(FsSquash, PartPrimSys, "386"),
			),
		},
		{
			name: "NotEmptyNotAligned",
			createOpts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataGeneric, []byte{0xfa, 0xce}),
				),
			},
			di: getDescriptorInput(t, DataPartition, []byte{0xfe, 0xed},
				OptPartitionMetadata(FsSquash, PartPrimSys, "386"),
				OptObjectAlignment(0),
			),
		},
		{
			name: "NotEmptyAligned",
			createOpts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataGeneric, []byte{0xfa, 0xce}),
				),
			},
			di: getDescriptorInput(t, DataPartition, []byte{0xfe, 0xed},
				OptPartitionMetadata(FsSquash, PartPrimSys, "386"),
				OptObjectAlignment(128),
			),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var b Buffer

			f, err := CreateContainer(&b, tt.createOpts...)
			if err != nil {
				t.Fatal(err)
			}

			if got, want := f.AddObject(tt.di, tt.opts...), tt.wantErr; !errors.Is(got, want) {
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
