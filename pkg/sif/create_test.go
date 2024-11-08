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
	"math"
	"os"
	"testing"
	"time"

	"github.com/sebdah/goldie/v2"
)

func TestNextAligned(t *testing.T) {
	tests := []struct {
		name       string
		offset     int64
		align      int
		wantOffset int64
		wantErr    error
	}{
		{name: "align 0 to 0", offset: 0, align: 0, wantOffset: 0},
		{name: "align 1 to 0", offset: 1, align: 0, wantOffset: 1},
		{name: "align 0 to 1024", offset: 0, align: 1024, wantOffset: 0},
		{name: "align 1 to 1024", offset: 1, align: 1024, wantOffset: 1024},
		{name: "align 1023 to 1024", offset: 1023, align: 1024, wantOffset: 1024},
		{name: "align 1024 to 1024", offset: 1024, align: 1024, wantOffset: 1024},
		{name: "align 1025 to 1024", offset: 1025, align: 1024, wantOffset: 2048},
		{name: "align max to 1024", offset: math.MaxInt64, align: 1024, wantErr: errAlignmentOverflow},
		{name: "align max to max", offset: math.MaxInt64, align: math.MaxInt - 1, wantErr: errAlignmentOverflow},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			offset, err := nextAligned(tt.offset, tt.align)
			if got, want := err, tt.wantErr; !errors.Is(got, want) {
				t.Errorf("got error %v, want %v", got, want)
			}
			if got, want := offset, tt.wantOffset; got != want {
				t.Errorf("got offset %v, want %v", got, want)
			}
		})
	}
}

func TestCreateContainer(t *testing.T) {
	tests := []struct {
		name    string
		opts    []CreateOpt
		wantErr error
	}{
		{
			name: "ErrInsufficientCapacity",
			opts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithDescriptorCapacity(0),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataGeneric, []byte{0xfa, 0xce}),
				),
			},
			wantErr: errInsufficientCapacity,
		},
		{
			name: "Empty",
			opts: []CreateOpt{
				OptCreateDeterministic(),
			},
		},
		{
			name: "EmptyLaunchScript",
			opts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithLaunchScript("#!/usr/bin/env launch-script\n"),
			},
		},
		{
			name: "EmptyWithID",
			opts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithID("de170c43-36ab-44a8-bca9-1ea1a070a274"),
			},
		},
		{
			name: "EmptyWithTime",
			opts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithTime(time.Unix(946702800, 0)),
			},
		},
		{
			name: "EmptyCloseOnUnload",
			opts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithCloseOnUnload(true),
			},
		},
		{
			name: "EmptyDescriptorLimitedCapacity",
			opts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithDescriptorCapacity(1),
			},
		},
		{
			name: "OneDescriptor",
			opts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataGeneric, []byte{0xfa, 0xce}),
				),
			},
		},
		{
			name: "TwoDescriptors",
			opts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataGeneric, []byte{0xfa, 0xce}),
					getDescriptorInput(t, DataPartition, []byte{0xfe, 0xed},
						OptPartitionMetadata(FsSquash, PartPrimSys, "386"),
					),
				),
			},
		},
		{
			name: "TwoDescriptorsNotAligned",
			opts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataGeneric, []byte{0xfa, 0xce},
						OptObjectAlignment(0),
					),
					getDescriptorInput(t, DataPartition, []byte{0xfe, 0xed},
						OptPartitionMetadata(FsSquash, PartPrimSys, "386"),
						OptObjectAlignment(0),
					),
				),
			},
		},
		{
			name: "TwoDescriptorsAligned",
			opts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataGeneric, []byte{0xfa, 0xce},
						OptObjectAlignment(4),
					),
					getDescriptorInput(t, DataPartition, []byte{0xfe, 0xed},
						OptPartitionMetadata(FsSquash, PartPrimSys, "386"),
						OptObjectAlignment(4),
					),
				),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var b Buffer

			f, err := CreateContainer(&b, tt.opts...)

			if got, want := err, tt.wantErr; !errors.Is(got, want) {
				t.Fatalf("got error %v, want %v", got, want)
			}

			if err == nil {
				if err := f.UnloadContainer(); err != nil {
					t.Error(err)
				}

				g := goldie.New(t, goldie.WithTestNameForDir(true))
				g.Assert(t, tt.name, b.Bytes())
			}
		})
	}
}

func TestCreateContainerAtPath(t *testing.T) {
	tests := []struct {
		name    string
		opts    []CreateOpt
		wantErr error
	}{
		{
			name: "ErrDescriptorCapacityNotSupported",
			opts: []CreateOpt{
				OptCreateWithDescriptorCapacity(math.MaxUint32),
			},
			wantErr: errDescriptorCapacityNotSupported,
		},
		{
			name: "ErrInsufficientCapacity",
			opts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithDescriptorCapacity(0),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataGeneric, []byte{0xfa, 0xce}),
				),
			},
			wantErr: errInsufficientCapacity,
		},
		{
			name: "Empty",
			opts: []CreateOpt{
				OptCreateDeterministic(),
			},
		},
		{
			name: "EmptyDescriptorLimitedCapacity",
			opts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithDescriptorCapacity(1),
			},
		},
		{
			name: "OneDescriptor",
			opts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataGeneric, []byte{0xfa, 0xce}),
				),
			},
		},
		{
			name: "TwoDescriptors",
			opts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataGeneric, []byte{0xfa, 0xce}),
					getDescriptorInput(t, DataPartition, []byte{0xfe, 0xed},
						OptPartitionMetadata(FsSquash, PartPrimSys, "386"),
					),
				),
			},
		},
		{
			name: "TwoDescriptorsNotAligned",
			opts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataGeneric, []byte{0xfa, 0xce},
						OptObjectAlignment(0),
					),
					getDescriptorInput(t, DataPartition, []byte{0xfe, 0xed},
						OptPartitionMetadata(FsSquash, PartPrimSys, "386"),
						OptObjectAlignment(0),
					),
				),
			},
		},
		{
			name: "TwoDescriptorsAligned",
			opts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataGeneric, []byte{0xfa, 0xce},
						OptObjectAlignment(4),
					),
					getDescriptorInput(t, DataPartition, []byte{0xfe, 0xed},
						OptPartitionMetadata(FsSquash, PartPrimSys, "386"),
						OptObjectAlignment(4),
					),
				),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tf, err := os.CreateTemp("", "sif-test-*")
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(tf.Name())
			tf.Close()

			f, err := CreateContainerAtPath(tf.Name(), tt.opts...)

			if got, want := err, tt.wantErr; !errors.Is(got, want) {
				t.Fatalf("got error %v, want %v", got, want)
			}

			if err == nil {
				if err := f.UnloadContainer(); err != nil {
					t.Error(err)
				}

				b, err := os.ReadFile(tf.Name())
				if err != nil {
					t.Fatal(err)
				}

				g := goldie.New(t, goldie.WithTestNameForDir(true))
				g.Assert(t, tt.name, b)
			}
		})
	}
}
