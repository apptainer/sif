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
	"os"
	"testing"
	"time"

	"github.com/sebdah/goldie/v2"
)

func TestNextAligned(t *testing.T) {
	cases := []struct {
		name     string
		offset   int64
		align    int
		expected int64
	}{
		{name: "align 0 to 0", offset: 0, align: 0, expected: 0},
		{name: "align 1 to 0", offset: 1, align: 0, expected: 1},
		{name: "align 0 to 1024", offset: 0, align: 1024, expected: 0},
		{name: "align 1 to 1024", offset: 1, align: 1024, expected: 1024},
		{name: "align 1023 to 1024", offset: 1023, align: 1024, expected: 1024},
		{name: "align 1024 to 1024", offset: 1024, align: 1024, expected: 1024},
		{name: "align 1025 to 1024", offset: 1025, align: 1024, expected: 2048},
	}

	for _, tc := range cases {
		actual := nextAligned(tc.offset, tc.align)
		if actual != tc.expected {
			t.Errorf("nextAligned case: %q, offset: %d, align: %d, expecting: %d, actual: %d\n",
				tc.name, tc.offset, tc.align, tc.expected, actual)
		}
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

func TestDeleteObject(t *testing.T) {
	tests := []struct {
		name       string
		createOpts []CreateOpt
		id         uint32
		opts       []DeleteOpt
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
			name: "Zero",
			createOpts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataGeneric, []byte{0xfa, 0xce}),
				),
			},
			id: 1,
			opts: []DeleteOpt{
				OptDeleteZero(true),
			},
		},
		{
			name: "Compact",
			createOpts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataGeneric, []byte{0xfa, 0xce}),
				),
			},
			id: 1,
			opts: []DeleteOpt{
				OptDeleteCompact(true),
			},
		},
		{
			name: "ZeroCompact",
			createOpts: []CreateOpt{
				OptCreateDeterministic(),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataGeneric, []byte{0xfa, 0xce}),
				),
			},
			id: 1,
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
			id: 1,
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
			id: 1,
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
			id: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var b Buffer

			f, err := CreateContainer(&b, tt.createOpts...)
			if err != nil {
				t.Fatal(err)
			}

			if got, want := f.DeleteObject(tt.id, tt.opts...), tt.wantErr; !errors.Is(got, want) {
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
