// Copyright (c) 2018-2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package sif

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

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
		name string
		opts []CreateOpt
	}{
		{
			name: "Empty",
			opts: []CreateOpt{
				OptCreateWithID(testID),
				OptCreateWithTime(testTime),
			},
		},
		{
			name: "EmptyCloseOnUnload",
			opts: []CreateOpt{
				OptCreateWithID(testID),
				OptCreateWithTime(testTime),
				OptCreateWithCloseOnUnload(true),
			},
		},
		{
			name: "EmptyDescriptorLimitedCapacity",
			opts: []CreateOpt{
				OptCreateWithID(testID),
				OptCreateWithTime(testTime),
				OptCreateWithDescriptorCapacity(1),
			},
		},
		{
			name: "OneDescriptor",
			opts: []CreateOpt{
				OptCreateWithID(testID),
				OptCreateWithTime(testTime),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataGeneric, []byte{0xfa, 0xce},
						OptObjectTime(testTime),
					),
				),
			},
		},
		{
			name: "TwoDescriptors",
			opts: []CreateOpt{
				OptCreateWithID(testID),
				OptCreateWithTime(testTime),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataGeneric, []byte{0xfa, 0xce},
						OptObjectTime(testTime),
					),
					getDescriptorInput(t, DataPartition, []byte{0xfe, 0xed},
						OptObjectTime(testTime),
						OptPartitionMetadata(FsSquash, PartPrimSys, "386"),
					),
				),
			},
		},
		{
			name: "TwoDescriptorsNotAligned",
			opts: []CreateOpt{
				OptCreateWithID(testID),
				OptCreateWithTime(testTime),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataGeneric, []byte{0xfa, 0xce},
						OptObjectTime(testTime),
						OptObjectAlignment(0),
					),
					getDescriptorInput(t, DataPartition, []byte{0xfe, 0xed},
						OptObjectTime(testTime),
						OptPartitionMetadata(FsSquash, PartPrimSys, "386"),
						OptObjectAlignment(0),
					),
				),
			},
		},
		{
			name: "TwoDescriptorsAligned",
			opts: []CreateOpt{
				OptCreateWithID(testID),
				OptCreateWithTime(testTime),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataGeneric, []byte{0xfa, 0xce},
						OptObjectTime(testTime),
						OptObjectAlignment(4),
					),
					getDescriptorInput(t, DataPartition, []byte{0xfe, 0xed},
						OptObjectTime(testTime),
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
			if err != nil {
				t.Fatal(err)
			}

			if err := f.UnloadContainer(); err != nil {
				t.Fatal(err)
			}

			g := goldie.New(t, goldie.WithTestNameForDir(true))
			g.Assert(t, tt.name, b.Bytes())
		})
	}
}

func TestCreateContainerAtPath(t *testing.T) {
	tests := []struct {
		name string
		opts []CreateOpt
	}{
		{
			name: "Empty",
			opts: []CreateOpt{
				OptCreateWithID(testID),
				OptCreateWithTime(testTime),
			},
		},
		{
			name: "EmptyDescriptorLimitedCapacity",
			opts: []CreateOpt{
				OptCreateWithID(testID),
				OptCreateWithTime(testTime),
				OptCreateWithDescriptorCapacity(1),
			},
		},
		{
			name: "OneDescriptor",
			opts: []CreateOpt{
				OptCreateWithID(testID),
				OptCreateWithTime(testTime),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataGeneric, []byte{0xfa, 0xce},
						OptObjectTime(testTime),
					),
				),
			},
		},
		{
			name: "TwoDescriptors",
			opts: []CreateOpt{
				OptCreateWithID(testID),
				OptCreateWithTime(testTime),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataGeneric, []byte{0xfa, 0xce},
						OptObjectTime(testTime),
					),
					getDescriptorInput(t, DataPartition, []byte{0xfe, 0xed},
						OptObjectTime(testTime),
						OptPartitionMetadata(FsSquash, PartPrimSys, "386"),
					),
				),
			},
		},
		{
			name: "TwoDescriptorsNotAligned",
			opts: []CreateOpt{
				OptCreateWithID(testID),
				OptCreateWithTime(testTime),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataGeneric, []byte{0xfa, 0xce},
						OptObjectTime(testTime),
						OptObjectAlignment(0),
					),
					getDescriptorInput(t, DataPartition, []byte{0xfe, 0xed},
						OptObjectTime(testTime),
						OptPartitionMetadata(FsSquash, PartPrimSys, "386"),
						OptObjectAlignment(0),
					),
				),
			},
		},
		{
			name: "TwoDescriptorsAligned",
			opts: []CreateOpt{
				OptCreateWithID(testID),
				OptCreateWithTime(testTime),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataGeneric, []byte{0xfa, 0xce},
						OptObjectTime(testTime),
						OptObjectAlignment(4),
					),
					getDescriptorInput(t, DataPartition, []byte{0xfe, 0xed},
						OptObjectTime(testTime),
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
			if err != nil {
				t.Fatal(err)
			}

			if err := f.UnloadContainer(); err != nil {
				t.Fatal(err)
			}

			b, err := os.ReadFile(tf.Name())
			if err != nil {
				t.Fatal(err)
			}

			g := goldie.New(t, goldie.WithTestNameForDir(true))
			g.Assert(t, tt.name, b)
		})
	}
}

func TestAddObject(t *testing.T) {
	tests := []struct {
		name       string
		createOpts []CreateOpt
		di         DescriptorInput
		wantErr    error
	}{
		{
			name: "ErrInsufficientCapacity",
			createOpts: []CreateOpt{
				OptCreateWithID(testID),
				OptCreateWithTime(testTime),
				OptCreateWithDescriptorCapacity(0),
			},
			di: getDescriptorInput(t, DataGeneric, []byte{0xfe, 0xed},
				OptObjectTime(testTime),
			),
			wantErr: errInsufficientCapacity,
		},
		{
			name: "ErrPrimaryPartition",
			createOpts: []CreateOpt{
				OptCreateWithID(testID),
				OptCreateWithTime(testTime),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataPartition, []byte{0xfa, 0xce},
						OptObjectTime(testTime),
						OptPartitionMetadata(FsSquash, PartPrimSys, "386"),
					),
				),
			},
			di: getDescriptorInput(t, DataPartition, []byte{0xfe, 0xed},
				OptObjectTime(testTime),
				OptPartitionMetadata(FsSquash, PartPrimSys, "amd64"),
			),
			wantErr: errPrimaryPartition,
		},
		{
			name: "Empty",
			createOpts: []CreateOpt{
				OptCreateWithID(testID),
				OptCreateWithTime(testTime),
			},
			di: getDescriptorInput(t, DataGeneric, []byte{0xfa, 0xce},
				OptObjectTime(testTime),
			),
		},
		{
			name: "EmptyNotAligned",
			createOpts: []CreateOpt{
				OptCreateWithID(testID),
				OptCreateWithTime(testTime),
			},
			di: getDescriptorInput(t, DataGeneric, []byte{0xfa, 0xce},
				OptObjectTime(testTime),
				OptObjectAlignment(0),
			),
		},
		{
			name: "EmptyAligned",
			createOpts: []CreateOpt{
				OptCreateWithID(testID),
				OptCreateWithTime(testTime),
			},
			di: getDescriptorInput(t, DataGeneric, []byte{0xfa, 0xce},
				OptObjectTime(testTime),
				OptObjectAlignment(128),
			),
		},
		{
			name: "NotEmpty",
			createOpts: []CreateOpt{
				OptCreateWithID(testID),
				OptCreateWithTime(testTime),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataGeneric, []byte{0xfa, 0xce},
						OptObjectTime(testTime),
					),
				),
			},
			di: getDescriptorInput(t, DataPartition, []byte{0xfe, 0xed},
				OptObjectTime(testTime),
				OptPartitionMetadata(FsSquash, PartPrimSys, "386"),
			),
		},
		{
			name: "NotEmptyNotAligned",
			createOpts: []CreateOpt{
				OptCreateWithID(testID),
				OptCreateWithTime(testTime),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataGeneric, []byte{0xfa, 0xce},
						OptObjectTime(testTime),
					),
				),
			},
			di: getDescriptorInput(t, DataPartition, []byte{0xfe, 0xed},
				OptObjectTime(testTime),
				OptPartitionMetadata(FsSquash, PartPrimSys, "386"),
				OptObjectAlignment(0),
			),
		},
		{
			name: "NotEmptyAligned",
			createOpts: []CreateOpt{
				OptCreateWithID(testID),
				OptCreateWithTime(testTime),
				OptCreateWithDescriptors(
					getDescriptorInput(t, DataGeneric, []byte{0xfa, 0xce},
						OptObjectTime(testTime),
					),
				),
			},
			di: getDescriptorInput(t, DataPartition, []byte{0xfe, 0xed},
				OptObjectTime(testTime),
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

			if got, want := f.AddObject(tt.di), tt.wantErr; !errors.Is(got, want) {
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

func TestAddDelObject(t *testing.T) {
	fimg, err := CreateContainer(&Buffer{})
	if err != nil {
		t.Fatal(err)
	}

	// data we need to create a dummy labels descriptor
	labinput, err := NewDescriptorInput(DataLabels, bytes.NewBufferString("LABEL"))
	if err != nil {
		t.Fatal(err)
	}

	// data we need to create a system partition descriptor
	partHandle, err := os.Open(filepath.Join("testdata", "busybox.squash"))
	if err != nil {
		t.Fatal(err)
	}
	defer partHandle.Close()
	parinput, err := NewDescriptorInput(DataPartition, partHandle,
		OptPartitionMetadata(FsSquash, PartPrimSys, "386"),
	)
	if err != nil {
		t.Fatal(err)
	}

	//
	// Add the object
	//

	// add new data object 'DataLabels' to SIF file
	if err = fimg.AddObject(labinput); err != nil {
		t.Errorf("fimg.AddObject(): %s", err)
	}

	// add new data object 'DataPartition' to SIF file
	if err = fimg.AddObject(parinput, OptAddWithTime(testTime)); err != nil {
		t.Errorf("fimg.AddObject(): %s", err)
	}

	//
	// Delete the object
	//

	// test data object deletation
	if err := fimg.DeleteObject(1, OptDeleteZero(true)); err != nil {
		t.Errorf("fimg.DeleteObject(1, DelZero): %s", err)
	}

	// test data object deletation
	if err := fimg.DeleteObject(2, OptDeleteCompact(true), OptDeleteWithTime(testTime)); err != nil {
		t.Errorf("fimg.DeleteObject(2, DelZero): %s", err)
	}

	// unload the test container
	if err = fimg.UnloadContainer(); err != nil {
		t.Errorf("UnloadContainer(fimg): %s", err)
	}
}

func TestSetPrimPart(t *testing.T) {
	payload := []byte("0123456789")

	di1, err := NewDescriptorInput(DataPartition, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}

	di2, err := NewDescriptorInput(DataPartition, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}

	inputs := []DescriptorInput{di1, di2}

	fimg := &FileImage{
		rw: &Buffer{},
		h: header{
			DescriptorsFree:  int64(len(inputs)),
			DescriptorsTotal: int64(len(inputs)),
		},
		rds:    make([]rawDescriptor, len(inputs)),
		minIDs: make(map[uint32]uint32),
	}

	for i := range inputs {
		if err := fimg.AddObject(inputs[i]); err != nil {
			t.Fatalf("fimg.AddObject(...): %s", err)
		}

		p := partition{
			Fstype:   FsRaw,
			Parttype: PartSystem,
		}
		if err := fimg.rds[i].setExtra(p); err != nil {
			t.Fatal(err)
		}
	}

	// the first pass tests that the primary partition can be set;
	// the second pass tests that the primary can be changed.
	for i := range inputs {
		if err := fimg.SetPrimPart(fimg.rds[i].ID, OptSetWithTime(testTime)); err != nil {
			t.Error("fimg.SetPrimPart(...):", err)
		}

		if part, err := fimg.getDescriptor(WithPartitionType(PartPrimSys)); err != nil {
			t.Fatal(err)
		} else if want, got := part.ID, fimg.rds[i].ID; got != want {
			t.Errorf("got ID %v, want %v", got, want)
		}
	}
}
