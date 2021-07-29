// Copyright (c) 2018-2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package sif

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"testing"
)

const (
	headerLen = 128
	descrLen  = 585
)

func TestNextAligned(t *testing.T) {
	cases := []struct {
		name     string
		offset   int64
		align    int
		expected int64
	}{
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

func TestDataStructs(t *testing.T) {
	var h header
	var descr rawDescriptor

	if hdrlen := binary.Size(h); hdrlen != headerLen {
		t.Errorf("expecting global header size of %d, got %d", headerLen, hdrlen)
	}

	if desclen := binary.Size(descr); desclen != descrLen {
		t.Errorf("expecting descriptor size of %d, got %d", descrLen, desclen)
	}
}

func TestCreateContainer(t *testing.T) {
	f, err := os.CreateTemp("", "sif-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Close()

	// test container creation without any input descriptors
	fimg, err := CreateContainer(f.Name())
	if err != nil {
		t.Fatalf("failed to create container: %v", err)
	}

	if err := fimg.UnloadContainer(); err != nil {
		t.Errorf("failed to unload container: %v", err)
	}

	defHandle, err := os.Open(filepath.Join("testdata", "busybox.def"))
	if err != nil {
		t.Fatal(err)
	}
	defer defHandle.Close()

	definput, err := NewDescriptorInput(DataDeffile, defHandle, OptGroupID(1))
	if err != nil {
		t.Fatal(err)
	}

	partHandle, err := os.Open(filepath.Join("testdata", "busybox.squash"))
	if err != nil {
		t.Fatal(err)
	}
	defer partHandle.Close()

	parinput, err := NewDescriptorInput(DataPartition, partHandle,
		OptObjectAlignment(1048576), // Test an aggressive alignment requirement
		OptPartitionMetadata(FsSquash, PartPrimSys, "386"),
	)
	if err != nil {
		t.Fatal(err)
	}

	// test container creation with two partition input descriptors
	fimg, err = CreateContainer(f.Name(),
		OptCreateWithDescriptors(definput, parinput),
		OptCreateWithTime(testTime),
	)
	if err != nil {
		t.Fatalf("failed to create container: %v", err)
	}

	if err := fimg.UnloadContainer(); err != nil {
		t.Errorf("failed to unload container: %v", err)
	}
}

func TestAddDelObject(t *testing.T) {
	f, err := os.CreateTemp("", "sif-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Close()

	testObjContainer := f.Name()

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

	// copy a test container, so we dont modify the existing container
	err = cpFile("testdata/testcontainer1.sif", testObjContainer)
	if err != nil {
		t.Fatalf("failed to copy test containers: %s", err)
	}

	//
	// Add the object
	//

	// load the test container
	fimg, err := LoadContainerFromPath(testObjContainer)
	if err != nil {
		t.Errorf("failed to load test container: %s: %s", testObjContainer, err)
	}

	// add new data object 'DataLabels' to SIF file
	if err = fimg.AddObject(labinput); err != nil {
		t.Errorf("fimg.AddObject(): %s", err)
	}

	// add new data object 'DataPartition' to SIF file
	if err = fimg.AddObject(parinput, OptAddWithTime(testTime)); err != nil {
		t.Errorf("fimg.AddObject(): %s", err)
	}

	// unload the test container
	if err = fimg.UnloadContainer(); err != nil {
		t.Errorf("UnloadContainer(fimg): %s", err)
	}

	//
	// Delete the object
	//

	// load the test container
	fimg, err = LoadContainerFromPath(testObjContainer)
	if err != nil {
		t.Errorf("failed to load test container: %s: %s", testObjContainer, err)
	}

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
			Dfree:  int64(len(inputs)),
			Dtotal: int64(len(inputs)),
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
		if err := fimg.SetPrimPart(fimg.rds[i].ID); err != nil {
			t.Error("fimg.SetPrimPart(...):", err)
		}

		if part, err := fimg.getDescriptor(WithPartitionType(PartPrimSys)); err != nil {
			t.Fatal(err)
		} else if want, got := part.ID, fimg.rds[i].ID; got != want {
			t.Errorf("got ID %v, want %v", got, want)
		}
	}
}

// cpFile is a simple function to copy the test container to a file.
func cpFile(fromFile, toFile string) error {
	s, err := os.Open(fromFile)
	if err != nil {
		return err
	}
	defer s.Close()

	d, err := os.OpenFile(toFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o777)
	if err != nil {
		return err
	}
	defer d.Close()

	_, err = io.Copy(d, s)

	return err
}
