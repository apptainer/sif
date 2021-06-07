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
	"runtime"
	"testing"

	uuid "github.com/satori/go.uuid"
)

const (
	headerLen = 128
	descrLen  = 585

	testObjContainer = "testdata/test-obj-container.sif"
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
	var header Header
	var descr Descriptor

	if hdrlen := binary.Size(header); hdrlen != headerLen {
		t.Errorf("expecting global header size of %d, got %d", headerLen, hdrlen)
	}

	if desclen := binary.Size(descr); desclen != descrLen {
		t.Errorf("expecting descriptor size of %d, got %d", descrLen, desclen)
	}
}

func TestCreateContainer(t *testing.T) {
	id, err := uuid.NewV4()
	if err != nil {
		t.Fatalf("id generation failed: %v", err)
	}

	// general info for the new SIF file creation
	cinfo := CreateInfo{
		Pathname:   "testdata/testcontainer.sif",
		Launchstr:  HdrLaunch,
		Sifversion: HdrVersion,
		ID:         id,
	}

	// test container creation without any input descriptors
	if _, err := CreateContainer(cinfo); err != nil {
		t.Error("CreateContainer(cinfo): should allow empty input descriptor list")
	}

	// data we need to create a definition file descriptor
	definput := DescriptorInput{
		Datatype: DataDeffile,
		Groupid:  DescrDefaultGroup,
		Link:     DescrUnusedLink,
		Fname:    "testdata/busybox.def",
	}

	// open up the data object file for this descriptor
	defHandle, err := os.Open(definput.Fname)
	if err != nil {
		t.Errorf("CreateContainer(cinfo): read data object file: %s", err)
	}
	defer defHandle.Close()

	definput.Fp = defHandle

	fi, err := defHandle.Stat()
	if err != nil {
		t.Errorf("CreateContainer(cinfo): can't stat definition file: %s", err)
	}
	definput.Size = fi.Size()

	// add this descriptor input element to creation descriptor slice
	cinfo.InputDescr = append(cinfo.InputDescr, definput)

	// data we need to create a system partition descriptor
	parinput := DescriptorInput{
		Datatype:  DataPartition,
		Groupid:   DescrDefaultGroup,
		Link:      DescrUnusedLink,
		Fname:     "testdata/busybox.squash",
		Alignment: 1048576, // Test an aggressive alignment requirement
	}
	// open up the data object file for this descriptor
	partHandle, err := os.Open(parinput.Fname)
	if err != nil {
		t.Errorf("CreateContainer(cinfo): read data object file: %s", err)
	}
	defer partHandle.Close()

	parinput.Fp = partHandle

	fi, err = partHandle.Stat()
	if err != nil {
		t.Errorf("CreateContainer(cinfo): can't stat partition file: %s", err)
	}
	parinput.Size = fi.Size()

	err = parinput.SetPartExtra(FsSquash, PartPrimSys, GetSIFArch(runtime.GOARCH))
	if err != nil {
		t.Errorf("CreateContainer(cinfo): can't set extra info: %s", err)
	}

	// add this descriptor input element to creation descriptor slice
	cinfo.InputDescr = append(cinfo.InputDescr, parinput)

	// test container creation with two partition input descriptors
	if _, err := CreateContainer(cinfo); err != nil {
		t.Errorf("CreateContainer(cinfo): CreateContainer(): %s", err)
	}
}

func TestAddDelObject(t *testing.T) {
	// data we need to create a dummy labels descriptor
	labinput := DescriptorInput{
		Datatype: DataLabels,
		Groupid:  DescrDefaultGroup,
		Link:     DescrUnusedLink,
		Fname:    "dummyLabels",
		Data:     []byte{'L', 'A', 'B', 'E', 'L'},
	}
	labinput.Size = int64(binary.Size(labinput.Data))

	// data we need to create a system partition descriptor
	parinput := DescriptorInput{
		Datatype: DataPartition,
		Groupid:  DescrDefaultGroup,
		Link:     DescrUnusedLink,
		Fname:    "testdata/busybox.squash",
	}
	// open up the data object file for this descriptor
	partHandle, err := os.Open(parinput.Fname)
	if err != nil {
		t.Errorf("os.Open(parinput.Fname): unable to read data object file: %s", err)
	}
	defer partHandle.Close()

	parinput.Fp = partHandle

	fi, err := partHandle.Stat()
	if err != nil {
		t.Errorf("CreateContainer(cinfo): can't stat partition file: %s", err)
	}
	parinput.Size = fi.Size()

	err = parinput.SetPartExtra(FsSquash, PartPrimSys, GetSIFArch(runtime.GOARCH))
	if err != nil {
		t.Errorf("CreateContainer(cinfo): can't stat partition file: %s", err)
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
	fimg, err := LoadContainer(testObjContainer, false)
	if err != nil {
		t.Errorf("failed to load test container: %s: %s", testObjContainer, err)
	}

	// add new data object 'DataLabels' to SIF file
	if err = fimg.AddObject(labinput); err != nil {
		t.Errorf("fimg.AddObject(): %s", err)
	}

	// add new data object 'DataPartition' to SIF file
	if err = fimg.AddObject(parinput); err != nil {
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
	fimg, err = LoadContainer(testObjContainer, false)
	if err != nil {
		t.Errorf("failed to load test container: %s: %s", testObjContainer, err)
	}

	// test data object deletation
	if err := fimg.DeleteObject(1, DelZero); err != nil {
		t.Errorf("fimg.DeleteObject(1, DelZero): %s", err)
	}

	// test data object deletation
	if err := fimg.DeleteObject(2, DelCompact); err != nil {
		t.Errorf("fimg.DeleteObject(2, DelZero): %s", err)
	}

	// unload the test container
	if err = fimg.UnloadContainer(); err != nil {
		t.Errorf("UnloadContainer(fimg): %s", err)
	}
}

func TestAddObjectPipe(t *testing.T) {
	// the code treats a DescriptorInput with a non-nil Fp field and
	// a Size == 0 field as a "pipe"
	payload := []byte("0123456789")
	input := DescriptorInput{
		Datatype: DataGeneric,
		Groupid:  DescrDefaultGroup,
		Link:     DescrUnusedLink,
		Fname:    "generic",
		Fp:       bytes.NewBuffer(payload),
		Size:     0,
	}

	fimg := &FileImage{
		Header: Header{
			Dfree:  1,
			Dtotal: 1,
		},
		Fp:       &mockSifReadWriter{},
		DescrArr: make([]Descriptor, 1),
	}

	if err := fimg.AddObject(input); err != nil {
		t.Errorf("fimg.AddObject(...): %s", err)
	}

	if expected, actual := int64(0), fimg.Header.Dfree; actual != expected {
		t.Errorf("after calling fimg.AddObject(...), unexpected value in fimg.Header.Dfree: expected=%d actual=%d",
			expected, actual)
	}

	if expected, actual := "pipe1", fimg.DescrArr[0].GetName(); actual != expected {
		t.Errorf("after calling fimg.AddObject(...), unexpected value from fimg.DescrArr[0].GetName(): expected=%s actual=%s",
			expected, actual)
	}

	if expected, actual := int64(len(payload)), fimg.DescrArr[0].Filelen; actual != expected {
		t.Errorf("after calling fimg.AddObject(...), unexpected value from fimg.DescrArr[0].Filelen: expected=%d actual=%d",
			expected, actual)
	}

	if expected, actual := input.Datatype, fimg.DescrArr[0].Datatype; actual != expected {
		t.Errorf("after calling fimg.AddObject(...), unexpected value from fimg.DescrArr[0].Datatype: expected=%d actual=%d",
			expected, actual)
	}

	if expected, actual := input.Groupid, fimg.DescrArr[0].Groupid; actual != expected {
		t.Errorf("after calling fimg.AddObject(...), unexpected value from fimg.DescrArr[0].Groupid: expected=%d actual=%d",
			expected, actual)
	}

	if expected, actual := input.Link, fimg.DescrArr[0].Link; actual != expected {
		t.Errorf("after calling fimg.AddObject(...), unexpected value from fimg.DescrArr[0].Groupid: expected=%d actual=%d",
			expected, actual)
	}
}

func TestSetPrimPart(t *testing.T) {
	// the code treats a DescriptorInput with a non-nil Fp field and
	// a Size == 0 field as a "pipe"
	payload := []byte("0123456789")
	inputs := []DescriptorInput{
		{
			Datatype: DataPartition,
			Groupid:  DescrDefaultGroup,
			Link:     DescrUnusedLink,
			Fname:    "generic",
			Fp:       bytes.NewBuffer(payload),
			Size:     0,
		},
		{
			Datatype: DataPartition,
			Groupid:  DescrDefaultGroup,
			Link:     DescrUnusedLink,
			Fname:    "generic",
			Fp:       bytes.NewBuffer(payload),
			Size:     0,
		},
	}

	fimg := &FileImage{
		Header: Header{
			Dfree:  int64(len(inputs)),
			Dtotal: int64(len(inputs)),
		},
		Fp:       &mockSifReadWriter{},
		DescrArr: make([]Descriptor, len(inputs)),
	}

	for i := range inputs {
		if err := fimg.AddObject(inputs[i]); err != nil {
			t.Fatalf("fimg.AddObject(...): %s", err)
		}

		partition := Partition{
			Fstype:   FsRaw,
			Parttype: PartSystem,
		}
		buffer := bytes.Buffer{}
		if err := binary.Write(&buffer, binary.LittleEndian, partition); err != nil {
			t.Fatalf("while serializing partition info: %s", err)
		}
		fimg.DescrArr[i].SetExtra(buffer.Bytes())
	}

	// the first pass tests that the primary partition can be set;
	// the second pass tests that the primary can be changed.
	for i := range inputs {
		if err := fimg.SetPrimPart(fimg.DescrArr[i].ID); err != nil {
			t.Error("fimg.SetPrimPart(...):", err)
		}

		if part, idx, err := fimg.GetPartPrimSys(); err != nil {
			t.Error("fimg.GetPartPrimSys():", err)
		} else if expected, actual := i, idx; actual != expected {
			t.Errorf("after calling fimg.SetPrimPart(...), unexpected value from fimg.GetPartPrimSys(): expected=%d actual=%d",
				expected, actual)
		} else if expected, actual := fimg.DescrArr[i].ID, part.ID; actual != expected {
			t.Errorf("after calling fimg.SetPrimPart(...), unexpected value from fimg.GetPartPrimSys(): expected=%d actual=%d",
				expected, actual)
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

	d, err := os.OpenFile(toFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0777)
	if err != nil {
		return err
	}
	defer d.Close()

	_, err = io.Copy(d, s)

	return err
}
