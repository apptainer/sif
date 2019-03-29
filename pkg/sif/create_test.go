// Copyright (c) 2018, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package sif

import (
	"bytes"
	"encoding/binary"
	"os"
	"runtime"
	"testing"

	uuid "github.com/satori/go.uuid"
)

const (
	headerLen = 128
	descrLen  = 585
)

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
	var err error

	// general info for the new SIF file creation
	cinfo := CreateInfo{
		Pathname:   "testdata/testcontainer.sif",
		Launchstr:  HdrLaunch,
		Sifversion: HdrVersion,
		ID:         uuid.NewV4(),
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
		Fname:    "testdata/busybox.deffile",
	}

	// open up the data object file for this descriptor
	defHandle, err := os.Open(definput.Fname)
	if err != nil {
		t.Error("CreateContainer(cinfo): read data object file:", err)
	}
	defer defHandle.Close()

	definput.Fp = defHandle

	fi, err := defHandle.Stat()
	if err != nil {
		t.Error("CreateContainer(cinfo): can't stat definition file", err)
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
		Alignment: 1048576, // Test an aggresive alignment requirement
	}
	// open up the data object file for this descriptor
	partHandle, err := os.Open(parinput.Fname)
	if err != nil {
		t.Error("CreateContainer(cinfo): read data object file:", err)
	}
	defer partHandle.Close()

	parinput.Fp = partHandle

	fi, err = partHandle.Stat()
	if err != nil {
		t.Error("CreateContainer(cinfo): can't stat partition file", err)
	}
	parinput.Size = fi.Size()

	err = parinput.SetPartExtra(FsSquash, PartPrimSys, GetSIFArch(runtime.GOARCH))
	if err != nil {
		t.Error("CreateContainer(cinfo): can't set extra info", err)
	}

	// add this descriptor input element to creation descriptor slice
	cinfo.InputDescr = append(cinfo.InputDescr, parinput)

	// test container creation with two partition input descriptors
	if _, err := CreateContainer(cinfo); err != nil {
		t.Error("CreateContainer(cinfo): CreateContainer():", err)
	}
}

func TestAddObject(t *testing.T) {
	var err error

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
		t.Error("CreateContainer(cinfo): read data object file:", err)
	}
	defer partHandle.Close()

	parinput.Fp = partHandle

	fi, err := partHandle.Stat()
	if err != nil {
		t.Error("CreateContainer(cinfo): can't stat partition file", err)
	}
	parinput.Size = fi.Size()

	err = parinput.SetPartExtra(FsSquash, PartPrimSys, GetSIFArch(runtime.GOARCH))
	if err != nil {
		t.Error("CreateContainer(cinfo): can't stat partition file", err)
	}

	// load the test container
	fimg, err := LoadContainer("testdata/testcontainer1.sif", false)
	if err != nil {
		t.Error("LoadContainer(testdata/testcontainer1.sif, false):", err)
	}

	// add new data object 'DataLabels' to SIF file
	if err = fimg.AddObject(labinput); err != nil {
		t.Error("fimg.AddObject():", err)
	}

	// add new data object 'DataPartition' to SIF file
	if err = fimg.AddObject(parinput); err != nil {
		t.Error("fimg.AddObject():", err)
	}

	// unload the test container
	if err = fimg.UnloadContainer(); err != nil {
		t.Error("UnloadContainer(fimg):", err)
	}
}

func TestAddObjectPipe(t *testing.T) {
	var err error

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

	if err = fimg.AddObject(input); err != nil {
		t.Error("fimg.AddObject(...):", err)
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

func TestDeleteObject(t *testing.T) {
	// load the test container
	fimg, err := LoadContainer("testdata/testcontainer1.sif", false)
	if err != nil {
		t.Error("LoadContainer(testdata/testcontainer1.sif, false):", err)
	}

	// test data object deletation
	if err := fimg.DeleteObject(1, DelZero); err != nil {
		t.Error(`fimg.DeleteObject(1, DelZero):`, err)
	}

	// test data object deletation
	if err := fimg.DeleteObject(2, DelCompact); err != nil {
		t.Error(`fimg.DeleteObject(2, DelZero):`, err)
	}

	// unload the test container
	if err = fimg.UnloadContainer(); err != nil {
		t.Error("UnloadContainer(fimg):", err)
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
