// Copyright (c) 2018, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package sif

import (
	"encoding/binary"
	"github.com/satori/go.uuid"
	"os"
	"testing"
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
		Arch:       HdrArchAMD64,
		ID:         uuid.NewV4(),
	}

	// test container creation without any input descriptors
	if err := CreateContainer(cinfo); err == nil {
		t.Error("CreateContainer(cinfo): should not allow empty input descriptor list")
	}

	// data we need to create a definition file descriptor
	definput := DescriptorInput{
		Datatype: DataDeffile,
		Groupid:  DescrDefaultGroup,
		Link:     DescrUnusedLink,
		Fname:    "testdata/busybox.deffile",
	}
	// open up the data object file for this descriptor
	if definput.Fp, err = os.Open(definput.Fname); err != nil {
		t.Error("CreateContainer(cinfo): read data object file:", err)
	}
	defer definput.Fp.Close()

	fi, err := definput.Fp.Stat()
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
	if parinput.Fp, err = os.Open(parinput.Fname); err != nil {
		t.Error("CreateContainer(cinfo): read data object file:", err)
	}
	defer parinput.Fp.Close()

	fi, err = parinput.Fp.Stat()
	if err != nil {
		t.Error("CreateContainer(cinfo): can't stat partition file", err)
	}
	parinput.Size = fi.Size()

	// extra data needed for the creation of a partition descriptor
	pinfo := Partition{
		Fstype:   FsSquash,
		Parttype: PartSystem,
	}

	// serialize the partition data for integration with the base descriptor input
	if err := binary.Write(&parinput.Extra, binary.LittleEndian, pinfo); err != nil {
		t.Error("CreateContainer(cinfo): serialize pinfo:", err)
	}

	// add this descriptor input element to creation descriptor slice
	cinfo.InputDescr = append(cinfo.InputDescr, parinput)

	// test container creation with two partition input descriptors
	if err := CreateContainer(cinfo); err != nil {
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
	if parinput.Fp, err = os.Open(parinput.Fname); err != nil {
		t.Error("CreateContainer(cinfo): read data object file:", err)
	}
	defer parinput.Fp.Close()

	fi, err := parinput.Fp.Stat()
	if err != nil {
		t.Error("CreateContainer(cinfo): can't stat partition file", err)
	}
	parinput.Size = fi.Size()

	// extra data needed for the creation of a partition descriptor
	pinfo := Partition{
		Fstype:   FsSquash,
		Parttype: PartSystem,
	}

	// serialize the partition data for integration with the base descriptor input
	if err := binary.Write(&parinput.Extra, binary.LittleEndian, pinfo); err != nil {
		t.Error("CreateContainer(cinfo): serialize pinfo:", err)
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
	if err := fimg.DeleteObject(2, DelZero); err != nil {
		t.Error(`fimg.DeleteObject(2, DelZero):`, err)
	}

	// unload the test container
	if err = fimg.UnloadContainer(); err != nil {
		t.Error("UnloadContainer(fimg):", err)
	}
}
