// Copyright (c) 2018, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package sif

import (
	"container/list"
	"encoding/binary"
	"github.com/satori/go.uuid"
	"os"
	"testing"
)

const (
	headerLen = 128
	descrLen  = 589
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
		pathname:   "testdata/testcontainer.sif",
		launchstr:  HdrLaunch,
		sifversion: HdrVersion,
		arch:       HdrArchAMD64,
		id:         uuid.NewV4(),
		inputlist:  list.New(),
	}

	// test container creation without any input descriptors
	if err := CreateContainer(cinfo); err == nil {
		t.Error("CreateContainer(cinfo): should not allow empty input descriptor list")
	}

	// data we need to create a definition file descriptor
	definput := descriptorInput{
		datatype: DataDeffile,
		groupid:  DescrDefaultGroup,
		link:     DescrUnusedLink,
		size:     222,
		fname:    "testdata/busybox.deffile",
		fp:       nil,
		data:     nil,
		image:    nil,
		descr:    nil,
	}
	// open up the data object file for this descriptor
	if definput.fp, err = os.Open(definput.fname); err != nil {
		t.Error("CreateContainer(cinfo): read data object file:", err)
	}
	defer definput.fp.Close()

	// add this descriptor input element to the list
	cinfo.inputlist.PushBack(definput)

	// data we need to create a system partition descriptor
	parinput := descriptorInput{
		datatype: DataPartition,
		groupid:  DescrDefaultGroup,
		link:     DescrUnusedLink,
		size:     1003520,
		fname:    "testdata/busybox.squash",
		fp:       nil,
		data:     nil,
		image:    nil,
		descr:    nil,
	}
	// open up the data object file for this descriptor
	if parinput.fp, err = os.Open(parinput.fname); err != nil {
		t.Error("CreateContainer(cinfo): read data object file:", err)
	}
	defer parinput.fp.Close()

	// extra data needed for the creation of a partition descriptor
	pinfo := partInput{
		Fstype:   FsSquash,
		Parttype: PartSystem,
	}

	// serialize the partition data for integration with the base descriptor input
	if err := binary.Write(&parinput.extra, binary.LittleEndian, pinfo); err != nil {
		t.Error("CreateContainer(cinfo): serialize pinfo:", err)
	}

	// add this descriptor input element to the list
	cinfo.inputlist.PushBack(parinput)

	// test container creation with two partition input descriptors
	if err := CreateContainer(cinfo); err != nil {
		t.Error("CreateContainer(cinfo): CreateContainer():", err)
	}
}

func TestAddObject(t *testing.T) {
	var err error

	// data we need to create a system partition descriptor
	parinput := descriptorInput{
		datatype: DataPartition,
		groupid:  DescrDefaultGroup,
		link:     DescrUnusedLink,
		size:     1003520,
		fname:    "testdata/busybox.squash",
		fp:       nil,
		data:     nil,
		image:    nil,
		descr:    nil,
	}
	// open up the data object file for this descriptor
	if parinput.fp, err = os.Open(parinput.fname); err != nil {
		t.Error("CreateContainer(cinfo): read data object file:", err)
	}
	defer parinput.fp.Close()

	// extra data needed for the creation of a partition descriptor
	pinfo := partInput{
		Fstype:   FsSquash,
		Parttype: PartSystem,
	}

	// serialize the partition data for integration with the base descriptor input
	if err := binary.Write(&parinput.extra, binary.LittleEndian, pinfo); err != nil {
		t.Error("CreateContainer(cinfo): serialize pinfo:", err)
	}

	// load the test container
	fimg, err := LoadContainer("testdata/testcontainer1.sif", false)
	if err != nil {
		t.Error("LoadContainer(testdata/testcontainer1.sif, false):", err)
	}

	// add new data object and its descriptor
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
	if err := fimg.DeleteObject("da4ef1f5", DelZero); err != nil {
		t.Error(`fimg.DeleteObject("da4ef1f5", DelZero):`, err)
	}

	// test data object deletation
	if err := fimg.DeleteObject("abc02448", DelZero); err != nil {
		t.Error(`fimg.DeleteObject("da4ef1f5", DelZero):`, err)
	}

	// unload the test container
	if err = fimg.UnloadContainer(); err != nil {
		t.Error("UnloadContainer(fimg):", err)
	}
}
