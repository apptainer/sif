// Copyright (c) 2018, Sylabs Inc. All rights reserved.
// Copyright (c) 2017, SingularityWare, LLC. All rights reserved.
// Copyright (c) 2017, Yannick Cote <yhcote@gmail.com> All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package sif

import (
	"encoding/binary"
	"fmt"
	"github.com/golang/glog"
	"os"
)

// Read the global header from the container file
func readHeader(fimg *FileImage) error {
	if err := binary.Read(fimg.fp, binary.LittleEndian, &fimg.header); err != nil {
		return fmt.Errorf("reading global header from container file: %s", err)
	}

	glog.Infoln("<<< read global header start >>>")
	glog.Infoln("Launch:", string(fimg.header.Launch[:]))
	glog.Infoln("Magic:", string(fimg.header.Magic[:]))
	glog.Infoln("Version:", string(fimg.header.Version[:]))
	glog.Infoln("Arch:", string(fimg.header.Arch[:]))
	glog.Infoln("ID:", fimg.header.ID)
	glog.Infoln("Ctime:", fimg.header.Ctime)
	glog.Infoln("Mtime:", fimg.header.Mtime)
	glog.Infoln("Dfree:", fimg.header.Dfree)
	glog.Infoln("Dtotal:", fimg.header.Dtotal)
	glog.Infoln("Descoff:", fimg.header.Descroff)
	glog.Infoln("Descrlen:", fimg.header.Descrlen)
	glog.Infoln("Dataoff:", fimg.header.Dataoff)
	glog.Infoln("Datalen:", fimg.header.Datalen)
	glog.Infoln("<<< read global header end >>>")

	return nil
}

// Read the used descriptors and populate an in-memory representation of those in node list
func readDescriptors(fimg *FileImage) error {
	// start by positioning us to the start of descriptors
	_, err := fimg.fp.Seek(fimg.header.Descroff, 0)
	if err != nil {
		return fmt.Errorf("seek() setting to descriptors start: %s", err)
	}

	// Initialize descriptor array (slice) and read them all from file
	fimg.descrArr = make([]Descriptor, fimg.header.Dtotal)
	if err := binary.Read(fimg.fp, binary.LittleEndian, &fimg.descrArr); err != nil {
		return fmt.Errorf("reading global header from container file: %s", err)
	}

	return nil
}

// LoadContainer is responsible for loading a SIF container file. It takes
// the container file name, and whether the file is opened as read-only
// as arguments.
func LoadContainer(filename string, rdonly bool) (fimg FileImage, err error) {
	if rdonly { // open SIF rdonly if mounting immutable partitions or inspecting the image
		if fimg.fp, err = os.Open(filename); err != nil {
			return fimg, fmt.Errorf("opening(RDONLY) container file: %s", err)
		}
	} else { // open SIF read-write when adding and removing data objects
		if fimg.fp, err = os.OpenFile(filename, os.O_RDWR, 0644); err != nil {
			return fimg, fmt.Errorf("opening(RDWR) container file: %s", err)
		}
	}

	if err = readHeader(&fimg); err != nil {
		return fimg, fmt.Errorf("reading global header: %s", err)
	}

	if err = readDescriptors(&fimg); err != nil {
		return fimg, fmt.Errorf("reading and populating descriptor nodes: %s", err)
	}

	glog.Flush()

	return fimg, nil
}
