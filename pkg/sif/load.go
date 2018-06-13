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
	"reflect"
	"syscall"
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

// Look at key fields from the global header to assess SIF validity
func isValidSif(fimg *FileImage) error {
	var p uintptr
	var buf syscall.Utsname

	// get machine name
	err := syscall.Uname(&buf)
	if err != nil {
		return fmt.Errorf("getting system info failed: %s", err)
	}

	// make a string out of the [65]int8 array
	b := make([]byte, len(buf.Machine))
	for i, v := range buf.Machine {
		b[i] = byte(v)
	}
	machine := string(b)

	// get the machine pointer size
	t := reflect.TypeOf(p)
	ptrSize := t.Size()

	// check the machine we run on, and if container file arch is compatible
	var arch string
	if machine[:6] == "x86_64" {
		if ptrSize == 8 {
			arch = HdrArchAMD64
		} else {
			arch = HdrArch386
		}
	} else if machine[0] == 'i' && machine[2] == '8' && machine[3] == '6' {
		arch = HdrArch386
	} else if machine[:3] == "arm" && ptrSize == 4 {
		arch = HdrArchARM
	} else if machine[:7] == "aarch64" {
		arch = HdrArchAARCH64
	} else {
		return fmt.Errorf("cannot determine machine architecture")
	}

	// check various header fields
	if string(fimg.header.Magic[:HdrMagicLen-1]) != HdrMagic {
		return fmt.Errorf("invalid SIF file: Magic |%s| want |%s|", fimg.header.Magic, HdrMagic)
	}
	if string(fimg.header.Version[:HdrVersionLen-1]) != HdrVersion {
		return fmt.Errorf("invalid SIF file: Version %s want %s", fimg.header.Version, HdrVersion)
	}
	if string(fimg.header.Arch[:HdrArchLen-1]) != arch {
		return fmt.Errorf("invalid SIF file: Arch %s want %s", fimg.header.Arch, arch)
	}
	if fimg.header.Dfree == fimg.header.Dtotal {
		return fmt.Errorf("invalid SIF file: no descriptor found")
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

	// read global header from SIF file
	if err = readHeader(&fimg); err != nil {
		return fimg, fmt.Errorf("reading global header: %s", err)
	}

	// validate global header
	if err = isValidSif(&fimg); err != nil {
		return fimg, err
	}

	// read descriptor array from SIF file
	if err = readDescriptors(&fimg); err != nil {
		return fimg, fmt.Errorf("reading and populating descriptor nodes: %s", err)
	}

	glog.Flush()

	return fimg, nil
}

// UnloadContainer closes the SIF container file and free associated resources if needed
func (fimg *FileImage) UnloadContainer() error {
	if err := fimg.fp.Close(); err != nil {
		return fmt.Errorf("closing SIF file failed, corrupted: don't use: %s", err)
	}
	return nil
}
