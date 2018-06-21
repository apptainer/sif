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
	"os"
	"reflect"
	"syscall"
)

// Read the global header from the container file
func readHeader(fimg *FileImage) error {
	if err := binary.Read(fimg.Fp, binary.LittleEndian, &fimg.Header); err != nil {
		return fmt.Errorf("reading global header from container file: %s", err)
	}

	return nil
}

// Read the used descriptors and populate an in-memory representation of those in node list
func readDescriptors(fimg *FileImage) error {
	// start by positioning us to the start of descriptors
	_, err := fimg.Fp.Seek(fimg.Header.Descroff, 0)
	if err != nil {
		return fmt.Errorf("seek() setting to descriptors start: %s", err)
	}

	// Initialize descriptor array (slice) and read them all from file
	fimg.DescrArr = make([]Descriptor, fimg.Header.Dtotal)
	if err := binary.Read(fimg.Fp, binary.LittleEndian, &fimg.DescrArr); err != nil {
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
	if string(fimg.Header.Magic[:HdrMagicLen-1]) != HdrMagic {
		return fmt.Errorf("invalid SIF file: Magic |%s| want |%s|", fimg.Header.Magic, HdrMagic)
	}
	if string(fimg.Header.Version[:HdrVersionLen-1]) != HdrVersion {
		return fmt.Errorf("invalid SIF file: Version %s want %s", fimg.Header.Version, HdrVersion)
	}
	if string(fimg.Header.Arch[:HdrArchLen-1]) != arch {
		return fmt.Errorf("invalid SIF file: Arch %s want %s", fimg.Header.Arch, arch)
	}
	if fimg.Header.Dfree == fimg.Header.Dtotal {
		return fmt.Errorf("invalid SIF file: no descriptor found")
	}

	return nil
}

// mapFile takes a file pointer and returns a slice of bytes representing the file data
func (fimg *FileImage) mapFile(rdonly bool) error {
	prot := syscall.PROT_READ
	flags := syscall.MAP_PRIVATE

	info, err := fimg.Fp.Stat()
	if err != nil {
		return fmt.Errorf("while trying to size SIF file to mmap")
	}
	fimg.Filesize = info.Size()

	size := nextAligned(info.Size(), syscall.Getpagesize())
	if int64(int(size)) < info.Size() {
		return fmt.Errorf("file is to big to be mapped")
	}

	if rdonly == false {
		prot = syscall.PROT_WRITE
		flags = syscall.MAP_SHARED
	}

	fimg.Filedata, err = syscall.Mmap(int(fimg.Fp.Fd()), 0, int(size), prot, flags)
	if err != nil {
		return fmt.Errorf("while trying to call mmap on SIF file")
	}

	return nil
}

func (fimg *FileImage) unmapFile() error {
	if err := syscall.Munmap(fimg.Filedata); err != nil {
		return fmt.Errorf("while calling unmapping SIF file")
	}
	return nil
}

// LoadContainer is responsible for loading a SIF container file. It takes
// the container file name, and whether the file is opened as read-only
// as arguments.
func LoadContainer(filename string, rdonly bool) (fimg FileImage, err error) {
	if rdonly { // open SIF rdonly if mounting immutable partitions or inspecting the image
		if fimg.Fp, err = os.Open(filename); err != nil {
			return fimg, fmt.Errorf("opening(RDONLY) container file: %s", err)
		}
	} else { // open SIF read-write when adding and removing data objects
		if fimg.Fp, err = os.OpenFile(filename, os.O_RDWR, 0644); err != nil {
			return fimg, fmt.Errorf("opening(RDWR) container file: %s", err)
		}
	}

	// read global header from SIF file
	if err = readHeader(&fimg); err != nil {
		return fimg, fmt.Errorf("reading global header: %s", err)
	}

	// validate global header
	if err = isValidSif(&fimg); err != nil {
		return
	}

	// read descriptor array from SIF file
	if err = readDescriptors(&fimg); err != nil {
		return fimg, fmt.Errorf("reading and populating descriptor nodes: %s", err)
	}

	// get a memory map of the SIF file
	if err = fimg.mapFile(rdonly); err != nil {
		return
	}

	return fimg, nil
}

// UnloadContainer closes the SIF container file and free associated resources if needed
func (fimg *FileImage) UnloadContainer() (err error) {
	if err = fimg.unmapFile(); err != nil {
		return
	}
	if err = fimg.Fp.Close(); err != nil {
		return fmt.Errorf("closing SIF file failed, corrupted: don't use: %s", err)
	}
	return
}
