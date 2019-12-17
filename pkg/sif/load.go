// Copyright (c) 2018-2019, Sylabs Inc. All rights reserved.
// Copyright (c) 2017, SingularityWare, LLC. All rights reserved.
// Copyright (c) 2017, Yannick Cote <yhcote@gmail.com> All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package sif

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"syscall"
)

// Read the global header from the container file.
func readHeader(fimg *FileImage) error {
	if err := binary.Read(fimg.Reader, binary.LittleEndian, &fimg.Header); err != nil {
		return fmt.Errorf("reading global header from container file: %s", err)
	}

	return nil
}

// Read the used descriptors and populate an in-memory representation of those in node list.
func readDescriptors(fimg *FileImage) error {
	// start by positioning us to the start of descriptors
	_, err := fimg.Reader.Seek(fimg.Header.Descroff, 0)
	if err != nil {
		return fmt.Errorf("seek() setting to descriptors start: %s", err)
	}

	// Initialize descriptor array (slice) and read them all from file
	fimg.DescrArr = make([]Descriptor, fimg.Header.Dtotal)
	if err := binary.Read(fimg.Reader, binary.LittleEndian, &fimg.DescrArr); err != nil {
		fimg.DescrArr = nil
		return fmt.Errorf("reading descriptor array from container file: %s", err)
	}

	descr, _, err := fimg.GetPartPrimSys()
	if err == nil {
		fimg.PrimPartID = descr.ID
	}

	return nil
}

// Look at key fields from the global header to assess SIF validity.
// `runnable' checks is current container can run on host.
func isValidSif(fimg *FileImage) error {
	// check various header fields
	if trimZeroBytes(fimg.Header.Magic[:]) != HdrMagic {
		return fmt.Errorf("invalid SIF file: Magic |%s| want |%s|", fimg.Header.Magic, HdrMagic)
	}
	if trimZeroBytes(fimg.Header.Version[:]) > HdrVersion {
		return fmt.Errorf("invalid SIF file: Version %s want <= %s", fimg.Header.Version, HdrVersion)
	}

	return nil
}

// mapFile takes a file pointer and returns a slice of bytes representing the file data.
func (fimg *FileImage) mapFile(rdonly bool) error {
	info, err := fimg.Fp.Stat()
	if err != nil {
		return fmt.Errorf("while trying to size SIF file to mmap")
	}

	switch info.Mode() & os.ModeType {
	case 0:
		// regular file
		fimg.Filesize = info.Size()
	case os.ModeDevice:
		// block device
		fimg.Amodebuf = true
		fimg.Filesize, err = fimg.Fp.Seek(0, io.SeekEnd)
		if err != nil {
			return fmt.Errorf("while getting block device size: %s", err)
		}
	default:
		return fmt.Errorf("%s is neither a file nor a block device", fimg.Fp.Name())
	}

	fimg.Filedata = nil

	if !fimg.Amodebuf {
		prot := syscall.PROT_READ
		flags := syscall.MAP_PRIVATE

		if !rdonly {
			prot = syscall.PROT_WRITE
			flags = syscall.MAP_SHARED
		}

		size := nextAligned(fimg.Filesize, syscall.Getpagesize())
		if int64(int(size)) < fimg.Filesize {
			return fmt.Errorf("file is too big to be mapped")
		}

		fimg.Filedata, err = syscall.Mmap(int(fimg.Fp.Fd()), 0, int(size), prot, flags)
		if err != nil {
			// mmap failed, use sequential read() instead for top of file
			log.Printf("mmap on %s failed (%s), reading buffer sequentially...", err, fimg.Fp.Name())
			fimg.Amodebuf = true
		}
	}

	if fimg.Filedata == nil {
		fimg.Filedata = make([]byte, DataStartOffset)

		// start by positioning us to the start of the file
		_, err := fimg.Fp.Seek(0, io.SeekStart)
		if err != nil {
			return fmt.Errorf("seek() setting to start of file: %s", err)
		}

		if n, err := fimg.Fp.Read(fimg.Filedata); n != DataStartOffset {
			return fmt.Errorf("short read while reading top of file: %v", err)
		}
	}

	// create and associate a new bytes.Reader on top of mmap'ed or buffered data from file
	fimg.Reader = bytes.NewReader(fimg.Filedata)

	return nil
}

func (fimg *FileImage) unmapFile() error {
	if fimg.Amodebuf {
		return nil
	}
	if err := syscall.Munmap(fimg.Filedata); err != nil {
		return fmt.Errorf("while calling unmapping SIF file")
	}
	return nil
}

// LoadContainer is responsible for loading a SIF container file. It takes
// the container file name, and whether the file is opened as read-only
// as arguments.
func LoadContainer(filename string, rdonly bool) (FileImage, error) {
	mode := os.O_RDWR // open SIF read-write when adding and removing data objects
	if rdonly {
		mode = os.O_RDONLY // open SIF rdonly if mounting immutable partitions or inspecting the image
	}

	f, err := os.OpenFile(filename, mode, 0)
	if err != nil {
		return FileImage{}, fmt.Errorf("opening(%s) container file: %v", modeToStr(mode), err)
	}

	fimg, err := LoadContainerFp(f, rdonly)
	if err != nil {
		_ = f.Close()
		return FileImage{}, err
	}

	return fimg, nil
}

// LoadContainerFp is responsible for loading a SIF container file. It takes
// a ReadWriter pointing to an opened file, and whether the file is opened as
// read-only for arguments.
func LoadContainerFp(fp ReadWriter, rdonly bool) (fimg FileImage, err error) {
	if fp == nil {
		return fimg, fmt.Errorf("provided fp for file is invalid")
	}
	fimg.Fp = fp

	defer func() {
		if err != nil {
			if err := fimg.unmapFile(); err != nil {
				log.Printf("could not unmap SIF: %v", err)
			}
		}
	}()

	// get a memory map of the SIF file
	if err = fimg.mapFile(rdonly); err != nil {
		return
	}

	// read global header from SIF file
	if err = readHeader(&fimg); err != nil {
		return
	}

	// validate global header
	if err = isValidSif(&fimg); err != nil {
		return
	}

	// read descriptor array from SIF file
	if err = readDescriptors(&fimg); err != nil {
		return
	}

	return fimg, nil
}

// LoadContainerReader is responsible for processing SIF data from a byte stream
// and extract various components like the global header, descriptors and even
// perhaps data, depending on how much is read from the source.
func LoadContainerReader(b *bytes.Reader) (fimg FileImage, err error) {
	fimg.Reader = b

	// read global header from SIF file
	if err = readHeader(&fimg); err != nil {
		return
	}

	// validate global header
	if err = isValidSif(&fimg); err != nil {
		return
	}

	// in the case where the reader buffer doesn't include descriptor data, we
	// don't return an error and DescrArr will be set to nil
	if readErr := readDescriptors(&fimg); readErr != nil {
		fmt.Println("Error reading descriptors: ", readErr)
	}

	return fimg, err
}

// UnloadContainer closes the SIF container file and free associated resources if needed.
func (fimg *FileImage) UnloadContainer() (err error) {
	// if SIF data comes from file, not a slice buffer (see LoadContainer() variants)
	if fimg.Fp != nil {
		if err = fimg.unmapFile(); err != nil {
			return
		}
		if err = fimg.Fp.Close(); err != nil {
			return fmt.Errorf("closing SIF file failed, corrupted: don't use: %s", err)
		}
	}
	return
}

func trimZeroBytes(str []byte) string {
	return string(bytes.TrimRight(str, "\x00"))
}

func modeToStr(mode int) string {
	switch mode {
	case os.O_RDONLY:
		return "RDONLY"
	case os.O_RDWR:
		return "RDWR"
	}
	return ""
}
