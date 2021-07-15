// Copyright (c) 2018-2021, Sylabs Inc. All rights reserved.
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
	"os"
)

// readBinaryAt reads structured binary data from r at offset off into data.
func readBinaryAt(r io.ReaderAt, off int64, data interface{}) error {
	return binary.Read(io.NewSectionReader(r, off, int64(binary.Size(data))), binary.LittleEndian, data)
}

// Read the global header from r and populate fimg.Header.
func readHeader(r io.ReaderAt, fimg *FileImage) error {
	if err := readBinaryAt(r, 0, &fimg.h); err != nil {
		return fmt.Errorf("reading global header from container file: %s", err)
	}

	return nil
}

// Read the descriptors from r and populate fimg.DescrArr.
func readDescriptors(r io.ReaderAt, fimg *FileImage) error {
	// Initialize descriptor array (slice) and read them all from file
	fimg.descrArr = make([]Descriptor, fimg.h.Dtotal)
	if err := readBinaryAt(r, fimg.h.Descroff, &fimg.descrArr); err != nil {
		fimg.descrArr = nil
		return fmt.Errorf("reading descriptor array from container file: %s", err)
	}

	descr, _, err := fimg.GetPartPrimSys()
	if err == nil {
		fimg.PrimPartID = descr.ID
	}

	return nil
}

// isValidSif looks at key fields from the global header to assess SIF validity.
func isValidSif(f *FileImage) error {
	if got, want := trimZeroBytes(f.h.Magic[:]), hdrMagic; got != want {
		return fmt.Errorf("invalid SIF file: Magic |%v| want |%v|", got, want)
	}

	if got, want := trimZeroBytes(f.h.Version[:]), CurrentVersion.String(); got > want {
		return fmt.Errorf("invalid SIF file: Version %s want <= %s", got, want)
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

	info, err := fimg.Fp.Stat()
	if err != nil {
		return fimg, err
	}
	fimg.Filesize = info.Size()

	fimg.Amodebuf = true // for backwards compat, true == !mmap

	// read global header from SIF file
	if err = readHeader(fp, &fimg); err != nil {
		return
	}

	// validate global header
	if err = isValidSif(&fimg); err != nil {
		return
	}

	// read descriptor array from SIF file
	if err = readDescriptors(fp, &fimg); err != nil {
		return
	}

	return fimg, nil
}

// LoadContainerReader is responsible for processing SIF data from a byte stream
// and extract various components like the global header, descriptors and even
// perhaps data, depending on how much is read from the source.
func LoadContainerReader(b *bytes.Reader) (fimg FileImage, err error) {
	fimg.Amodebuf = true // for backwards compat, true == !mmap

	// read global header from SIF file
	if err = readHeader(b, &fimg); err != nil {
		return
	}

	// validate global header
	if err = isValidSif(&fimg); err != nil {
		return
	}

	// in the case where the reader buffer doesn't include descriptor data, we
	// don't return an error and DescrArr will be set to nil
	if readErr := readDescriptors(b, &fimg); readErr != nil {
		fmt.Println("Error reading descriptors: ", readErr)
	}

	return fimg, err
}

// UnloadContainer closes the SIF container file and free associated resources if needed.
func (fimg *FileImage) UnloadContainer() (err error) {
	// if SIF data comes from file, not a slice buffer (see LoadContainer() variants)
	if fimg.Fp != nil {
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
