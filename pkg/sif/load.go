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
	fimg.rds = make([]rawDescriptor, fimg.h.Dtotal)
	if err := readBinaryAt(r, fimg.h.Descroff, &fimg.rds); err != nil {
		fimg.rds = nil
		return fmt.Errorf("reading descriptor array from container file: %s", err)
	}

	if d, err := fimg.GetDescriptor(WithPartitionType(PartPrimSys)); err == nil {
		fimg.primPartID = d.ID
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

// loadContainer loads a SIF image from rw.
func loadContainer(rw ReadWriter) (*FileImage, error) {
	f := FileImage{rw: rw}

	if err := readHeader(rw, &f); err != nil {
		return nil, err
	}

	if err := isValidSif(&f); err != nil {
		return nil, err
	}

	if err := readDescriptors(rw, &f); err != nil {
		return nil, err
	}

	return &f, nil
}

// loadOpts accumulates container loading options.
type loadOpts struct {
	flag int
}

// LoadOpt are used to specify container loading options.
type LoadOpt func(*loadOpts) error

// OptLoadWithFlag specifies flag (os.O_RDONLY etc.) to be used when opening the container file.
func OptLoadWithFlag(flag int) LoadOpt {
	return func(lo *loadOpts) error {
		lo.flag = flag
		return nil
	}
}

// LoadContainerFromPath loads a new SIF container from path, according to opts.
//
// On success, a FileImage is returned. The caller must call UnloadContainer to ensure resources
// are released.
//
// By default, the file is opened for read and write access. To change this behavior, consider
// using OptLoadWithFlag.
func LoadContainerFromPath(path string, opts ...LoadOpt) (*FileImage, error) {
	lo := loadOpts{
		flag: os.O_RDWR,
	}

	for _, opt := range opts {
		if err := opt(&lo); err != nil {
			return nil, fmt.Errorf("%w", err)
		}
	}

	fp, err := os.OpenFile(path, lo.flag, 0)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	f, err := loadContainer(fp)
	if err != nil {
		fp.Close()

		return nil, fmt.Errorf("%w", err)
	}
	return f, nil
}

// LoadContainer loads a new SIF container from rw, according to opts.
//
// On success, a FileImage is returned. The caller must call UnloadContainer to ensure resources
// are released.
func LoadContainer(rw ReadWriter, opts ...LoadOpt) (*FileImage, error) {
	lo := loadOpts{}

	for _, opt := range opts {
		if err := opt(&lo); err != nil {
			return nil, fmt.Errorf("%w", err)
		}
	}

	f, err := loadContainer(rw)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	return f, nil
}

// UnloadContainer unloads f, releasing associated resources.
func (f *FileImage) UnloadContainer() error {
	if c, ok := f.rw.(io.Closer); ok {
		if err := c.Close(); err != nil {
			return err
		}
	}
	return nil
}

func trimZeroBytes(str []byte) string {
	return string(bytes.TrimRight(str, "\x00"))
}
