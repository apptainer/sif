// Copyright (c) 2018, Sylabs Inc. All rights reserved.
// Copyright (c) 2017, SingularityWare, LLC. All rights reserved.
// Copyright (c) 2017, Yannick Cote <yhcote@gmail.com> All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package sif

import (
	"bytes"
	"container/list"
	"encoding/binary"
	"fmt"
	"github.com/golang/glog"
	"github.com/satori/go.uuid"
	"io"
	"os"
	"os/user"
	"path"
	"strconv"
	"time"
)

// Find next offset aligned to block size
func nextAligned(offset int64, align int) int64 {
	align64 := uint64(align)
	offset64 := uint64(offset)

	if offset64%align64 != 0 {
		offset64 = (offset64 & ^(align64 - 1)) + align64
	}

	return int64(offset64)
}

// Set file pointer offset to next aligned block
func setFileOffNA(fimg *FileImage, alignment int) (int64, error) {
	offset, err := fimg.fp.Seek(0, 1) // get current position
	if err != nil {
		return -1, fmt.Errorf("seek() getting current file position: %s", err)
	}
	aligned := nextAligned(offset, alignment)
	offset, err = fimg.fp.Seek(aligned, 0) // set new position
	if err != nil {
		return -1, fmt.Errorf("seek() getting current file position: %s", err)
	}
	return offset, nil
}

// Get current user and returns both uid and gid
func getUserIDs() (int64, int64, error) {
	u, err := user.Current()
	if err != nil {
		return -1, -1, fmt.Errorf("getting current user info: %s", err)
	}

	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return -1, -1, fmt.Errorf("converting UID: %s", err)
	}

	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return -1, -1, fmt.Errorf("converting GID: %s", err)
	}

	return int64(uid), int64(gid), nil
}

// Fill all of the fields of a Descriptor
func fillDescriptor(fimg *FileImage, descr *Descriptor, input descriptorInput) (err error) {
	descr.Datatype = input.datatype
	descr.ID = uuid.NewV4()
	descr.Used = true
	descr.Groupid = input.groupid
	descr.Link = input.link
	descr.Fileoff, err = setFileOffNA(fimg, os.Getpagesize())
	if err != nil {
		return
	}
	descr.Filelen = input.size
	descr.Ctime = time.Now().Unix()
	descr.Mtime = time.Now().Unix()
	descr.UID, descr.Gid, err = getUserIDs()
	if err != nil {
		return fmt.Errorf("filling descriptor: %s", err)
	}
	copy(descr.Name[:DescrNameLen], path.Base(input.fname))
	copy(descr.Private[:DescrMaxPrivLen], input.extra.Bytes())

	glog.Infoln(descr)

	return
}

// Write new data object to the SIF file
func writeDataObject(fimg *FileImage, input descriptorInput) error {
	if n, err := io.Copy(fimg.fp, input.fp); err != nil {
		return fmt.Errorf("copying data object file to SIF file: %s", err)
	} else if n != input.size {
		return fmt.Errorf("short write while copying data object file to SIF file")
	}
	return nil
}

// Find a free descriptor and create a memory representation for addition to the SIF file
func createDescriptor(fimg *FileImage, descrtable *[DescrNumEntries]Descriptor, e *list.Element) (err error) {
	var (
		idx int
		v   Descriptor
	)

	if fimg.header.Dfree == 0 {
		return fmt.Errorf("no descriptor table free entry")
	}

	// look for a free entry in the descriptor table
	for idx, v = range descrtable {
		if v.Used == false {
			break
		}
	}
	if idx == DescrNumEntries-1 && descrtable[idx].Used == true {
		return fmt.Errorf("no descriptor table free entry, warning: header.Dfree was > 0")
	}

	// extract the descriptor input info from the list element
	input, ok := e.Value.(descriptorInput)
	if ok == false {
		return fmt.Errorf("structure is not of expected descriptorInput type")
	}

	// fill in SIF file descriptor
	if err = fillDescriptor(fimg, &descrtable[idx], input); err != nil {
		return
	}

	// write data object associated to the descriptor in SIF file
	if err = writeDataObject(fimg, input); err != nil {
		return fmt.Errorf("writing data object for SIF file: %s", err)
	}

	// update some global header fields from adding this new descriptor
	fimg.header.Dfree--
	fimg.header.Datalen += input.size

	return
}

// Release and write the data object descriptor to backing storage (SIF container file)
func writeDescriptors(fimg *FileImage, descrtable *[DescrNumEntries]Descriptor) error {
	buf := new(bytes.Buffer)
	for _, v := range descrtable {
		if err := binary.Write(buf, binary.LittleEndian, v); err != nil {
			return fmt.Errorf("binary writing descrtable to buf: %s", err)
		}
	}
	fimg.header.Descrlen = int64(binary.Size(descrtable))

	// first, move to descriptor start offset
	if _, err := fimg.fp.Seek(DescrStartOffset, 0); err != nil {
		return fmt.Errorf("seeking to descriptor start offset: %s", err)
	}

	if n, err := fimg.fp.Write(buf.Bytes()); err != nil || n < buf.Len() {
		if err != nil {
			return fmt.Errorf("writing descriptor table failed: %s", err)
		}
		return fmt.Errorf("writing descriptor table, short write")
	}

	return nil
}

// Write the global header to file
func writeHeader(fimg *FileImage) error {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, fimg.header); err != nil {
		return fmt.Errorf("binary writing header to buf: %s", err)
	}

	// first, move to descriptor start offset
	if _, err := fimg.fp.Seek(0, 0); err != nil {
		return fmt.Errorf("seeking to descriptor start offset: %s", err)
	}

	if n, err := fimg.fp.Write(buf.Bytes()); err != nil || n < buf.Len() {
		if err != nil {
			return fmt.Errorf("writing global header failed: %s", err)
		}
		return fmt.Errorf("writing global header, short write")
	}

	return nil
}

// CreateContainer is responsible for the creation of a new SIF container
// file. It takes the creation information specification as input
// and produces an output file as specified in the input data.
func CreateContainer(cinfo CreateInfo) (err error) {
	var fimg FileImage
	var descrtable [DescrNumEntries]Descriptor

	if cinfo.inputlist.Len() == 0 {
		return fmt.Errorf("need at least one input descriptor")
	}

	// Prepare a fresh global header
	copy(fimg.header.Launch[:], cinfo.launchstr)
	copy(fimg.header.Magic[:], HdrMagic)
	copy(fimg.header.Version[:], cinfo.sifversion)
	copy(fimg.header.Arch[:], cinfo.arch)
	copy(fimg.header.ID[:], cinfo.id[:])
	fimg.header.Ctime = time.Now().Unix()
	fimg.header.Mtime = time.Now().Unix()
	fimg.header.Dfree = DescrNumEntries
	fimg.header.Dtotal = DescrNumEntries
	fimg.header.Descroff = DescrStartOffset
	fimg.header.Dataoff = DataStartOffset

	fimg.nextid = 1

	// Create container file
	fimg.fp, err = os.OpenFile(cinfo.pathname, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return fmt.Errorf("container file creation failed: %s", err)
	}
	defer fimg.fp.Close()

	// set file pointer to start of data section */
	if _, err = fimg.fp.Seek(DataStartOffset, 0); err != nil {
		return fmt.Errorf("setting file offset pointer to DataStartOffset: %s", err)
	}

	for e := cinfo.inputlist.Front(); e != nil; e = e.Next() {
		if err = createDescriptor(&fimg, &descrtable, e); err != nil {
			return
		}
	}

	// Write down the descriptor array
	if err = writeDescriptors(&fimg, &descrtable); err != nil {
		return
	}

	// Write down header file
	if err = writeHeader(&fimg); err != nil {
		return
	}

	glog.Flush()

	return
}

// DeleteObject removes data from a SIF file referred to by id. The descriptor for the
// data object is free'd and can be reused later. There's currenly 2 clean mode specified
// by flags: DelZero, to zero out the data region for security and DelCompact to
// remove and shink the file compacting the unused area.
func DeleteObject(fimg *FileImage, id uuid.UUID, flags int) error {
	return nil
}
