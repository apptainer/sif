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
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"time"

	"github.com/google/uuid"
)

// Find next offset aligned to block size.
func nextAligned(offset int64, align int) int64 {
	align64 := uint64(align)
	offset64 := uint64(offset)

	if offset64%align64 != 0 {
		offset64 = (offset64 & ^(align64 - 1)) + align64
	}

	return int64(offset64)
}

// Set file pointer offset to next aligned block.
func setFileOffNA(fimg *FileImage, alignment int) (int64, error) {
	offset, err := fimg.Fp.Seek(0, 1) // get current position
	if err != nil {
		return -1, fmt.Errorf("seek() getting current file position: %s", err)
	}
	aligned := nextAligned(offset, alignment)
	offset, err = fimg.Fp.Seek(aligned, 0) // set new position
	if err != nil {
		return -1, fmt.Errorf("seek() getting current file position: %s", err)
	}
	return offset, nil
}

// Fill all of the fields of a Descriptor.
func fillDescriptor(fimg *FileImage, index int, input DescriptorInput) (err error) {
	descr := &fimg.DescrArr[index]

	curoff, err := fimg.Fp.Seek(0, 1)
	if err != nil {
		return fmt.Errorf("while file pointer look at: %s", err)
	}

	descr.Datatype = input.Datatype
	descr.ID = uint32(index) + 1
	descr.Used = true
	descr.Groupid = input.Groupid
	descr.Link = input.Link
	align := os.Getpagesize()
	if input.Alignment != 0 {
		align = input.Alignment
	}
	descr.Fileoff, err = setFileOffNA(fimg, align)
	if err != nil {
		return
	}
	descr.Filelen = input.Size
	descr.Storelen = descr.Fileoff + descr.Filelen - curoff
	descr.Ctime = time.Now().Unix()
	descr.Mtime = time.Now().Unix()
	descr.UID = 0
	descr.GID = 0
	descr.setName(path.Base(input.Fname))
	descr.setExtra(input.Extra.Bytes())

	// Check that none or only 1 primary partition is ever set
	if descr.Datatype == DataPartition {
		ptype, err := descr.GetPartType()
		if err != nil {
			return err
		}
		if ptype == PartPrimSys {
			if fimg.PrimPartID != 0 {
				return fmt.Errorf("only 1 FS data object may be a primary partition")
			}
			fimg.PrimPartID = descr.ID
			arch, err := descr.GetArch()
			if err != nil {
				return err
			}
			copy(fimg.h.Arch[:], arch[:])
		}
	}

	return
}

// Write new data object to the SIF file.
func writeDataObject(fimg *FileImage, index int, input DescriptorInput) error {
	// if we have bytes in input.data use that instead of an input file
	if input.Data != nil {
		if _, err := fimg.Fp.Write(input.Data); err != nil {
			return fmt.Errorf("copying data object data to SIF file: %s", err)
		}
	} else {
		n, err := io.Copy(fimg.Fp, input.Fp)
		if err != nil {
			return fmt.Errorf("copying data object file to SIF file: %s", err)
		}
		if n != input.Size && input.Size != 0 {
			return fmt.Errorf("short write while copying to SIF file")
		}
		if input.Size == 0 {
			// coming in from os.Stdin (pipe)
			descr := &fimg.DescrArr[index]
			descr.Filelen = n
			descr.setName("pipe" + fmt.Sprint(index+1))
		}
	}

	return nil
}

// Find a free descriptor and create a memory representation for addition to the SIF file.
func createDescriptor(fimg *FileImage, input DescriptorInput) (err error) {
	var (
		idx int
		v   Descriptor
	)

	if fimg.h.Dfree == 0 {
		return fmt.Errorf("no descriptor table free entry")
	}

	// look for a free entry in the descriptor table
	for idx, v = range fimg.DescrArr {
		if !v.Used {
			break
		}
	}
	if int64(idx) == fimg.h.Dtotal-1 && fimg.DescrArr[idx].Used {
		return fmt.Errorf("no descriptor table free entry, warning: header.Dfree was > 0")
	}

	// fill in SIF file descriptor
	if err = fillDescriptor(fimg, idx, input); err != nil {
		return
	}

	// write data object associated to the descriptor in SIF file
	if err = writeDataObject(fimg, idx, input); err != nil {
		return fmt.Errorf("writing data object for SIF file: %s", err)
	}

	// update some global header fields from adding this new descriptor
	fimg.h.Dfree--
	fimg.h.Datalen += fimg.DescrArr[idx].Storelen

	return
}

// Release and write the data object descriptor to backing storage (SIF container file).
func writeDescriptors(fimg *FileImage) error {
	// first, move to descriptor start offset
	if _, err := fimg.Fp.Seek(DescrStartOffset, 0); err != nil {
		return fmt.Errorf("seeking to descriptor start offset: %s", err)
	}

	for _, v := range fimg.DescrArr {
		if err := binary.Write(fimg.Fp, binary.LittleEndian, v); err != nil {
			return fmt.Errorf("binary writing descrtable to buf: %s", err)
		}
	}
	fimg.h.Descrlen = int64(binary.Size(fimg.DescrArr))

	return nil
}

// Write the global header to file.
func writeHeader(fimg *FileImage) error {
	// first, move to descriptor start offset
	if _, err := fimg.Fp.Seek(0, 0); err != nil {
		return fmt.Errorf("seeking to beginning of the file: %s", err)
	}

	if err := binary.Write(fimg.Fp, binary.LittleEndian, fimg.h); err != nil {
		return fmt.Errorf("binary writing header to buf: %s", err)
	}

	return nil
}

// createOpts accumulates container creation options.
type createOpts struct {
	ID         uuid.UUID
	InputDescr []DescriptorInput
	GetTime    func() time.Time
}

// CreateOpt are used to specify container creation options.
type CreateOpt func(*createOpts) error

// WithID specifies id as the unique ID.
func WithID(id string) CreateOpt {
	return func(co *createOpts) error {
		id, err := uuid.Parse(id)
		co.ID = id
		return err
	}
}

// WithDescriptors appends dis to the list of descriptors.
func WithDescriptors(dis ...DescriptorInput) CreateOpt {
	return func(co *createOpts) error {
		co.InputDescr = append(co.InputDescr, dis...)
		return nil
	}
}

// WithTimeFunc specifies fn as the function to obtain timestamps.
func WithTimeFunc(fn func() time.Time) CreateOpt {
	return func(co *createOpts) error {
		co.GetTime = fn
		return nil
	}
}

// CreateContainer creates a new SIF container file at path, according to opts.
func CreateContainer(path string, opts ...CreateOpt) (*FileImage, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	co := createOpts{
		ID:      id,
		GetTime: time.Now,
	}

	for _, opt := range opts {
		if err := opt(&co); err != nil {
			return nil, err
		}
	}

	t := co.GetTime()

	f := &FileImage{}
	f.DescrArr = make([]Descriptor, DescrNumEntries)

	// Prepare a fresh global header
	copy(f.h.Launch[:], hdrLaunch)
	copy(f.h.Magic[:], hdrMagic)
	copy(f.h.Version[:], CurrentVersion.bytes())
	copy(f.h.Arch[:], HdrArchUnknown)
	f.h.ID = id
	f.h.Ctime = t.Unix()
	f.h.Mtime = t.Unix()
	f.h.Dfree = DescrNumEntries
	f.h.Dtotal = DescrNumEntries
	f.h.Descroff = DescrStartOffset
	f.h.Dataoff = DataStartOffset

	// Create container file
	f.Fp, err = os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return nil, fmt.Errorf("container file creation failed: %s", err)
	}
	defer f.Fp.Close()

	// set file pointer to start of data section */
	if _, err = f.Fp.Seek(DataStartOffset, 0); err != nil {
		return nil, fmt.Errorf("setting file offset pointer to DataStartOffset: %s", err)
	}

	for _, v := range co.InputDescr {
		if err := createDescriptor(f, v); err != nil {
			return nil, err
		}
	}

	// Write down the descriptor array
	if err := writeDescriptors(f); err != nil {
		return nil, err
	}

	// Write down global header to file
	if err := writeHeader(f); err != nil {
		return nil, err
	}

	return f, nil
}

func zeroData(fimg *FileImage, descr *Descriptor) error {
	// first, move to data object offset
	if _, err := fimg.Fp.Seek(descr.Fileoff, 0); err != nil {
		return fmt.Errorf("seeking to data object offset: %s", err)
	}

	var zero [4096]byte
	n := descr.Filelen
	upbound := int64(4096)
	for {
		if n < 4096 {
			upbound = n
		}

		if _, err := fimg.Fp.Write(zero[:upbound]); err != nil {
			return fmt.Errorf("writing 0's to data object")
		}
		n -= 4096
		if n <= 0 {
			break
		}
	}

	return nil
}

func resetDescriptor(fimg *FileImage, index int) error {
	// If we remove the primary partition, set the global header Arch field to HdrArchUnknown
	// to indicate that the SIF file doesn't include a primary partition and no dependency
	// on any architecture exists.
	_, idx, _ := fimg.GetPartPrimSys()
	if idx == index {
		fimg.PrimPartID = 0
		copy(fimg.h.Arch[:], HdrArchUnknown)
	}

	offset := fimg.h.Descroff + int64(index)*int64(binary.Size(fimg.DescrArr[0]))

	// first, move to descriptor offset
	if _, err := fimg.Fp.Seek(offset, 0); err != nil {
		return fmt.Errorf("seeking to descriptor: %s", err)
	}

	var emptyDesc Descriptor
	if err := binary.Write(fimg.Fp, binary.LittleEndian, emptyDesc); err != nil {
		return fmt.Errorf("binary writing empty descriptor: %s", err)
	}

	return nil
}

// AddObject add a new data object and its descriptor into the specified SIF file.
func (fimg *FileImage) AddObject(input DescriptorInput) error {
	// set file pointer to the end of data section
	if _, err := fimg.Fp.Seek(fimg.h.Dataoff+fimg.h.Datalen, 0); err != nil {
		return fmt.Errorf("setting file offset pointer to DataStartOffset: %s", err)
	}

	// create a new descriptor entry from input data
	if err := createDescriptor(fimg, input); err != nil {
		return err
	}

	// write down the descriptor array
	if err := writeDescriptors(fimg); err != nil {
		return err
	}

	fimg.h.Mtime = time.Now().Unix()
	// write down global header to file
	if err := writeHeader(fimg); err != nil {
		return err
	}

	if err := fimg.Fp.Sync(); err != nil {
		return fmt.Errorf("while sync'ing new data object to SIF file: %s", err)
	}

	return nil
}

// descrIsLast return true if passed descriptor's object is the last in a SIF file.
func objectIsLast(fimg *FileImage, descr *Descriptor) bool {
	return fimg.Filesize == descr.Fileoff+descr.Filelen
}

// compactAtDescr joins data objects leading and following "descr" by compacting a SIF file.
func compactAtDescr(fimg *FileImage, descr *Descriptor) error {
	var prev Descriptor

	for _, v := range fimg.DescrArr {
		if !v.Used || v.ID == descr.ID {
			continue
		}
		if v.Fileoff > prev.Fileoff {
			prev = v
		}
	}
	// make sure it's not the only used descriptor first
	if prev.Used {
		if err := fimg.Fp.Truncate(prev.Fileoff + prev.Filelen); err != nil {
			return err
		}
	} else {
		if err := fimg.Fp.Truncate(descr.Fileoff); err != nil {
			return err
		}
	}
	fimg.h.Datalen -= descr.Storelen
	return nil
}

// DeleteObject removes data from a SIF file referred to by id. The descriptor for the
// data object is free'd and can be reused later. There's currently 2 clean mode specified
// by flags: DelZero, to zero out the data region for security and DelCompact to
// remove and shink the file compacting the unused area.
func (fimg *FileImage) DeleteObject(id uint32, flags int) error {
	descr, index, err := fimg.GetFromDescrID(id)
	if err != nil {
		return err
	}

	switch flags {
	case DelZero:
		if err = zeroData(fimg, descr); err != nil {
			return err
		}
	case DelCompact:
		if objectIsLast(fimg, descr) {
			if err = compactAtDescr(fimg, descr); err != nil {
				return err
			}
		} else {
			return fmt.Errorf("method (DelCompact) not implemented yet")
		}
	default:
		if objectIsLast(fimg, descr) {
			if err = compactAtDescr(fimg, descr); err != nil {
				return err
			}
		}
	}

	// update some global header fields from deleting this descriptor
	fimg.h.Dfree++
	fimg.h.Mtime = time.Now().Unix()

	// zero out the unused descriptor
	if err = resetDescriptor(fimg, index); err != nil {
		return err
	}

	// update global header
	if err = writeHeader(fimg); err != nil {
		return err
	}

	if err := fimg.Fp.Sync(); err != nil {
		return fmt.Errorf("while sync'ing deleted data object to SIF file: %s", err)
	}

	return nil
}

// SetPartExtra serializes the partition and fs type info into a binary buffer.
func (di *DescriptorInput) SetPartExtra(fs Fstype, part Parttype, arch string) error {
	extra := Partition{
		Fstype:   fs,
		Parttype: part,
	}
	if arch == HdrArchUnknown {
		return fmt.Errorf("architecture not supported: %v", arch)
	}
	copy(extra.Arch[:], arch)

	// serialize the partition data for integration with the base descriptor input
	return binary.Write(&di.Extra, binary.LittleEndian, extra)
}

// SetSignExtra serializes the hash type and the entity info into a binary buffer.
func (di *DescriptorInput) SetSignExtra(hash Hashtype, entity string) error {
	extra := Signature{
		Hashtype: hash,
	}

	h, err := hex.DecodeString(entity)
	if err != nil {
		return err
	}
	copy(extra.Entity[:], h)

	// serialize the signature data for integration with the base descriptor input
	return binary.Write(&di.Extra, binary.LittleEndian, extra)
}

// SetCryptoMsgExtra serializes the message format and type info into a binary buffer.
func (di *DescriptorInput) SetCryptoMsgExtra(format Formattype, message Messagetype) error {
	extra := CryptoMessage{
		Formattype:  format,
		Messagetype: message,
	}

	// serialize the message data for integration with the base descriptor input
	return binary.Write(&di.Extra, binary.LittleEndian, extra)
}

// SetPrimPart sets the specified system partition to be the primary one.
func (fimg *FileImage) SetPrimPart(id uint32) error {
	descr, _, err := fimg.GetFromDescrID(id)
	if err != nil {
		return err
	}

	if descr.Datatype != DataPartition {
		return fmt.Errorf("not a volume partition")
	}

	ptype, err := descr.GetPartType()
	if err != nil {
		return err
	}

	// if already primary system partition, nothing to do
	if ptype == PartPrimSys {
		return nil
	}

	if ptype != PartSystem {
		return fmt.Errorf("partition must be of system type")
	}

	olddescr, _, err := fimg.GetPartPrimSys()
	if err != nil && err != ErrNotFound {
		return err
	}

	fs, err := descr.GetFsType()
	if err != nil {
		return nil
	}

	arch, err := descr.GetArch()
	if err != nil {
		return err
	}

	copy(fimg.h.Arch[:], arch[:])
	fimg.PrimPartID = descr.ID

	extra := Partition{
		Fstype:   fs,
		Parttype: PartPrimSys,
	}
	copy(extra.Arch[:], arch[:])

	var extrabuf bytes.Buffer
	if err := binary.Write(&extrabuf, binary.LittleEndian, extra); err != nil {
		return err
	}
	descr.setExtra(extrabuf.Bytes())

	if olddescr != nil {
		oldfs, err := olddescr.GetFsType()
		if err != nil {
			return nil
		}
		oldarch, err := olddescr.GetArch()
		if err != nil {
			return nil
		}

		oldextra := Partition{
			Fstype:   oldfs,
			Parttype: PartSystem,
		}
		copy(oldextra.Arch[:], oldarch[:])

		var oldextrabuf bytes.Buffer
		if err := binary.Write(&oldextrabuf, binary.LittleEndian, oldextra); err != nil {
			return err
		}
		olddescr.setExtra(oldextrabuf.Bytes())
	}

	// write down the descriptor array
	if err := writeDescriptors(fimg); err != nil {
		return err
	}

	fimg.h.Mtime = time.Now().Unix()
	// write down global header to file
	if err := writeHeader(fimg); err != nil {
		return err
	}

	if err := fimg.Fp.Sync(); err != nil {
		return fmt.Errorf("while sync'ing new data object to SIF file: %s", err)
	}

	return nil
}
