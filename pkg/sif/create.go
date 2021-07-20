// Copyright (c) 2018-2021, Sylabs Inc. All rights reserved.
// Copyright (c) 2017, SingularityWare, LLC. All rights reserved.
// Copyright (c) 2017, Yannick Cote <yhcote@gmail.com> All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package sif

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/google/uuid"
)

// nextAligned finds the next offset that satisfies alignment.
func nextAligned(offset int64, alignment int) int64 {
	align64 := uint64(alignment)
	offset64 := uint64(offset)

	if offset64%align64 != 0 {
		offset64 = (offset64 & ^(align64 - 1)) + align64
	}

	return int64(offset64)
}

// writeDataObject writes the data object described by di to ws, recording details in d.
func writeDataObject(ws io.WriteSeeker, di DescriptorInput, d *Descriptor) error {
	if err := di.fillDescriptor(d); err != nil {
		return err
	}

	// Record initial offset.
	curoff, err := ws.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}

	// Advance in accordance with alignment, record offset.
	offset, err := ws.Seek(nextAligned(curoff, di.opts.alignment), io.SeekStart)
	if err != nil {
		return err
	}

	// Write the data object.
	n, err := io.Copy(ws, di.fp)
	if err != nil {
		return err
	}

	d.Used = true
	d.Fileoff = offset
	d.Filelen = n
	d.Storelen = offset - curoff + n

	return nil
}

// writeDataObject locates a free descriptor in f, writes the data object described by di to
// backing storage, recording data object details in the descriptor.
func (f *FileImage) writeDataObject(di DescriptorInput) error {
	var d *Descriptor

	for i, od := range f.descrArr {
		if !od.Used {
			d = &f.descrArr[i]
			d.ID = uint32(i) + 1
			break
		}
	}

	if d == nil {
		return fmt.Errorf("no free descriptor table entry")
	}

	// If this is a primary partition, verify there isn't another primary partition, and update the
	// architecture in the global header.
	if p, ok := di.opts.extra.(partition); ok && p.Parttype == PartPrimSys {
		if f.primPartID != 0 {
			return fmt.Errorf("only 1 FS data object may be a primary partition")
		}
		f.primPartID = d.ID

		f.h.Arch = p.Arch
	}

	if err := writeDataObject(f.fp, di, d); err != nil {
		return err
	}

	f.h.Dfree--
	f.h.Datalen += d.Storelen

	return nil
}

// writeDescriptors writes the descriptors in f to backing storage.
func (f *FileImage) writeDescriptors() error {
	if _, err := f.fp.Seek(DescrStartOffset, io.SeekStart); err != nil {
		return err
	}

	for _, v := range f.descrArr {
		if err := binary.Write(f.fp, binary.LittleEndian, v); err != nil {
			return err
		}
	}
	f.h.Descrlen = int64(binary.Size(f.descrArr))

	return nil
}

// writeHeader writes the the global header in f to backing storage.
func (f *FileImage) writeHeader() error {
	if _, err := f.fp.Seek(0, io.SeekStart); err != nil {
		return err
	}

	return binary.Write(f.fp, binary.LittleEndian, f.h)
}

// createOpts accumulates container creation options.
type createOpts struct {
	id  uuid.UUID
	dis []DescriptorInput
	t   time.Time
}

// CreateOpt are used to specify container creation options.
type CreateOpt func(*createOpts) error

// OptCreateWithID specifies id as the unique ID.
func OptCreateWithID(id string) CreateOpt {
	return func(co *createOpts) error {
		id, err := uuid.Parse(id)
		co.id = id
		return err
	}
}

// OptCreateWithDescriptors appends dis to the list of descriptors.
func OptCreateWithDescriptors(dis ...DescriptorInput) CreateOpt {
	return func(co *createOpts) error {
		co.dis = append(co.dis, dis...)
		return nil
	}
}

// OptCreateWithTime specifies t as the creation time.
func OptCreateWithTime(t time.Time) CreateOpt {
	return func(co *createOpts) error {
		co.t = t
		return nil
	}
}

// createContainer creates a new SIF container file in fp, according to opts.
func createContainer(fp ReadWriter, co createOpts) (*FileImage, error) {
	h := header{
		ID:       co.id,
		Ctime:    co.t.Unix(),
		Mtime:    co.t.Unix(),
		Dfree:    DescrNumEntries,
		Dtotal:   DescrNumEntries,
		Descroff: DescrStartOffset,
		Dataoff:  DataStartOffset,
	}
	copy(h.Launch[:], hdrLaunch)
	copy(h.Magic[:], hdrMagic)
	copy(h.Version[:], CurrentVersion.bytes())
	copy(h.Arch[:], HdrArchUnknown)

	f := &FileImage{
		h:        h,
		fp:       fp,
		descrArr: make([]Descriptor, DescrNumEntries),
	}

	if _, err := f.fp.Seek(DataStartOffset, io.SeekStart); err != nil {
		return nil, err
	}

	for _, di := range co.dis {
		if err := f.writeDataObject(di); err != nil {
			return nil, err
		}
	}

	if err := f.writeDescriptors(); err != nil {
		return nil, err
	}

	if err := f.writeHeader(); err != nil {
		return nil, err
	}

	return f, nil
}

// CreateContainer creates a new SIF container file at path, according to opts.
//
// On success, a FileImage is returned. The caller must call UnloadContainer to ensure resources
// are released.
func CreateContainer(path string, opts ...CreateOpt) (f *FileImage, err error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	co := createOpts{
		id: id,
		t:  time.Now(),
	}

	for _, opt := range opts {
		if err := opt(&co); err != nil {
			return nil, fmt.Errorf("%w", err)
		}
	}

	fp, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	defer func() {
		if err != nil {
			fp.Close()
			os.Remove(fp.Name())
		}
	}()

	f, err = createContainer(fp, co)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	return f, nil
}

func zeroData(fimg *FileImage, descr Descriptor) error {
	// first, move to data object offset
	if _, err := fimg.fp.Seek(descr.Fileoff, io.SeekStart); err != nil {
		return fmt.Errorf("seeking to data object offset: %s", err)
	}

	var zero [4096]byte
	n := descr.Filelen
	upbound := int64(4096)
	for {
		if n < 4096 {
			upbound = n
		}

		if _, err := fimg.fp.Write(zero[:upbound]); err != nil {
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
	if pt, err := fimg.descrArr[index].GetPartType(); err == nil && pt == PartPrimSys {
		fimg.primPartID = 0
		copy(fimg.h.Arch[:], HdrArchUnknown)
	}

	offset := fimg.h.Descroff + int64(index)*int64(binary.Size(fimg.descrArr[0]))

	// first, move to descriptor offset
	if _, err := fimg.fp.Seek(offset, io.SeekStart); err != nil {
		return fmt.Errorf("seeking to descriptor: %s", err)
	}

	var emptyDesc Descriptor
	if err := binary.Write(fimg.fp, binary.LittleEndian, emptyDesc); err != nil {
		return fmt.Errorf("binary writing empty descriptor: %s", err)
	}

	return nil
}

// AddObject add a new data object and its descriptor into the specified SIF file.
func (f *FileImage) AddObject(input DescriptorInput) error {
	// set file pointer to the end of data section
	if _, err := f.fp.Seek(f.h.Dataoff+f.h.Datalen, io.SeekStart); err != nil {
		return fmt.Errorf("setting file offset pointer to DataStartOffset: %s", err)
	}

	// create a new descriptor entry from input data
	if err := f.writeDataObject(input); err != nil {
		return err
	}

	// write down the descriptor array
	if err := f.writeDescriptors(); err != nil {
		return err
	}

	f.h.Mtime = time.Now().Unix()
	// write down global header to file
	if err := f.writeHeader(); err != nil {
		return err
	}

	if err := f.fp.Sync(); err != nil {
		return fmt.Errorf("while sync'ing new data object to SIF file: %s", err)
	}

	return nil
}

// descrIsLast return true if passed descriptor's object is the last in a SIF file.
func objectIsLast(fimg *FileImage, descr Descriptor) bool {
	return fimg.size == descr.Fileoff+descr.Filelen
}

// compactAtDescr joins data objects leading and following "descr" by compacting a SIF file.
func compactAtDescr(fimg *FileImage, descr Descriptor) error {
	var prev Descriptor

	for _, v := range fimg.descrArr {
		if !v.Used || v.ID == descr.ID {
			continue
		}
		if v.Fileoff > prev.Fileoff {
			prev = v
		}
	}
	// make sure it's not the only used descriptor first
	if prev.Used {
		if err := fimg.fp.Truncate(prev.Fileoff + prev.Filelen); err != nil {
			return err
		}
	} else {
		if err := fimg.fp.Truncate(descr.Fileoff); err != nil {
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
func (f *FileImage) DeleteObject(id uint32, flags int) error {
	descr, err := f.GetDescriptor(WithID(id))
	if err != nil {
		return err
	}

	index := 0
	for i, od := range f.descrArr {
		if od.ID == id {
			index = i
			break
		}
	}

	switch flags {
	case DelZero:
		if err = zeroData(f, descr); err != nil {
			return err
		}
	case DelCompact:
		if objectIsLast(f, descr) {
			if err = compactAtDescr(f, descr); err != nil {
				return err
			}
		} else {
			return fmt.Errorf("method (DelCompact) not implemented yet")
		}
	default:
		if objectIsLast(f, descr) {
			if err = compactAtDescr(f, descr); err != nil {
				return err
			}
		}
	}

	// update some global header fields from deleting this descriptor
	f.h.Dfree++
	f.h.Mtime = time.Now().Unix()

	// zero out the unused descriptor
	if err = resetDescriptor(f, index); err != nil {
		return err
	}

	// update global header
	if err = f.writeHeader(); err != nil {
		return err
	}

	if err := f.fp.Sync(); err != nil {
		return fmt.Errorf("while sync'ing deleted data object to SIF file: %s", err)
	}

	return nil
}

// SetPrimPart sets the specified system partition to be the primary one.
func (f *FileImage) SetPrimPart(id uint32) error {
	descr, err := f.getDescriptor(WithID(id))
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

	olddescr, err := f.getDescriptor(WithPartitionType(PartPrimSys))
	if err != nil && !errors.Is(err, ErrObjectNotFound) {
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

	copy(f.h.Arch[:], arch[:])
	f.primPartID = descr.ID

	extra := partition{
		Fstype:   fs,
		Parttype: PartPrimSys,
	}
	copy(extra.Arch[:], arch[:])

	if err := descr.setExtra(extra); err != nil {
		return err
	}

	if olddescr != nil {
		oldfs, err := olddescr.GetFsType()
		if err != nil {
			return nil
		}
		oldarch, err := olddescr.GetArch()
		if err != nil {
			return nil
		}

		oldextra := partition{
			Fstype:   oldfs,
			Parttype: PartSystem,
		}
		copy(oldextra.Arch[:], oldarch[:])

		if err := olddescr.setExtra(oldextra); err != nil {
			return err
		}
	}

	// write down the descriptor array
	if err := f.writeDescriptors(); err != nil {
		return err
	}

	f.h.Mtime = time.Now().Unix()
	// write down global header to file
	if err := f.writeHeader(); err != nil {
		return err
	}

	if err := f.fp.Sync(); err != nil {
		return fmt.Errorf("while sync'ing new data object to SIF file: %s", err)
	}

	return nil
}
