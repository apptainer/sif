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
func writeDataObject(ws io.WriteSeeker, di DescriptorInput, d *rawDescriptor) error {
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
	n, err := io.Copy(ws, di.r)
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
	var d *rawDescriptor

	for i, od := range f.rds {
		if !od.Used {
			d = &f.rds[i]
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
		ds, err := f.GetDescriptors(WithPartitionType(PartPrimSys))
		if err != nil {
			return err
		}
		if len(ds) > 0 {
			return fmt.Errorf("only 1 FS data object may be a primary partition")
		}

		f.h.Arch = p.Arch
	}

	// Update minimum object ID map.
	if minID, ok := f.minIDs[d.Groupid]; !ok || d.ID < minID {
		f.minIDs[d.Groupid] = d.ID
	}

	if err := writeDataObject(f.rw, di, d); err != nil {
		return err
	}

	f.h.Dfree--
	f.h.Datalen += d.Storelen

	return nil
}

// writeDescriptors writes the descriptors in f to backing storage.
func (f *FileImage) writeDescriptors() error {
	if _, err := f.rw.Seek(descrStartOffset, io.SeekStart); err != nil {
		return err
	}

	for _, v := range f.rds {
		if err := binary.Write(f.rw, binary.LittleEndian, v); err != nil {
			return err
		}
	}
	f.h.Descrlen = int64(binary.Size(f.rds))

	return nil
}

// writeHeader writes the the global header in f to backing storage.
func (f *FileImage) writeHeader() error {
	if _, err := f.rw.Seek(0, io.SeekStart); err != nil {
		return err
	}

	return binary.Write(f.rw, binary.LittleEndian, f.h)
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

// OptCreateWithTime specifies t as the image creation time.
func OptCreateWithTime(t time.Time) CreateOpt {
	return func(co *createOpts) error {
		co.t = t
		return nil
	}
}

// createContainer creates a new SIF container file in rw, according to opts.
func createContainer(rw ReadWriter, co createOpts) (*FileImage, error) {
	h := header{
		Arch:     hdrArchUnknown,
		ID:       co.id,
		Ctime:    co.t.Unix(),
		Mtime:    co.t.Unix(),
		Dfree:    descrNumEntries,
		Dtotal:   descrNumEntries,
		Descroff: descrStartOffset,
		Dataoff:  dataStartOffset,
	}
	copy(h.Launch[:], hdrLaunch)
	copy(h.Magic[:], hdrMagic)
	copy(h.Version[:], CurrentVersion.bytes())

	f := &FileImage{
		rw:     rw,
		h:      h,
		rds:    make([]rawDescriptor, descrNumEntries),
		minIDs: make(map[uint32]uint32),
	}

	if _, err := f.rw.Seek(dataStartOffset, io.SeekStart); err != nil {
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

func zeroData(fimg *FileImage, descr *rawDescriptor) error {
	// first, move to data object offset
	if _, err := fimg.rw.Seek(descr.Fileoff, io.SeekStart); err != nil {
		return fmt.Errorf("seeking to data object offset: %s", err)
	}

	var zero [4096]byte
	n := descr.Filelen
	upbound := int64(4096)
	for {
		if n < 4096 {
			upbound = n
		}

		if _, err := fimg.rw.Write(zero[:upbound]); err != nil {
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
	if fimg.rds[index].isPartitionOfType(PartPrimSys) {
		fimg.h.Arch = hdrArchUnknown
	}

	offset := fimg.h.Descroff + int64(index)*int64(binary.Size(fimg.rds[0]))

	// first, move to descriptor offset
	if _, err := fimg.rw.Seek(offset, io.SeekStart); err != nil {
		return fmt.Errorf("seeking to descriptor: %s", err)
	}

	var emptyDesc rawDescriptor
	if err := binary.Write(fimg.rw, binary.LittleEndian, emptyDesc); err != nil {
		return fmt.Errorf("binary writing empty descriptor: %s", err)
	}

	return nil
}

// addOpts accumulates object add options.
type addOpts struct {
	t time.Time
}

// AddOpt are used to specify object add options.
type AddOpt func(*addOpts) error

// OptAddWithTime specifies t as the image modification time.
func OptAddWithTime(t time.Time) AddOpt {
	return func(ao *addOpts) error {
		ao.t = t
		return nil
	}
}

// AddObject add a new data object and its descriptor into the specified SIF file.
//
// By default, the image modification time is set to the data object creation time. To override
// this, use OptAddWithTime.
func (f *FileImage) AddObject(input DescriptorInput, opts ...AddOpt) error {
	ao := addOpts{
		t: input.opts.t,
	}

	for _, opt := range opts {
		if err := opt(&ao); err != nil {
			return err
		}
	}

	// set file pointer to the end of data section
	if _, err := f.rw.Seek(f.h.Dataoff+f.h.Datalen, io.SeekStart); err != nil {
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

	f.h.Mtime = ao.t.Unix()

	return f.writeHeader()
}

// descrIsLast return true if passed descriptor's object is the last in a SIF file.
func objectIsLast(f *FileImage, d *rawDescriptor) bool {
	isLast := true

	end := d.Fileoff + d.Filelen
	f.WithDescriptors(func(d Descriptor) bool {
		isLast = d.Offset()+d.Size() <= end
		return !isLast
	})

	return isLast
}

// compactAtDescr joins data objects leading and following "descr" by compacting a SIF file.
func compactAtDescr(fimg *FileImage, descr *rawDescriptor) error {
	var prev rawDescriptor

	for _, v := range fimg.rds {
		if !v.Used || v.ID == descr.ID {
			continue
		}
		if v.Fileoff > prev.Fileoff {
			prev = v
		}
	}
	// make sure it's not the only used descriptor first
	if prev.Used {
		if err := fimg.rw.Truncate(prev.Fileoff + prev.Filelen); err != nil {
			return err
		}
	} else {
		if err := fimg.rw.Truncate(descr.Fileoff); err != nil {
			return err
		}
	}
	fimg.h.Datalen -= descr.Storelen
	return nil
}

// deleteOpts accumulates object deletion options.
type deleteOpts struct {
	zero    bool
	compact bool
	t       time.Time
}

// DeleteOpt are used to specify object deletion options.
type DeleteOpt func(*deleteOpts) error

// OptDeleteZero specifies whether the deleted object should be zeroed.
func OptDeleteZero(b bool) DeleteOpt {
	return func(do *deleteOpts) error {
		do.zero = b
		return nil
	}
}

// OptDeleteCompact specifies whether the image should be compacted following object deletion.
func OptDeleteCompact(b bool) DeleteOpt {
	return func(do *deleteOpts) error {
		do.compact = b
		return nil
	}
}

// OptDeleteWithTime specifies t as the image modification time.
func OptDeleteWithTime(t time.Time) DeleteOpt {
	return func(do *deleteOpts) error {
		do.t = t
		return nil
	}
}

// DeleteObject deletes the data object with id, according to opts.
//
// To zero the data region of the deleted object, use OptDeleteZero. To compact the file following
// object deletion, use OptDeleteCompact.
//
// By default, the image modification time is set to time.Now(). To override this, use
// OptDeleteWithTime.
func (f *FileImage) DeleteObject(id uint32, opts ...DeleteOpt) error {
	do := deleteOpts{
		t: time.Now(),
	}

	for _, opt := range opts {
		if err := opt(&do); err != nil {
			return err
		}
	}

	d, err := f.getDescriptor(WithID(id))
	if err != nil {
		return err
	}

	index := 0
	for i, od := range f.rds {
		if od.ID == id {
			index = i
			break
		}
	}

	if do.zero {
		if err := zeroData(f, d); err != nil {
			return err
		}
	}

	if do.compact {
		if objectIsLast(f, d) {
			if err := compactAtDescr(f, d); err != nil {
				return err
			}
		} else {
			return fmt.Errorf("compact not implemented yet")
		}
	}

	f.h.Dfree++
	f.h.Mtime = do.t.Unix()

	if err = resetDescriptor(f, index); err != nil {
		return err
	}

	return f.writeHeader()
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

	fs, pt, arch, err := descr.getPartitionMetadata()
	if err != nil {
		return err
	}

	// if already primary system partition, nothing to do
	if pt == PartPrimSys {
		return nil
	}

	if pt != PartSystem {
		return fmt.Errorf("partition must be of system type")
	}

	olddescr, err := f.getDescriptor(WithPartitionType(PartPrimSys))
	if err != nil && !errors.Is(err, ErrObjectNotFound) {
		return err
	}

	f.h.Arch = getSIFArch(arch)

	extra := partition{
		Fstype:   fs,
		Parttype: PartPrimSys,
	}
	copy(extra.Arch[:], arch)

	if err := descr.setExtra(extra); err != nil {
		return err
	}

	if olddescr != nil {
		oldfs, _, oldarch, err := olddescr.getPartitionMetadata()
		if err != nil {
			return err
		}

		oldextra := partition{
			Fstype:   oldfs,
			Parttype: PartSystem,
			Arch:     getSIFArch(oldarch),
		}

		if err := olddescr.setExtra(oldextra); err != nil {
			return err
		}
	}

	// write down the descriptor array
	if err := f.writeDescriptors(); err != nil {
		return err
	}

	f.h.Mtime = time.Now().Unix()

	return f.writeHeader()
}
