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
	"errors"
	"fmt"
	"io"
	"strings"
)

// Descriptor represents the SIF descriptor type.
type Descriptor struct {
	rawDescriptor
}

// rawDescriptor represents the on-disk descriptor type.
type rawDescriptor struct {
	Datatype DataType // informs of descriptor type
	Used     bool     // is the descriptor in use
	ID       uint32   // a unique id for this data object
	Groupid  uint32   // object group this data object is related to
	Link     uint32   // special link or relation to an id or group
	Fileoff  int64    // offset from start of image file
	Filelen  int64    // length of data in file
	Storelen int64    // length of data + alignment to store data in file

	Ctime int64                 // image creation time
	Mtime int64                 // last modification time
	UID   int64                 // Deprecated: UID exists for historical compatibility and should not be used.
	GID   int64                 // Deprecated: GID exists for historical compatibility and should not be used.
	Name  [DescrNameLen]byte    // descriptor name (string identifier)
	Extra [DescrMaxPrivLen]byte // big enough for extra data below
}

// partition represents the SIF partition data object descriptor.
type partition struct {
	Fstype   FSType
	Parttype PartType
	Arch     archType
}

// signature represents the SIF signature data object descriptor.
type signature struct {
	Hashtype HashType
	Entity   [DescrEntityLen]byte
}

// cryptoMessage represents the SIF crypto message object descriptor.
type cryptoMessage struct {
	Formattype  FormatType
	Messagetype MessageType
}

var errNameTooLarge = errors.New("name value too large")

// setName encodes name into the name field of d.
func (d *rawDescriptor) setName(name string) error {
	if len(name) > len(d.Name) {
		return errNameTooLarge
	}

	for i := copy(d.Name[:], name); i < len(d.Name); i++ {
		d.Name[i] = 0
	}

	return nil
}

var errExtraTooLarge = errors.New("extra value too large")

// setExtra encodes v into the extra field of d.
func (d *rawDescriptor) setExtra(v interface{}) error {
	if v == nil {
		return nil
	}

	if binary.Size(v) > len(d.Extra) {
		return errExtraTooLarge
	}

	b := new(bytes.Buffer)
	if err := binary.Write(b, binary.LittleEndian, v); err != nil {
		return err
	}

	for i := copy(d.Extra[:], b.Bytes()); i < len(d.Extra); i++ {
		d.Extra[i] = 0
	}

	return nil
}

// GetDataType returns the type of data object.
func (d rawDescriptor) GetDataType() DataType { return d.Datatype }

// GetID returns the data object ID of d.
func (d rawDescriptor) GetID() uint32 { return d.ID }

// GetGroupID returns the data object group ID of d, or zero if d is not part of a data object
// group.
func (d rawDescriptor) GetGroupID() uint32 { return d.Groupid &^ DescrGroupMask }

// GetLinkedID returns the object/group ID d is linked to, or zero if d does not contain a linked
// ID. If isGroup is true, the returned id is an object group ID. Otherwise, the returned id is a
// data object ID.
func (d rawDescriptor) GetLinkedID() (id uint32, isGroup bool) {
	return d.Link &^ DescrGroupMask, d.Link&DescrGroupMask == DescrGroupMask
}

// GetSize returns the data object size.
func (d rawDescriptor) GetSize() int64 { return d.Filelen }

// GetName returns the name tag associated with the descriptor. Analogous to file name.
func (d rawDescriptor) GetName() string { return strings.TrimRight(string(d.Name[:]), "\000") }

// GetPartitionMetadata gets metadata for a partition data object.
func (d rawDescriptor) GetPartitionMetadata() (fs FSType, pt PartType, arch string, err error) {
	if got, want := d.Datatype, DataPartition; got != want {
		return 0, 0, "", &unexpectedDataTypeError{got, want}
	}

	var p partition

	b := bytes.NewReader(d.Extra[:])
	if err := binary.Read(b, binary.LittleEndian, &p); err != nil {
		return 0, 0, "", fmt.Errorf("%w", err)
	}

	return p.Fstype, p.Parttype, p.Arch.GoArch(), nil
}

// isPartitionOfType returns true if d is a partition data object of type pt.
func (d rawDescriptor) isPartitionOfType(pt PartType) bool {
	_, t, _, err := d.GetPartitionMetadata()
	if err != nil {
		return false
	}
	return t == pt
}

// GetSignatureMetadata gets metadata for a signature data object.
func (d rawDescriptor) GetSignatureMetadata() (ht HashType, fp [20]byte, err error) {
	if got, want := d.Datatype, DataSignature; got != want {
		return ht, fp, &unexpectedDataTypeError{got, want}
	}

	var s signature

	b := bytes.NewReader(d.Extra[:])
	if err := binary.Read(b, binary.LittleEndian, &s); err != nil {
		return ht, fp, fmt.Errorf("%w", err)
	}

	copy(fp[:], s.Entity[:])

	return s.Hashtype, fp, nil
}

// GetCryptoMessageMetadata gets metadata for a crypto message data object.
func (d rawDescriptor) GetCryptoMessageMetadata() (FormatType, MessageType, error) {
	if got, want := d.Datatype, DataCryptoMessage; got != want {
		return 0, 0, &unexpectedDataTypeError{got, want}
	}

	var m cryptoMessage

	b := bytes.NewReader(d.Extra[:])
	if err := binary.Read(b, binary.LittleEndian, &m); err != nil {
		return 0, 0, fmt.Errorf("%w", err)
	}

	return m.Formattype, m.Messagetype, nil
}

// GetData returns the data object associated with descriptor d from f.
func (d rawDescriptor) GetData(f *FileImage) ([]byte, error) {
	b := make([]byte, d.Filelen)
	if _, err := io.ReadFull(d.GetReader(f), b); err != nil {
		return nil, err
	}
	return b, nil
}

// GetReader returns a io.Reader that reads the data object associated with descriptor d from f.
func (d rawDescriptor) GetReader(f *FileImage) io.Reader {
	return io.NewSectionReader(f.fp, d.Fileoff, d.Filelen)
}

// GetIntegrityReader returns an io.Reader that reads the integrity-protected fields from d.
func (d rawDescriptor) GetIntegrityReader(relativeID uint32) io.Reader {
	fields := []interface{}{
		d.Datatype,
		d.Used,
		relativeID,
		d.Link,
		d.Filelen,
		d.Ctime,
		d.UID,
		d.GID,
	}

	// Encode endian-sensitive fields.
	data := bytes.Buffer{}
	for _, f := range fields {
		if err := binary.Write(&data, binary.LittleEndian, f); err != nil {
			panic(err) // (*bytes.Buffer).Write() is documented as always returning a nil error.
		}
	}

	return io.MultiReader(
		&data,
		bytes.NewReader(d.Name[:]),
		bytes.NewReader(d.Extra[:]),
	)
}
