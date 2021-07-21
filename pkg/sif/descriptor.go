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
	Arch     [hdrArchLen]byte // arch the image is built for
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

// GetFsType extracts the Fstype field from the Extra field of a Partition Descriptor.
func (d rawDescriptor) GetFsType() (FSType, error) {
	if d.Datatype != DataPartition {
		return -1, fmt.Errorf("expected DataPartition, got %v", d.Datatype)
	}

	var pinfo partition
	b := bytes.NewReader(d.Extra[:])
	if err := binary.Read(b, binary.LittleEndian, &pinfo); err != nil {
		return -1, fmt.Errorf("while extracting Partition extra info: %s", err)
	}

	return pinfo.Fstype, nil
}

// GetPartType extracts the Parttype field from the Extra field of a Partition Descriptor.
func (d rawDescriptor) GetPartType() (PartType, error) {
	if d.Datatype != DataPartition {
		return -1, fmt.Errorf("expected DataPartition, got %v", d.Datatype)
	}

	var pinfo partition
	b := bytes.NewReader(d.Extra[:])
	if err := binary.Read(b, binary.LittleEndian, &pinfo); err != nil {
		return -1, fmt.Errorf("while extracting Partition extra info: %s", err)
	}

	return pinfo.Parttype, nil
}

// GetArch extracts the Arch field from the Extra field of a Partition Descriptor.
func (d rawDescriptor) GetArch() ([hdrArchLen]byte, error) {
	if d.Datatype != DataPartition {
		return [hdrArchLen]byte{}, fmt.Errorf("expected DataPartition, got %v", d.Datatype)
	}

	var pinfo partition
	b := bytes.NewReader(d.Extra[:])
	if err := binary.Read(b, binary.LittleEndian, &pinfo); err != nil {
		return [hdrArchLen]byte{}, fmt.Errorf("while extracting Partition extra info: %s", err)
	}

	return pinfo.Arch, nil
}

// GetHashType extracts the Hashtype field from the Extra field of a Signature Descriptor.
func (d rawDescriptor) GetHashType() (HashType, error) {
	if d.Datatype != DataSignature {
		return -1, fmt.Errorf("expected DataSignature, got %v", d.Datatype)
	}

	var sinfo signature
	b := bytes.NewReader(d.Extra[:])
	if err := binary.Read(b, binary.LittleEndian, &sinfo); err != nil {
		return -1, fmt.Errorf("while extracting Signature extra info: %s", err)
	}

	return sinfo.Hashtype, nil
}

// GetEntity extracts the signing entity field from the Extra field of a Signature Descriptor.
func (d rawDescriptor) GetEntity() ([]byte, error) {
	if d.Datatype != DataSignature {
		return nil, fmt.Errorf("expected DataSignature, got %v", d.Datatype)
	}

	var sinfo signature
	b := bytes.NewReader(d.Extra[:])
	if err := binary.Read(b, binary.LittleEndian, &sinfo); err != nil {
		return nil, fmt.Errorf("while extracting Signature extra info: %s", err)
	}

	return sinfo.Entity[:], nil
}

// GetEntityString returns the string version of the stored entity.
func (d rawDescriptor) GetEntityString() (string, error) {
	fingerprint, err := d.GetEntity()
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%0X", fingerprint[:20]), nil
}

// GetFormatType extracts the Formattype field from the Extra field of a Cryptographic Message Descriptor.
func (d rawDescriptor) GetFormatType() (FormatType, error) {
	if d.Datatype != DataCryptoMessage {
		return -1, fmt.Errorf("expected DataCryptoMessage, got %v", d.Datatype)
	}

	var cinfo cryptoMessage
	b := bytes.NewReader(d.Extra[:])
	if err := binary.Read(b, binary.LittleEndian, &cinfo); err != nil {
		return -1, fmt.Errorf("while extracting Crypto extra info: %s", err)
	}

	return cinfo.Formattype, nil
}

// GetMessageType extracts the Messagetype field from the Extra field of a Cryptographic Message Descriptor.
func (d rawDescriptor) GetMessageType() (MessageType, error) {
	if d.Datatype != DataCryptoMessage {
		return -1, fmt.Errorf("expected DataCryptoMessage, got %v", d.Datatype)
	}

	var cinfo cryptoMessage
	b := bytes.NewReader(d.Extra[:])
	if err := binary.Read(b, binary.LittleEndian, &cinfo); err != nil {
		return -1, fmt.Errorf("while extracting Crypto extra info: %s", err)
	}

	return cinfo.Messagetype, nil
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
