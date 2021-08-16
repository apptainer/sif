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
	"strings"
)

// Descriptor represents the SIF descriptor type.
type Descriptor struct {
	Datatype Datatype // informs of descriptor type
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

// setName sets the byte array field "Name" to the value of string "name".
func (d *Descriptor) setName(name string) {
	copy(d.Name[:], name)
	for i := len(name); i < len(d.Name); i++ {
		d.Name[i] = 0
	}
}

// setExtra sets the extra byte array to a provided byte array.
func (d *Descriptor) setExtra(extra []byte) {
	copy(d.Extra[:], extra)
	for i := len(extra); i < len(d.Extra); i++ {
		d.Extra[i] = 0
	}
}

// GetDataType returns the type of data object.
func (d Descriptor) GetDataType() Datatype { return d.Datatype }

// GetID returns the data object ID of d.
func (d Descriptor) GetID() uint32 { return d.ID }

// GetGroupID returns the data object group ID of d, or zero if d is not part of a data object
// group.
func (d Descriptor) GetGroupID() uint32 { return d.Groupid &^ DescrGroupMask }

// GetLinkedID returns the object/group ID d is linked to, or zero if d does not contain a linked
// ID. If isGroup is true, the returned id is an object group ID. Otherwise, the returned id is a
// data object ID.
func (d Descriptor) GetLinkedID() (id uint32, isGroup bool) {
	return d.Link &^ DescrGroupMask, d.Link&DescrGroupMask == DescrGroupMask
}

// GetSize returns the data object size.
func (d Descriptor) GetSize() int64 { return d.Filelen }

// GetName returns the name tag associated with the descriptor. Analogous to file name.
func (d Descriptor) GetName() string { return strings.TrimRight(string(d.Name[:]), "\000") }

// GetFsType extracts the Fstype field from the Extra field of a Partition Descriptor.
func (d Descriptor) GetFsType() (Fstype, error) {
	if d.Datatype != DataPartition {
		return -1, fmt.Errorf("expected DataPartition, got %v", d.Datatype)
	}

	var pinfo Partition
	b := bytes.NewReader(d.Extra[:])
	if err := binary.Read(b, binary.LittleEndian, &pinfo); err != nil {
		return -1, fmt.Errorf("while extracting Partition extra info: %s", err)
	}

	return pinfo.Fstype, nil
}

// GetPartType extracts the Parttype field from the Extra field of a Partition Descriptor.
func (d Descriptor) GetPartType() (Parttype, error) {
	if d.Datatype != DataPartition {
		return -1, fmt.Errorf("expected DataPartition, got %v", d.Datatype)
	}

	var pinfo Partition
	b := bytes.NewReader(d.Extra[:])
	if err := binary.Read(b, binary.LittleEndian, &pinfo); err != nil {
		return -1, fmt.Errorf("while extracting Partition extra info: %s", err)
	}

	return pinfo.Parttype, nil
}

// GetArch extracts the Arch field from the Extra field of a Partition Descriptor.
func (d Descriptor) GetArch() ([hdrArchLen]byte, error) {
	if d.Datatype != DataPartition {
		return [hdrArchLen]byte{}, fmt.Errorf("expected DataPartition, got %v", d.Datatype)
	}

	var pinfo Partition
	b := bytes.NewReader(d.Extra[:])
	if err := binary.Read(b, binary.LittleEndian, &pinfo); err != nil {
		return [hdrArchLen]byte{}, fmt.Errorf("while extracting Partition extra info: %s", err)
	}

	return pinfo.Arch, nil
}

// GetHashType extracts the Hashtype field from the Extra field of a Signature Descriptor.
func (d Descriptor) GetHashType() (Hashtype, error) {
	if d.Datatype != DataSignature {
		return -1, fmt.Errorf("expected DataSignature, got %v", d.Datatype)
	}

	var sinfo Signature
	b := bytes.NewReader(d.Extra[:])
	if err := binary.Read(b, binary.LittleEndian, &sinfo); err != nil {
		return -1, fmt.Errorf("while extracting Signature extra info: %s", err)
	}

	return sinfo.Hashtype, nil
}

// GetEntity extracts the signing entity field from the Extra field of a Signature Descriptor.
func (d Descriptor) GetEntity() ([]byte, error) {
	if d.Datatype != DataSignature {
		return nil, fmt.Errorf("expected DataSignature, got %v", d.Datatype)
	}

	var sinfo Signature
	b := bytes.NewReader(d.Extra[:])
	if err := binary.Read(b, binary.LittleEndian, &sinfo); err != nil {
		return nil, fmt.Errorf("while extracting Signature extra info: %s", err)
	}

	return sinfo.Entity[:], nil
}

// GetEntityString returns the string version of the stored entity.
func (d Descriptor) GetEntityString() (string, error) {
	fingerprint, err := d.GetEntity()
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%0X", fingerprint[:20]), nil
}

// GetFormatType extracts the Formattype field from the Extra field of a Cryptographic Message Descriptor.
func (d Descriptor) GetFormatType() (Formattype, error) {
	if d.Datatype != DataCryptoMessage {
		return -1, fmt.Errorf("expected DataCryptoMessage, got %v", d.Datatype)
	}

	var cinfo CryptoMessage
	b := bytes.NewReader(d.Extra[:])
	if err := binary.Read(b, binary.LittleEndian, &cinfo); err != nil {
		return -1, fmt.Errorf("while extracting Crypto extra info: %s", err)
	}

	return cinfo.Formattype, nil
}

// GetMessageType extracts the Messagetype field from the Extra field of a Cryptographic Message Descriptor.
func (d Descriptor) GetMessageType() (Messagetype, error) {
	if d.Datatype != DataCryptoMessage {
		return -1, fmt.Errorf("expected DataCryptoMessage, got %v", d.Datatype)
	}

	var cinfo CryptoMessage
	b := bytes.NewReader(d.Extra[:])
	if err := binary.Read(b, binary.LittleEndian, &cinfo); err != nil {
		return -1, fmt.Errorf("while extracting Crypto extra info: %s", err)
	}

	return cinfo.Messagetype, nil
}

// GetData returns the data object associated with descriptor d from f.
func (d Descriptor) GetData(f *FileImage) ([]byte, error) {
	b := make([]byte, d.Filelen)
	if _, err := io.ReadFull(d.GetReader(f), b); err != nil {
		return nil, err
	}
	return b, nil
}

// GetReader returns a io.Reader that reads the data object associated with descriptor d from f.
func (d Descriptor) GetReader(f *FileImage) io.Reader {
	return io.NewSectionReader(f.fp, d.Fileoff, d.Filelen)
}

// GetIntegrityReader returns an io.Reader that reads the integrity-protected fields from d.
func (d Descriptor) GetIntegrityReader(relativeID uint32) io.Reader {
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
