// Copyright (c) 2018-2021, Sylabs Inc. All rights reserved.
// Copyright (c) 2017, SingularityWare, LLC. All rights reserved.
// Copyright (c) 2017, Yannick Cote <yhcote@gmail.com> All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package sif

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

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
	Name  [descrNameLen]byte    // descriptor name (string identifier)
	Extra [descrMaxPrivLen]byte // big enough for extra data below
}

// partition represents the SIF partition data object descriptor.
type partition struct {
	Fstype   FSType
	Parttype PartType
	Arch     archType
}

// signature represents the SIF signature data object descriptor.
type signature struct {
	Hashtype hashType
	Entity   [descrEntityLen]byte
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

// getPartitionMetadata gets metadata for a partition data object.
func (d rawDescriptor) getPartitionMetadata() (fs FSType, pt PartType, arch string, err error) {
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
	_, t, _, err := d.getPartitionMetadata()
	if err != nil {
		return false
	}
	return t == pt
}

// Descriptor represents the SIF descriptor type.
type Descriptor struct {
	raw rawDescriptor
	r   io.ReaderAt
}

// DataType returns the type of data object.
func (d Descriptor) DataType() DataType { return d.raw.Datatype }

// ID returns the data object ID of d.
func (d Descriptor) ID() uint32 { return d.raw.ID }

// GroupID returns the data object group ID of d, or zero if d is not part of a data object
// group.
func (d Descriptor) GroupID() uint32 { return d.raw.Groupid &^ descrGroupMask }

// LinkedID returns the object/group ID d is linked to, or zero if d does not contain a linked
// ID. If isGroup is true, the returned id is an object group ID. Otherwise, the returned id is a
// data object ID.
func (d Descriptor) LinkedID() (id uint32, isGroup bool) {
	return d.raw.Link &^ descrGroupMask, d.raw.Link&descrGroupMask == descrGroupMask
}

// Offset returns the offset of the data object.
func (d Descriptor) Offset() int64 { return d.raw.Fileoff }

// Size returns the data object size.
func (d Descriptor) Size() int64 { return d.raw.Filelen }

// CreatedAt returns the creation time of the data object.
func (d Descriptor) CreatedAt() time.Time { return time.Unix(d.raw.Ctime, 0).UTC() }

// ModifiedAt returns the modification time of the data object.
func (d Descriptor) ModifiedAt() time.Time { return time.Unix(d.raw.Mtime, 0).UTC() }

// Name returns the name of the data object.
func (d Descriptor) Name() string { return strings.TrimRight(string(d.raw.Name[:]), "\000") }

// PartitionMetadata gets metadata for a partition data object.
func (d Descriptor) PartitionMetadata() (fs FSType, pt PartType, arch string, err error) {
	return d.raw.getPartitionMetadata()
}

var errHashUnsupported = errors.New("hash algorithm unsupported")

// getHashType converts ht into a crypto.Hash.
func getHashType(ht hashType) (crypto.Hash, error) {
	switch ht {
	case hashSHA256:
		return crypto.SHA256, nil
	case hashSHA384:
		return crypto.SHA384, nil
	case hashSHA512:
		return crypto.SHA512, nil
	case hashBLAKE2S:
		return crypto.BLAKE2s_256, nil
	case hashBLAKE2B:
		return crypto.BLAKE2b_256, nil
	}
	return 0, errHashUnsupported
}

// SignatureMetadata gets metadata for a signature data object.
func (d Descriptor) SignatureMetadata() (ht crypto.Hash, fp [20]byte, err error) {
	if got, want := d.raw.Datatype, DataSignature; got != want {
		return ht, fp, &unexpectedDataTypeError{got, want}
	}

	var s signature

	b := bytes.NewReader(d.raw.Extra[:])
	if err := binary.Read(b, binary.LittleEndian, &s); err != nil {
		return ht, fp, fmt.Errorf("%w", err)
	}

	if ht, err = getHashType(s.Hashtype); err != nil {
		return ht, fp, fmt.Errorf("%w", err)
	}

	copy(fp[:], s.Entity[:])

	return ht, fp, nil
}

// CryptoMessageMetadata gets metadata for a crypto message data object.
func (d Descriptor) CryptoMessageMetadata() (FormatType, MessageType, error) {
	if got, want := d.raw.Datatype, DataCryptoMessage; got != want {
		return 0, 0, &unexpectedDataTypeError{got, want}
	}

	var m cryptoMessage

	b := bytes.NewReader(d.raw.Extra[:])
	if err := binary.Read(b, binary.LittleEndian, &m); err != nil {
		return 0, 0, fmt.Errorf("%w", err)
	}

	return m.Formattype, m.Messagetype, nil
}

// GetData returns the data object associated with descriptor d.
func (d Descriptor) GetData() ([]byte, error) {
	b := make([]byte, d.raw.Filelen)
	if _, err := io.ReadFull(d.GetReader(), b); err != nil {
		return nil, err
	}
	return b, nil
}

// GetReader returns a io.Reader that reads the data object associated with descriptor d.
func (d Descriptor) GetReader() io.Reader {
	return io.NewSectionReader(d.r, d.raw.Fileoff, d.raw.Filelen)
}

// GetIntegrityReader returns an io.Reader that reads the integrity-protected fields from d.
func (d Descriptor) GetIntegrityReader(relativeID uint32) io.Reader {
	fields := []interface{}{
		d.raw.Datatype,
		d.raw.Used,
		relativeID,
		d.raw.Link,
		d.raw.Filelen,
		d.raw.Ctime,
		d.raw.UID,
		d.raw.GID,
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
		bytes.NewReader(d.raw.Name[:]),
		bytes.NewReader(d.raw.Extra[:]),
	)
}
