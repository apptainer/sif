// Copyright (c) 2020, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the LICENSE.md file
// distributed with the sources of this project regarding your rights to use or distribute this
// software.

package integrity

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/sylabs/sif/pkg/sif"
)

var (
	errObjectNotSigned      = errors.New("object not signed")
	errSignedObjectNotFound = errors.New("signed object not found")
	errHeaderIntegrity      = errors.New("header integrity compromised")
	errObjectIntegrity      = errors.New("data object integrity compromised")
)

// writeHeader writes the integrity-protected fields of h to w.
func writeHeader(w io.Writer, h sif.Header) error {
	fields := []interface{}{
		h.Launch,
		h.Magic,
		h.Version,
		h.Arch,
		h.ID,
		h.Ctime,
	}

	for _, f := range fields {
		if err := binary.Write(w, binary.LittleEndian, f); err != nil {
			return err
		}
	}
	return nil
}

// writeDescriptor writes the integrity-protected fields of od to w.
func writeDescriptor(w io.Writer, od sif.Descriptor) error {
	fields := []interface{}{
		od.Datatype,
		od.Used,
		od.ID,
		od.Groupid,
		od.Link,
		od.Filelen,
		od.Ctime,
		od.UID,
		od.Gid,
		od.Name,
		od.Extra,
	}

	for _, f := range fields {
		if err := binary.Write(w, binary.LittleEndian, f); err != nil {
			return err
		}
	}
	return nil
}

type headerMetadata struct {
	Digest digest `json:"digest"`
}

// getHeaderMetadata returns headerMetadata for hdr, using hash algorithm h.
func getHeaderMetadata(hdr sif.Header, h crypto.Hash) (headerMetadata, error) {
	b := bytes.Buffer{}
	if err := writeHeader(&b, hdr); err != nil {
		return headerMetadata{}, err
	}

	d, err := newDigestReader(h, &b)
	if err != nil {
		return headerMetadata{}, err
	}

	return headerMetadata{Digest: d}, nil
}

// matches verifies hdr matches the metadata in hm.
func (hm headerMetadata) matches(hdr sif.Header) error {
	b := bytes.Buffer{}
	if err := writeHeader(&b, hdr); err != nil {
		return err
	}

	if ok, err := hm.Digest.matches(&b); err != nil {
		return err
	} else if !ok {
		return errHeaderIntegrity
	}
	return nil
}

type objectMetadata struct {
	ID               uint32  `json:"id"`
	DescriptorDigest digest  `json:"descriptorDigest"`
	ObjectDigest     *digest `json:"objectDigest,omitempty"`
}

// getObjectMetadata returns objectMetadata for object with descriptor od and content r using hash
// algorithm h.
func getObjectMetadata(od sif.Descriptor, r io.Reader, h crypto.Hash) (objectMetadata, error) {
	b := bytes.Buffer{}
	if err := writeDescriptor(&b, od); err != nil {
		return objectMetadata{}, err
	}

	// Calculate digest on object descriptor.
	d, err := newDigestReader(h, &b)
	if err != nil {
		return objectMetadata{}, err
	}
	md := objectMetadata{
		ID:               od.ID,
		DescriptorDigest: d,
	}

	// Calculate digest on object data.
	d, err = newDigestReader(h, r)
	if err != nil {
		return objectMetadata{}, err
	}
	md.ObjectDigest = &d

	return md, nil
}

// matches verifies the object in f described by od matches the metadata in om.
func (om objectMetadata) matches(f *sif.FileImage, od *sif.Descriptor) error {
	b := bytes.Buffer{}
	if err := writeDescriptor(&b, *od); err != nil {
		return err
	}

	if ok, err := om.DescriptorDigest.matches(&b); err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("object %d: %w", od.ID, errObjectIntegrity)
	}

	// TODO: use something more efficient than GetData.
	r := bytes.NewReader(od.GetData(f))
	if ok, err := om.ObjectDigest.matches(r); err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("object %d: %w", od.ID, errObjectIntegrity)
	}
	return nil
}

type mdVersion int

const (
	metadataVersion1 mdVersion = iota + 1
)

type imageMetadata struct {
	Version mdVersion        `json:"version"`
	Header  headerMetadata   `json:"header"`
	Objects []objectMetadata `json:"objects"`
}

// getImageMetadata returns populated imageMetadata for object descriptors ods in f, using hash
// algorithm h.
func getImageMetadata(f *sif.FileImage, ods []*sif.Descriptor, h crypto.Hash) (imageMetadata, error) {
	im := imageMetadata{Version: metadataVersion1}

	// Add header metadata.
	hm, err := getHeaderMetadata(f.Header, h)
	if err != nil {
		return imageMetadata{}, err
	}
	im.Header = hm

	// Add object descriptor/data metadata.
	for _, od := range ods {
		// TODO: use something more efficient than GetData.
		r := bytes.NewReader(od.GetData(f))

		om, err := getObjectMetadata(*od, r, h)
		if err != nil {
			return imageMetadata{}, err
		}
		im.Objects = append(im.Objects, om)
	}

	return im, nil
}

// objectIDsMatch verifies the object IDs described by ods match exactly the object IDs described
// by im.
func (im imageMetadata) objectIDsMatch(ods []*sif.Descriptor) error {
	ids := make(map[uint32]bool)
	for _, om := range im.Objects {
		ids[om.ID] = false
	}

	// Check each object in ods exists in ids, and mark as seen.
	for _, od := range ods {
		if _, ok := ids[od.ID]; !ok {
			return fmt.Errorf("object %d: %w", od.ID, errObjectNotSigned)
		}
		ids[od.ID] = true
	}

	// Check that all objects in ids were seen.
	for id, seen := range ids {
		if !seen {
			return fmt.Errorf("object %d: %w", id, errSignedObjectNotFound)
		}
	}
	return nil
}

// metadataForObject retrieves the objectMetadata for object specified by id.
func (im imageMetadata) metadataForObject(id uint32) (objectMetadata, error) {
	for _, om := range im.Objects {
		if om.ID == id {
			return om, nil
		}
	}
	return objectMetadata{}, fmt.Errorf("object %d: %w", id, errObjectNotSigned)
}

// matches verifies the header and objects described by ods match the metadata in im.
func (im imageMetadata) matches(f *sif.FileImage, ods []*sif.Descriptor) ([]uint32, error) {
	verified := make([]uint32, 0, len(ods))

	// Verify header metadata.
	if err := im.Header.matches(f.Header); err != nil {
		return verified, err
	}

	// Verify data object metadata.
	for _, od := range ods {
		om, err := im.metadataForObject(od.ID)
		if err != nil {
			return verified, err
		}

		if err := om.matches(f, od); err != nil {
			return verified, err
		}

		verified = append(verified, od.ID)
	}

	return verified, nil
}
