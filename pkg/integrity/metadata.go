// Copyright (c) 2021 Apptainer a Series of LF Projects LLC
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// Copyright (c) 2020-2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the LICENSE.md file
// distributed with the sources of this project regarding your rights to use or distribute this
// software.

package integrity

import (
	"crypto"
	"errors"
	"fmt"
	"io"

	"github.com/apptainer/sif/v2/pkg/sif"
)

var (
	errObjectNotSigned      = errors.New("object not signed")
	errSignedObjectNotFound = errors.New("signed object not found")
	errMinimumIDInvalid     = errors.New("minimum ID value invalid")
)

// ErrHeaderIntegrity is the error returned when the integrity of the SIF global header is
// compromised.
var ErrHeaderIntegrity = errors.New("header integrity compromised")

// DescriptorIntegrityError records an error in cryptographic verification of a data object
// descriptor.
type DescriptorIntegrityError struct {
	ID uint32 // Data object ID.
}

func (e *DescriptorIntegrityError) Error() string {
	if e.ID == 0 {
		return "data object descriptor integrity compromised"
	}
	return fmt.Sprintf("data object descriptor integrity compromised: %v", e.ID)
}

// Is compares e against target. If target is a DescriptorIntegrityError and matches e or target
// has a zero value ID, true is returned.
func (e *DescriptorIntegrityError) Is(target error) bool {
	t, ok := target.(*DescriptorIntegrityError)
	if !ok {
		return false
	}
	return e.ID == t.ID || t.ID == 0
}

// ObjectIntegrityError records an error in cryptographic verification of a data object.
type ObjectIntegrityError struct {
	ID uint32 // Data object ID.
}

func (e *ObjectIntegrityError) Error() string {
	if e.ID == 0 {
		return "data object integrity compromised"
	}
	return fmt.Sprintf("data object integrity compromised: %v", e.ID)
}

// Is compares e against target. If target is a ObjectIntegrityError and matches e or target has a
// zero value ID, true is returned.
func (e *ObjectIntegrityError) Is(target error) bool {
	t, ok := target.(*ObjectIntegrityError)
	if !ok {
		return false
	}
	return e.ID == t.ID || t.ID == 0
}

type headerMetadata struct {
	Digest digest `json:"digest"`
}

// getHeaderMetadata returns headerMetadata for the fields read from r, using hash algorithm h.
func getHeaderMetadata(r io.Reader, h crypto.Hash) (headerMetadata, error) {
	d, err := newDigestReader(h, r)
	if err != nil {
		return headerMetadata{}, err
	}

	return headerMetadata{Digest: d}, nil
}

// matches verifies the fields read fromr matche the metadata in hm.
//
// If the SIF global header does not match, ErrHeaderIntegrity is returned.
func (hm headerMetadata) matches(r io.Reader) error {
	if ok, err := hm.Digest.matches(r); err != nil {
		return err
	} else if !ok {
		return ErrHeaderIntegrity
	}
	return nil
}

type objectMetadata struct {
	RelativeID       uint32 `json:"relativeId"`
	DescriptorDigest digest `json:"descriptorDigest"`
	ObjectDigest     digest `json:"objectDigest"`

	id uint32 // absolute object ID (minID + RelativeID)
}

// getObjectMetadata returns objectMetadata for object with relativeID, using digests calculated
// over descr and data using hash algorithm h.
func getObjectMetadata(relativeID uint32, descr, data io.Reader, h crypto.Hash) (objectMetadata, error) {
	om := objectMetadata{RelativeID: relativeID}

	// Calculate digest on object descriptor.
	d, err := newDigestReader(h, descr)
	if err != nil {
		return objectMetadata{}, err
	}
	om.DescriptorDigest = d

	// Calculate digest on object data.
	d, err = newDigestReader(h, data)
	if err != nil {
		return objectMetadata{}, err
	}
	om.ObjectDigest = d

	return om, nil
}

// populateAbsoluteID populates the absolute object ID of om based on minID.
func (om *objectMetadata) populateAbsoluteID(minID uint32) {
	om.id = minID + om.RelativeID
}

// matches verifies the object described by od matches the metadata in om.
//
// If the data object descriptor does not match, a DescriptorIntegrityError is returned. If the
// data object does not match, a ObjectIntegrityError is returned.
func (om objectMetadata) matches(od sif.Descriptor) error {
	if ok, err := om.DescriptorDigest.matches(od.GetIntegrityReader()); err != nil {
		return err
	} else if !ok {
		return &DescriptorIntegrityError{ID: od.ID()}
	}

	if ok, err := om.ObjectDigest.matches(od.GetReader()); err != nil {
		return err
	} else if !ok {
		return &ObjectIntegrityError{ID: od.ID()}
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
func getImageMetadata(f *sif.FileImage, minID uint32, ods []sif.Descriptor, h crypto.Hash) (imageMetadata, error) {
	im := imageMetadata{Version: metadataVersion1}

	// Add header metadata.
	hm, err := getHeaderMetadata(f.GetHeaderIntegrityReader(), h)
	if err != nil {
		return imageMetadata{}, err
	}
	im.Header = hm

	// Add object descriptor/data metadata.
	for _, od := range ods {
		id := od.ID()

		if id < minID { // shouldn't really be possible...
			return imageMetadata{}, errMinimumIDInvalid
		}

		om, err := getObjectMetadata(id-minID, od.GetIntegrityReader(), od.GetReader(), h)
		if err != nil {
			return imageMetadata{}, err
		}
		im.Objects = append(im.Objects, om)
	}

	im.populateAbsoluteObjectIDs(minID)

	return im, nil
}

// populateAbsoluteObjectIDs populates the absolute object ID of each object in im by adding minID
// to the relative ID of each object in im.
func (im *imageMetadata) populateAbsoluteObjectIDs(minID uint32) {
	for i := range im.Objects {
		im.Objects[i].populateAbsoluteID(minID)
	}
}

// objectIDsMatch verifies the object IDs described by ods match exactly the object IDs described
// by im.
func (im imageMetadata) objectIDsMatch(ods []sif.Descriptor) error {
	ids := make(map[uint32]bool)
	for _, om := range im.Objects {
		ids[om.id] = false
	}

	// Check each object in ods exists in ids, and mark as seen.
	for _, od := range ods {
		id := od.ID()
		if _, ok := ids[id]; !ok {
			return fmt.Errorf("object %d: %w", id, errObjectNotSigned)
		}
		ids[id] = true
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
		if om.id == id {
			return om, nil
		}
	}
	return objectMetadata{}, fmt.Errorf("object %d: %w", id, errObjectNotSigned)
}

// matches verifies the header and objects described by ods match the metadata in im.
//
// If the SIF global header does not match, ErrHeaderIntegrity is returned. If the data object
// descriptor does not match, a DescriptorIntegrityError is returned. If the data object does not
// match, a ObjectIntegrityError is returned.
func (im imageMetadata) matches(f *sif.FileImage, ods []sif.Descriptor) ([]sif.Descriptor, error) {
	verified := make([]sif.Descriptor, 0, len(ods))

	// Verify header metadata.
	if err := im.Header.matches(f.GetHeaderIntegrityReader()); err != nil {
		return verified, err
	}

	// Verify data object metadata.
	for _, od := range ods {
		om, err := im.metadataForObject(od.ID())
		if err != nil {
			return verified, err
		}

		if err := om.matches(od); err != nil {
			return verified, err
		}

		verified = append(verified, od)
	}

	return verified, nil
}
