// Copyright (c) 2020, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the LICENSE.md file
// distributed with the sources of this project regarding your rights to use or distribute this
// software.

package integrity

import (
	"github.com/sylabs/sif/pkg/sif"
	"golang.org/x/crypto/openpgp"
)

type result struct {
	signature uint32          // ID of signature object.
	im        imageMetadata   // Metadata from signature.
	verified  []uint32        // IDs of verified objects.
	e         *openpgp.Entity // Signing entity.
	err       error           // Verify error (nil if successful).
}

// Signature returns the ID of the signature object associated with the result.
func (r result) Signature() uint32 {
	return r.signature
}

// Signed returns the IDs of data objects that were signed.
func (r result) Signed() []uint32 {
	ids := make([]uint32, 0, len(r.im.Objects))
	for _, om := range r.im.Objects {
		ids = append(ids, om.id)
	}
	return ids
}

// Verified returns the IDs of data objects that were verified.
func (r result) Verified() []uint32 {
	return r.verified
}

// Entity returns the signing entity, or nil if the signing entity could not be determined.
func (r result) Entity() *openpgp.Entity {
	return r.e
}

// Error returns an error describing the reason verification failed, or nil if verification was
// successful.
func (r result) Error() error {
	return r.err
}

type legacyResult struct {
	signature uint32            // ID of signature object.
	ods       []*sif.Descriptor // Descriptors of signed objects.
	e         *openpgp.Entity   // Signing entity.
	err       error             // Verify error (nil if successful).
}

// Signature returns the ID of the signature object associated with the result.
func (r legacyResult) Signature() uint32 {
	return r.signature
}

// Signed returns the IDs of data objects that were signed.
func (r legacyResult) Signed() []uint32 {
	ids := make([]uint32, 0, len(r.ods))
	for _, om := range r.ods {
		ids = append(ids, om.ID)
	}
	return ids
}

// Verified returns the IDs of data objects that were verified.
func (r legacyResult) Verified() []uint32 {
	if r.err != nil {
		return nil
	}
	return r.Signed()
}

// Entity returns the signing entity, or nil if the signing entity could not be determined.
func (r legacyResult) Entity() *openpgp.Entity {
	return r.e
}

// Error returns an error describing the reason verification failed, or nil if verification was
// successful.
func (r legacyResult) Error() error {
	return r.err
}
