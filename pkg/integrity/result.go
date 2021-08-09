// Copyright (c) 2020-2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the LICENSE.md file
// distributed with the sources of this project regarding your rights to use or distribute this
// software.

package integrity

import (
	"github.com/hpcng/sif/v2/pkg/sif"
	"golang.org/x/crypto/openpgp"
)

type result struct {
	signature sif.Descriptor   // Signature object.
	im        imageMetadata    // Metadata from signature.
	verified  []sif.Descriptor // Verified objects.
	e         *openpgp.Entity  // Signing entity.
	err       error            // Verify error (nil if successful).
}

// Signature returns the signature object associated with the result.
func (r result) Signature() sif.Descriptor {
	return r.signature
}

// Verified returns the data objects that were verified.
func (r result) Verified() []sif.Descriptor {
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
	signature sif.Descriptor   // Signature object.
	ods       []sif.Descriptor // Signed objects.
	e         *openpgp.Entity  // Signing entity.
	err       error            // Verify error (nil if successful).
}

// Signature returns the signature object associated with the result.
func (r legacyResult) Signature() sif.Descriptor {
	return r.signature
}

// Verified returns the data objects that were verified.
func (r legacyResult) Verified() []sif.Descriptor {
	if r.err != nil {
		return nil
	}
	return r.ods
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
