// Copyright (c) 2020-2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the LICENSE.md file
// distributed with the sources of this project regarding your rights to use or distribute this
// software.

package integrity

import (
	"github.com/hpcng/sif/v2/pkg/sif"
	"github.com/ProtonMail/go-crypto/openpgp"
)

type VerifyResult struct {
	sig      sif.Descriptor
	verified []sif.Descriptor
	e        *openpgp.Entity
	err      error
}

// Signature returns the signature object associated with the result.
func (r VerifyResult) Signature() sif.Descriptor {
	return r.sig
}

// Verified returns the data objects that were verified.
func (r VerifyResult) Verified() []sif.Descriptor {
	return r.verified
}

// Entity returns the signing entity, or nil if the signing entity could not be determined.
func (r VerifyResult) Entity() *openpgp.Entity {
	return r.e
}

// Error returns an error describing the reason verification failed, or nil if verification was
// successful.
func (r VerifyResult) Error() error {
	return r.err
}
