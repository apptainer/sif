// Copyright (c) Contributors to the Apptainer project, established as
//   Apptainer a Series of LF Projects LLC.
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// Copyright (c) 2020-2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the LICENSE.md file
// distributed with the sources of this project regarding your rights to use or distribute this
// software.

package integrity

import (
	"github.com/apptainer/sif/v2/pkg/sif"
)

// VerifyResult describes the results of an individual signature validation.
type VerifyResult struct {
	sig      sif.Descriptor
	verified []sif.Descriptor
	e        interface{}
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
func (r VerifyResult) Entity() interface{} {
	return r.e
}

// Error returns an error describing the reason verification failed, or nil if verification was
// successful.
func (r VerifyResult) Error() error {
	return r.err
}
