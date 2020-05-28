// Copyright (c) 2020, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the LICENSE.md file
// distributed with the sources of this project regarding your rights to use or distribute this
// software.

package integrity

import (
	"fmt"

	"github.com/sylabs/sif/pkg/sif"
	"golang.org/x/crypto/openpgp"
)

type verifyTask interface {
	verifyWithKeyRing(kr openpgp.KeyRing) error
}

// Verifier describes a SIF image verifier.
type Verifier struct {
	f *sif.FileImage // SIF image to verify.

	keyRing  openpgp.KeyRing // Keyring to use for verification.
	groups   []uint32        // Data object group(s) selected for verification.
	objects  []uint32        // Individual data object(s) selected for verification.
	isLegacy bool            // Enable verification of legacy signature(s).

	tasks []verifyTask // Slice of verification tasks.
}

// VerifierOpt are used to configure v.
type VerifierOpt func(v *Verifier) error

// OptVerifyWithKeyRing sets the keyring to use for verification to kr.
func OptVerifyWithKeyRing(kr openpgp.KeyRing) VerifierOpt {
	return func(v *Verifier) error {
		v.keyRing = kr
		return nil
	}
}

// OptVerifyGroup adds a verification task for the group with the specified groupID. This may be
// called multliple times to request verification of more than one group.
func OptVerifyGroup(groupID uint32) VerifierOpt {
	return func(v *Verifier) error {
		if groupID == 0 {
			return errInvalidGroupID
		}
		v.groups = insertSorted(v.groups, groupID)
		return nil
	}
}

// OptVerifyObject adds a verification task for the object with the specified id. This may be
// called multliple times to request verification of more than one object.
func OptVerifyObject(id uint32) VerifierOpt {
	return func(v *Verifier) error {
		if id == 0 {
			return errInvalidObjectID
		}
		v.objects = insertSorted(v.objects, id)
		return nil
	}
}

// OptVerifyLegacy enables verification of legacy signatures. Non-legacy signatures will not be
// considered.
func OptVerifyLegacy() VerifierOpt {
	return func(v *Verifier) error {
		v.isLegacy = true
		return nil
	}
}

// NewVerifier returns a Verifier to examine and/or verify digital signatures(s) in f according to
// opts.
//
// Verify requires key material be provided. OptVerifyWithKeyRing can be used for this purpose.
//
// By default, the returned Verifier will consider non-legacy signatures for all object groups. To
// override this behavior, consider using OptVerifyGroup, OptVerifyObject, and/or OptVerifyLegacy.
func NewVerifier(f *sif.FileImage, opts ...VerifierOpt) (*Verifier, error) {
	if f == nil {
		return nil, fmt.Errorf("integrity: %w", errNilFileImage)
	}

	v := &Verifier{f: f}

	// Apply options.
	for _, o := range opts {
		if err := o(v); err != nil {
			return nil, fmt.Errorf("integrity: %w", err)
		}
	}

	// If no verification tasks specified, add one per object group
	if len(v.groups) == 0 && len(v.objects) == 0 {
		ids, err := getGroupIDs(f)
		if err != nil {
			return nil, fmt.Errorf("integrity: %w", err)
		}
		v.groups = ids
	}

	return v, nil
}

// Verify performs all cryptographic verification tasks specified by v.
//
// If key material was not provided when v was created, Verify returns an error wrapping
// ErrNoKeyMaterial.
func (v *Verifier) Verify() error {
	if v.keyRing == nil {
		return fmt.Errorf("integrity: %w", ErrNoKeyMaterial)
	}

	for _, t := range v.tasks {
		if err := t.verifyWithKeyRing(v.keyRing); err != nil {
			return fmt.Errorf("integrity: %w", err)
		}
	}
	return nil
}
