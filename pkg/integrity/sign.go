// Copyright (c) Contributors to the Apptainer project, established as
//   Apptainer a Series of LF Projects LLC.
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// Copyright (c) 2020-2023, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the LICENSE.md file
// distributed with the sources of this project regarding your rights to use or distribute this
// software.

package integrity

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/apptainer/sif/v2/pkg/sif"
	"github.com/sigstore/sigstore/pkg/signature"
)

var (
	errNoObjectsSpecified = errors.New("no objects specified")
	errUnexpectedGroupID  = errors.New("unexpected group ID")
	errNilFileImage       = errors.New("nil file image")
)

// ErrNoKeyMaterial is the error returned when no key material was provided.
var ErrNoKeyMaterial = errors.New("key material not provided")

type encoder interface {
	// signMessage signs the message from r, and writes the result to w. On success, the signature
	// hash function is returned.
	signMessage(ctx context.Context, w io.Writer, r io.Reader) (ht crypto.Hash, err error)
}

type groupSigner struct {
	en     encoder          // Message encoder.
	f      *sif.FileImage   // SIF image to sign.
	id     uint32           // Group ID.
	ods    []sif.Descriptor // Descriptors of object(s) to sign.
	mdHash crypto.Hash      // Hash type for metadata.
	fp     []byte           // Fingerprint of signing entity.
}

// groupSignerOpt are used to configure gs.
type groupSignerOpt func(gs *groupSigner) error

// optSignGroupObjects specifies the signature include objects with the specified ids.
func optSignGroupObjects(ids ...uint32) groupSignerOpt {
	return func(gs *groupSigner) error {
		if len(ids) == 0 {
			return errNoObjectsSpecified
		}

		for _, id := range ids {
			od, err := gs.f.GetDescriptor(sif.WithID(id))
			if err != nil {
				return err
			}

			if err := gs.addObject(od); err != nil {
				return err
			}
		}

		return nil
	}
}

// optSignGroupMetadataHash sets h as the metadata hash function.
func optSignGroupMetadataHash(h crypto.Hash) groupSignerOpt {
	return func(gs *groupSigner) error {
		gs.mdHash = h
		return nil
	}
}

// optSignGroupFingerprint sets fp as the fingerprint of the signing entity.
func optSignGroupFingerprint(fp []byte) groupSignerOpt {
	return func(gs *groupSigner) error {
		gs.fp = fp
		return nil
	}
}

// newGroupSigner returns a new groupSigner to add a digital signature using en for the specified
// group to f, according to opts.
//
// By default, all data objects in the group will be signed. To override this behavior, use
// optSignGroupObjects(). To override the default metadata hash algorithm, use
// optSignGroupMetadataHash().
//
// By default, the fingerprint of the signing entity is not set. To override this behavior, use
// optSignGroupFingerprint.
func newGroupSigner(en encoder, f *sif.FileImage, groupID uint32, opts ...groupSignerOpt) (*groupSigner, error) {
	if groupID == 0 {
		return nil, sif.ErrInvalidGroupID
	}

	gs := groupSigner{
		en:     en,
		f:      f,
		id:     groupID,
		mdHash: crypto.SHA256,
	}

	// Apply options.
	for _, opt := range opts {
		if err := opt(&gs); err != nil {
			return nil, err
		}
	}

	// If no object descriptors specified, select all in group.
	if len(gs.ods) == 0 {
		ods, err := getGroupObjects(f, groupID)
		if err != nil {
			return nil, err
		}

		for _, od := range ods {
			if err := gs.addObject(od); err != nil {
				return nil, err
			}
		}
	}

	return &gs, nil
}

// addObject adds od to the list of object descriptors to be signed.
func (gs *groupSigner) addObject(od sif.Descriptor) error {
	if groupID := od.GroupID(); groupID != gs.id {
		return fmt.Errorf("%w (%v)", errUnexpectedGroupID, groupID)
	}

	// Insert into sorted descriptor list, if not already present.
	gs.ods = insertSortedFunc(gs.ods, od, func(a, b sif.Descriptor) int { return int(a.ID()) - int(b.ID()) })

	return nil
}

// sign creates a digital signature as specified by gs.
func (gs *groupSigner) sign(ctx context.Context) (sif.DescriptorInput, error) {
	// Get minimum object ID in group. Object IDs in the image metadata will be relative to this.
	minID, err := getGroupMinObjectID(gs.f, gs.id)
	if err != nil {
		return sif.DescriptorInput{}, err
	}

	// Get metadata for the image.
	md, err := getImageMetadata(gs.f, minID, gs.ods, gs.mdHash)
	if err != nil {
		return sif.DescriptorInput{}, fmt.Errorf("failed to get image metadata: %w", err)
	}

	// Encode image metadata.
	enc, err := json.Marshal(md)
	if err != nil {
		return sif.DescriptorInput{}, fmt.Errorf("failed to encode image metadata: %w", err)
	}

	// Sign image metadata.
	b := bytes.Buffer{}
	ht, err := gs.en.signMessage(ctx, &b, bytes.NewReader(enc))
	if err != nil {
		return sif.DescriptorInput{}, fmt.Errorf("failed to sign message: %w", err)
	}

	// Prepare SIF data object descriptor.
	return sif.NewDescriptorInput(sif.DataSignature, &b,
		sif.OptNoGroup(),
		sif.OptLinkedGroupID(gs.id),
		sif.OptSignatureMetadata(ht, gs.fp),
	)
}

type signOpts struct {
	ss            []signature.Signer
	e             *openpgp.Entity
	groupIDs      []uint32
	objectIDs     [][]uint32
	timeFunc      func() time.Time
	deterministic bool
	ctx           context.Context //nolint:containedctx
}

// SignerOpt are used to configure so.
type SignerOpt func(so *signOpts) error

// OptSignWithSigner specifies signer(s) to use to generate signature(s).
func OptSignWithSigner(ss ...signature.Signer) SignerOpt {
	return func(so *signOpts) error {
		so.ss = append(so.ss, ss...)
		return nil
	}
}

// OptSignWithEntity specifies e as the entity to use to generate signature(s).
func OptSignWithEntity(e *openpgp.Entity) SignerOpt {
	return func(so *signOpts) error {
		so.e = e
		return nil
	}
}

// OptSignGroup specifies that a signature be applied to cover all objects in the group with the
// specified groupID. This may be called multiple times to add multiple group signatures.
func OptSignGroup(groupID uint32) SignerOpt {
	return func(so *signOpts) error {
		so.groupIDs = append(so.groupIDs, groupID)
		return nil
	}
}

// OptSignObjects specifies that one or more signature(s) be applied to cover objects with the
// specified ids. One signature will be applied for each group ID associated with the object(s).
// This may be called multiple times to add multiple signatures.
func OptSignObjects(ids ...uint32) SignerOpt {
	return func(so *signOpts) error {
		if len(ids) == 0 {
			return errNoObjectsSpecified
		}

		so.objectIDs = append(so.objectIDs, ids)
		return nil
	}
}

// OptSignWithTime specifies fn as the func to obtain signature timestamp(s). Unless
// OptSignDeterministic is supplied, fn is also used to set SIF timestamps.
func OptSignWithTime(fn func() time.Time) SignerOpt {
	return func(so *signOpts) error {
		so.timeFunc = fn
		return nil
	}
}

// OptSignDeterministic sets SIF header/descriptor fields to values that support deterministic
// modification of images. This does not affect the signature timestamps; to specify deterministic
// signature timestamps, use OptSignWithTime.
func OptSignDeterministic() SignerOpt {
	return func(so *signOpts) error {
		so.deterministic = true
		return nil
	}
}

// OptSignWithContext specifies that the given context should be used in RPC to external services.
func OptSignWithContext(ctx context.Context) SignerOpt {
	return func(so *signOpts) error {
		so.ctx = ctx
		return nil
	}
}

// withGroupedObjects splits the objects represented by ids into object groups, and calls fn once
// per object group.
func withGroupedObjects(f *sif.FileImage, ids []uint32, fn func(uint32, []uint32) error) error {
	var groupIDs []uint32
	groupObjectIDs := make(map[uint32][]uint32)

	for _, id := range ids {
		od, err := f.GetDescriptor(sif.WithID(id))
		if err != nil {
			return err
		}

		// Note the group ID if it hasn't been seen before, and append the object ID to the
		// appropriate group in the map.
		groupID := od.GroupID()
		if _, ok := groupObjectIDs[groupID]; !ok {
			groupIDs = append(groupIDs, groupID)
		}
		groupObjectIDs[groupID] = append(groupObjectIDs[groupID], id)
	}

	slices.Sort(groupIDs)

	for _, groupID := range groupIDs {
		if err := fn(groupID, groupObjectIDs[groupID]); err != nil {
			return err
		}
	}

	return nil
}

// Signer describes a SIF image signer.
type Signer struct {
	f       *sif.FileImage
	opts    signOpts
	signers []*groupSigner
}

// NewSigner returns a Signer to add digital signature(s) to f, according to opts. Key material
// must be provided, or an error wrapping ErrNoKeyMaterial is returned.
//
// To provide key material, consider using OptSignWithSigner or OptSignWithEntity.
//
// By default, one digital signature is added per object group in f. To override this behavior,
// consider using OptSignGroup and/or OptSignObjects.
//
// By default, signature timestamps are set to the current time. To override this behavior,
// consider using OptSignWithTime.
//
// By default, header and descriptor timestamps are set to the current time for non-deterministic
// images, and unset otherwise. To override this behavior, consider using OptSignWithTime or
// OptSignDeterministic.
func NewSigner(f *sif.FileImage, opts ...SignerOpt) (*Signer, error) {
	if f == nil {
		return nil, fmt.Errorf("integrity: %w", errNilFileImage)
	}

	so := signOpts{
		ctx: context.Background(),
	}

	// Apply options.
	for _, opt := range opts {
		if err := opt(&so); err != nil {
			return nil, fmt.Errorf("integrity: %w", err)
		}
	}

	s := Signer{
		f:    f,
		opts: so,
	}

	var commonOpts []groupSignerOpt

	// Get message encoder.
	var en encoder
	switch {
	case so.ss != nil:
		en = newDSSEEncoder(so.ss)
	case so.e != nil:
		timeFunc := time.Now
		if so.timeFunc != nil {
			timeFunc = so.timeFunc
		}
		en = newClearsignEncoder(so.e, timeFunc)
		commonOpts = append(commonOpts, optSignGroupFingerprint(so.e.PrimaryKey.Fingerprint))
	default:
		return nil, fmt.Errorf("integrity: %w", ErrNoKeyMaterial)
	}

	// Add signer for each groupID.
	for _, groupID := range so.groupIDs {
		gs, err := newGroupSigner(en, f, groupID, commonOpts...)
		if err != nil {
			return nil, fmt.Errorf("integrity: %w", err)
		}
		s.signers = append(s.signers, gs)
	}

	// Add signer(s) for each list of object IDs.
	for _, ids := range so.objectIDs {
		err := withGroupedObjects(f, ids, func(groupID uint32, ids []uint32) error {
			opts := commonOpts
			opts = append(opts, optSignGroupObjects(ids...))

			gs, err := newGroupSigner(en, f, groupID, opts...)
			if err != nil {
				return err
			}
			s.signers = append(s.signers, gs)

			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("integrity: %w", err)
		}
	}

	// If no signers specified, add one per object group.
	if len(s.signers) == 0 {
		ids, err := getGroupIDs(f)
		if err != nil {
			return nil, fmt.Errorf("integrity: %w", err)
		}

		for _, id := range ids {
			gs, err := newGroupSigner(en, f, id, commonOpts...)
			if err != nil {
				return nil, fmt.Errorf("integrity: %w", err)
			}
			s.signers = append(s.signers, gs)
		}
	}

	return &s, nil
}

// Sign adds digital signatures as specified by s.
func (s *Signer) Sign() error {
	for _, gs := range s.signers {
		di, err := gs.sign(s.opts.ctx)
		if err != nil {
			return fmt.Errorf("integrity: %w", err)
		}

		var opts []sif.AddOpt
		if s.opts.deterministic {
			opts = append(opts, sif.OptAddDeterministic())
		} else if s.opts.timeFunc != nil {
			opts = append(opts, sif.OptAddWithTime(s.opts.timeFunc()))
		}

		if err := s.f.AddObject(di, opts...); err != nil {
			return fmt.Errorf("integrity: failed to add object: %w", err)
		}
	}

	return nil
}
