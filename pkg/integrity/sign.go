// Copyright (c) 2020, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the LICENSE.md file
// distributed with the sources of this project regarding your rights to use or distribute this
// software.

package integrity

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"github.com/sylabs/sif/pkg/sif"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

var (
	errNoObjectsSpecified = errors.New("no objects specified")
	errUnexpectedGroupID  = errors.New("unexpected group ID")
	errNilFileImage       = errors.New("nil file image")
)

// ErrNoKeyMaterial is the error returned when no key material was provided.
var ErrNoKeyMaterial = errors.New("key material not provided")

func sifHashType(h crypto.Hash) sif.Hashtype {
	switch h {
	case crypto.SHA256:
		return sif.HashSHA256
	case crypto.SHA384:
		return sif.HashSHA384
	case crypto.SHA512:
		return sif.HashSHA512
	case crypto.BLAKE2s_256:
		return sif.HashBLAKE2S
	case crypto.BLAKE2b_256, crypto.BLAKE2b_384, crypto.BLAKE2b_512:
		return sif.HashBLAKE2B
	}
	return 0
}

type groupSigner struct {
	f         *sif.FileImage    // SIF image to sign.
	id        uint32            // Group ID.
	ods       []*sif.Descriptor // Descriptors of object(s) to sign.
	mdHash    crypto.Hash       // Hash type for metadata.
	sigConfig *packet.Config    // Configuration for signature.
	sigHash   sif.Hashtype      // SIF hash type for signature.
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
			od, err := getObject(gs.f, id)
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

// optSignGroupSignatureConfig sets c as the configuration used for signature generation.
func optSignGroupSignatureConfig(c *packet.Config) groupSignerOpt {
	return func(gs *groupSigner) error {
		gs.sigConfig = c
		return nil
	}
}

// newGroupSigner returns a new groupSigner to add a digital signature for the specified group to
// f, according to opts.
//
// By default, all data objects in the group will be signed. To override this behavior, use
// optSignGroupObjects(). To override the default metadata hash algorithm, use
// optSignGroupMetadataHash(). To override the default PGP configuration for signature generation,
// use optSignGroupSignatureConfig().
func newGroupSigner(f *sif.FileImage, groupID uint32, opts ...groupSignerOpt) (*groupSigner, error) {
	gs := groupSigner{
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

	// Populate SIF hash type.
	gs.sigHash = sifHashType(gs.sigConfig.Hash())

	return &gs, nil
}

// addObject adds od to the list of object descriptors to be signed.
func (gs *groupSigner) addObject(od *sif.Descriptor) error {
	if groupID := od.Groupid &^ sif.DescrGroupMask; groupID != gs.id {
		return fmt.Errorf("%w (%v)", errUnexpectedGroupID, groupID)
	}

	// Insert into sorted descriptor list, if not already present.
	i := sort.Search(len(gs.ods), func(i int) bool { return gs.ods[i].ID >= od.ID })
	if i < len(gs.ods) && gs.ods[i].ID == od.ID {
		return nil
	}
	gs.ods = append(gs.ods, nil)
	copy(gs.ods[i+1:], gs.ods[i:])
	gs.ods[i] = od

	return nil
}

// signWithEntity signs the objects specified by gs with e.
func (gs *groupSigner) signWithEntity(e *openpgp.Entity) (sif.DescriptorInput, error) {
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

	// Sign and encode image metadata.
	b := bytes.Buffer{}
	if err := signAndEncodeJSON(&b, md, e.PrivateKey, gs.sigConfig); err != nil {
		return sif.DescriptorInput{}, fmt.Errorf("failed to encode signature: %w", err)
	}

	// Prepare SIF data object descriptor.
	di := sif.DescriptorInput{
		Datatype: sif.DataSignature,
		Groupid:  sif.DescrUnusedGroup,
		Link:     sif.DescrGroupMask | gs.id,
		Size:     int64(b.Len()),
		Fp:       &b,
	}
	if err := di.SetSignExtra(gs.sigHash, hex.EncodeToString(e.PrimaryKey.Fingerprint[:])); err != nil {
		return sif.DescriptorInput{}, fmt.Errorf("failed to set signature metadata: %w", err)
	}

	return di, nil
}

// Signer describes a SIF image signer.
type Signer struct {
	f       *sif.FileImage  // SIF image to sign.
	signers []*groupSigner  // Signer for each group.
	e       *openpgp.Entity // Entity to use to generate signature(s).
}

// SignerOpt are used to configure s.
type SignerOpt func(s *Signer) error

// OptSignWithEntity specifies e as the entity to use to generate signature(s).
func OptSignWithEntity(e *openpgp.Entity) SignerOpt {
	return func(s *Signer) error {
		s.e = e
		return nil
	}
}

// OptSignGroup specifies that a signature be applied to cover all objects in the group with the
// specified groupID. This may be called multiple times to add multiple group signatures.
func OptSignGroup(groupID uint32) SignerOpt {
	return func(s *Signer) error {
		gs, err := newGroupSigner(s.f, groupID)
		if err != nil {
			return err
		}
		s.signers = append(s.signers, gs)
		return nil
	}
}

// OptSignObjects specifies that one or more signature(s) be applied to cover objects with the
// specified ids. One signature will be applied for each group ID associated with the object(s).
// This may be called multiple times to add multiple signatures.
func OptSignObjects(ids ...uint32) SignerOpt {
	return func(s *Signer) error {
		if len(ids) == 0 {
			return errNoObjectsSpecified
		}

		idMap := make(map[uint32]bool)
		groupObjectIDs := make(map[uint32][]uint32)
		var groupIDs []uint32

		for _, id := range ids {
			// Ignore duplicate IDs.
			if _, ok := idMap[id]; ok {
				continue
			}
			idMap[id] = true

			// Get descriptor.
			od, err := getObject(s.f, id)
			if err != nil {
				return err
			}

			// Note the group ID if it hasn't been seen before, and append the object ID to the
			// appropriate group in the map.
			groupID := od.Groupid &^ sif.DescrGroupMask
			if _, ok := groupObjectIDs[groupID]; !ok {
				groupIDs = append(groupIDs, groupID)
			}
			groupObjectIDs[groupID] = append(groupObjectIDs[groupID], id)
		}

		sort.Slice(groupIDs, func(i, j int) bool { return groupIDs[i] < groupIDs[j] })

		// Add one groupSigner per group.
		for _, groupID := range groupIDs {
			gs, err := newGroupSigner(s.f, groupID, optSignGroupObjects(groupObjectIDs[groupID]...))
			if err != nil {
				return err
			}
			s.signers = append(s.signers, gs)
		}

		return nil
	}
}

// NewSigner returns a Signer to add digital signature(s) to f, according to opts.
//
// Sign requires key material be provided. OptSignWithEntity can be used for this purpose.
//
// By default, one digital signature is added per object group in f. To override this behavior,
// consider using OptSignGroup and/or OptSignObjects.
func NewSigner(f *sif.FileImage, opts ...SignerOpt) (*Signer, error) {
	if f == nil {
		return nil, fmt.Errorf("integrity: %w", errNilFileImage)
	}

	s := Signer{f: f}

	// Apply options.
	for _, opt := range opts {
		if err := opt(&s); err != nil {
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
			gs, err := newGroupSigner(f, id)
			if err != nil {
				return nil, fmt.Errorf("integrity: %w", err)
			}
			s.signers = append(s.signers, gs)
		}
	}

	return &s, nil
}

// Sign adds digital signatures as specified by s.
//
// If key material was not provided when s was created, Sign returns an error wrapping
// ErrNoKeyMaterial.
func (s *Signer) Sign() error {
	if s.e == nil {
		return fmt.Errorf("integrity: %w", ErrNoKeyMaterial)
	}

	for _, gs := range s.signers {
		di, err := gs.signWithEntity(s.e)
		if err != nil {
			return fmt.Errorf("integrity: %w", err)
		}

		if err := s.f.AddObject(di); err != nil {
			return fmt.Errorf("integrity: failed to add object: %w", err)
		}
	}

	return nil
}
