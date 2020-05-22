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
)

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
	md, err := getImageMetadata(gs.f, gs.ods, gs.mdHash)
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
