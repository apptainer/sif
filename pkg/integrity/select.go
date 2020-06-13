// Copyright (c) 2020, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the LICENSE.md file
// distributed with the sources of this project regarding your rights to use or distribute this
// software.

package integrity

import (
	"bytes"
	"errors"
	"sort"

	"github.com/sylabs/sif/pkg/sif"
)

var (
	errInvalidObjectID      = errors.New("invalid object ID")
	errInvalidGroupID       = errors.New("invalid group ID")
	errMultipleObjectsFound = errors.New("multiple objects found")
	errObjectNotFound       = errors.New("object not found")
	errGroupNotFound        = errors.New("group not found")
	errNoGroupsFound        = errors.New("no groups found")
	errSignatureNotFound    = errors.New("signature not found")
)

// insertSorted inserts unique vals into the sorted slice s.
func insertSorted(s []uint32, vals ...uint32) []uint32 {
	for _, val := range vals {
		val := val

		i := sort.Search(len(s), func(i int) bool { return s[i] >= val })
		if i < len(s) && s[i] == val {
			continue
		}

		s = append(s, 0)
		copy(s[i+1:], s[i:])
		s[i] = val
	}

	return s
}

// getObject returns the descriptor in f associated with the object with identifier id. If multiple
// such objects are found, errMultipleObjectsFound is returned. If no such object is found,
// errObjectNotFound is returned.
func getObject(f *sif.FileImage, id uint32) (*sif.Descriptor, error) {
	if id == 0 {
		return nil, errInvalidObjectID
	}

	od, _, err := f.GetFromDescrID(id)
	switch {
	case errors.Is(err, sif.ErrMultValues):
		err = errMultipleObjectsFound
	case errors.Is(err, sif.ErrNotFound):
		err = errObjectNotFound
	}
	return od, err
}

// getGroupObjects returns all descriptors in f that are contained in the object group with
// identifier groupID. If no such object group is found, errGroupNotFound is returned.
func getGroupObjects(f *sif.FileImage, groupID uint32) ([]*sif.Descriptor, error) {
	if groupID == 0 {
		return nil, errInvalidGroupID
	}

	ods, _, err := f.GetFromDescr(sif.Descriptor{
		Groupid: groupID | sif.DescrGroupMask,
	})
	if errors.Is(err, sif.ErrNotFound) {
		err = errGroupNotFound
	}
	return ods, err
}

// getObjectSignatures returns all descriptors in f that contain signature objects linked to the
// object with identifier id. If no such signatures are found, errSignatureNotFound is returned.
func getObjectSignatures(f *sif.FileImage, id uint32) ([]*sif.Descriptor, error) {
	if id == 0 {
		return nil, errInvalidObjectID
	}

	sigs, _, err := f.GetLinkedDescrsByType(id, sif.DataSignature)
	if errors.Is(err, sif.ErrNotFound) {
		err = errSignatureNotFound
	}
	return sigs, err
}

// getGroupSignatures returns descriptors in f that contain signature objects linked to the object
// group with identifier groupID. If legacy is true, only legacy signatures are considered.
// Otherwise, only non-legacy signatures are considered. If no such signatures are found,
// errSignatureNotFound is returned.
func getGroupSignatures(f *sif.FileImage, groupID uint32, legacy bool) ([]*sif.Descriptor, error) {
	if groupID == 0 {
		return nil, errInvalidGroupID
	}

	// Get list of signature blocks linked to group.
	ods, _, err := f.GetLinkedDescrsByType(groupID|sif.DescrGroupMask, sif.DataSignature)
	if errors.Is(err, sif.ErrNotFound) {
		return nil, errSignatureNotFound
	} else if err != nil {
		return nil, err
	}

	// Filter signatures based on legacy flag.
	sigs := make([]*sif.Descriptor, 0, len(ods))
	for _, od := range ods {
		if isLegacySignature(od.GetData(f)) == legacy {
			sigs = append(sigs, od)
		}
	}

	if len(sigs) == 0 {
		return nil, errSignatureNotFound
	}

	return sigs, err
}

// getGroupIDs returns all identifiers for the groups contained in f, sorted by ID. If no groups
// are present, errNoGroupsFound is returned.
func getGroupIDs(f *sif.FileImage) (groupIDs []uint32, err error) {
	for _, od := range f.DescrArr {
		if !od.Used {
			continue
		}
		if od.Groupid == sif.DescrUnusedGroup {
			continue
		}
		groupIDs = insertSorted(groupIDs, od.Groupid&^sif.DescrGroupMask)
	}

	if len(groupIDs) == 0 {
		err = errNoGroupsFound
	}

	return groupIDs, err
}

// getFingerprints returns a sorted list of unique fingerprints contained in sigs.
func getFingerprints(sigs []*sif.Descriptor) ([][20]byte, error) {
	fps := make([][20]byte, 0, len(sigs))

	for _, sig := range sigs {
		e, err := sig.GetEntity()
		if err != nil {
			return nil, err
		}

		// Extract fingerprint from entity.
		var fp [20]byte
		copy(fp[:], e)

		// Check if fingerprint is already in list.
		i := sort.Search(len(fps), func(i int) bool {
			return bytes.Compare(fps[i][:], fp[:]) < 0
		})
		if i < len(fps) && fps[i] == fp {
			continue
		}

		// Insert into (sorted) list.
		fps = append(fps, [20]byte{})
		copy(fps[i+1:], fps[i:])
		fps[i] = fp
	}

	return fps, nil
}
