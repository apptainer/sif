// Copyright (c) 2021 Apptainer a Series of LF Projects LLC
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// Copyright (c) 2020-2021, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the LICENSE.md file
// distributed with the sources of this project regarding your rights to use or distribute this
// software.

package integrity

import (
	"bytes"
	"errors"
	"fmt"
	"sort"

	"github.com/apptainer/sif/v2/pkg/sif"
)

var (
	errGroupNotFound = errors.New("group not found")
	errNoGroupsFound = errors.New("no groups found")
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

// getGroupObjects returns all descriptors in f that are contained in the object group with
// identifier groupID. If no such object group is found, errGroupNotFound is returned.
func getGroupObjects(f *sif.FileImage, groupID uint32) ([]sif.Descriptor, error) {
	ods, err := f.GetDescriptors(sif.WithGroupID(groupID))
	if err == nil && len(ods) == 0 {
		err = errGroupNotFound
	}
	return ods, err
}

// SignatureNotFoundError records an error attempting to locate one or more signatures for a data
// object or data object group.
type SignatureNotFoundError struct {
	ID      uint32 // ID of the object/group for which signature was not found.
	IsGroup bool   // If true, ID is a group ID. Otherwise, ID is an object ID.
}

func (e *SignatureNotFoundError) Error() string {
	if e.ID == 0 {
		return "signature not found"
	}
	if e.IsGroup {
		return fmt.Sprintf("signature not found for object group %v", e.ID)
	}
	return fmt.Sprintf("signature not found for object %v", e.ID)
}

// Is compares e against target. If target is a SignatureNotFoundError and matches e or target has
// a zero value ID, true is returned.
func (e *SignatureNotFoundError) Is(target error) bool {
	t, ok := target.(*SignatureNotFoundError)
	if !ok {
		return false
	}
	if e.ID == t.ID && e.IsGroup == t.IsGroup {
		return true
	}
	return t.ID == 0
}

// getObjectSignatures returns all descriptors in f that contain signature objects linked to the
// object with identifier id. If no such signatures are found, a SignatureNotFoundError is
// returned.
func getObjectSignatures(f *sif.FileImage, id uint32) ([]sif.Descriptor, error) {
	sigs, err := f.GetDescriptors(
		sif.WithDataType(sif.DataSignature),
		sif.WithLinkedID(id),
	)
	if err != nil {
		return nil, err
	}

	if len(sigs) == 0 {
		return nil, &SignatureNotFoundError{ID: id}
	}

	return sigs, nil
}

// getGroupSignatures returns descriptors in f that contain signature objects linked to the object
// group with identifier groupID. If legacy is true, only legacy signatures are considered.
// Otherwise, only non-legacy signatures are considered. If no such signatures are found, a
// SignatureNotFoundError is returned.
func getGroupSignatures(f *sif.FileImage, groupID uint32, legacy bool) ([]sif.Descriptor, error) {
	// Get list of signature blocks linked to group, taking legacy flag into consideration.
	sigs, err := f.GetDescriptors(
		sif.WithDataType(sif.DataSignature),
		sif.WithLinkedGroupID(groupID),
		func(od sif.Descriptor) (bool, error) {
			b, err := od.GetData()
			if err != nil {
				return false, err
			}

			isLegacy, err := isLegacySignature(b)
			return isLegacy == legacy, err
		},
	)
	if err != nil {
		return nil, err
	}

	if len(sigs) == 0 {
		return nil, &SignatureNotFoundError{IsGroup: true, ID: groupID}
	}

	return sigs, nil
}

// getGroupMinObjectID returns the minimum ID from the set of descriptors in f that are contained
// in the object group with identifier groupID. If no such object group is found, errGroupNotFound
// is returned.
func getGroupMinObjectID(f *sif.FileImage, groupID uint32) (uint32, error) {
	minID := ^uint32(0)

	f.WithDescriptors(func(od sif.Descriptor) bool {
		if od.GroupID() != groupID {
			return false
		}

		if id := od.ID(); id < minID {
			minID = id
		}
		return false
	})

	if minID == ^uint32(0) {
		return 0, errGroupNotFound
	}
	return minID, nil
}

// getGroupIDs returns all identifiers for the groups contained in f, sorted by ID. If no groups
// are present, errNoGroupsFound is returned.
func getGroupIDs(f *sif.FileImage) (groupIDs []uint32, err error) {
	f.WithDescriptors(func(od sif.Descriptor) bool {
		if groupID := od.GroupID(); groupID != 0 {
			groupIDs = insertSorted(groupIDs, groupID)
		}
		return false
	})

	if len(groupIDs) == 0 {
		err = errNoGroupsFound
	}

	return groupIDs, err
}

// getFingerprints returns a sorted list of unique fingerprints contained in sigs.
func getFingerprints(sigs []sif.Descriptor) ([][]byte, error) {
	fps := make([][]byte, 0, len(sigs))

	for _, sig := range sigs {
		_, fp, err := sig.SignatureMetadata()
		if err != nil {
			return nil, err
		}

		// Check if fingerprint is already in list.
		i := sort.Search(len(fps), func(i int) bool {
			return bytes.Compare(fps[i], fp) >= 0
		})
		if i < len(fps) && bytes.Equal(fps[i], fp) {
			continue
		}

		// Insert into (sorted) list.
		fps = append(fps, []byte{})
		copy(fps[i+1:], fps[i:])
		fps[i] = fp
	}

	return fps, nil
}
